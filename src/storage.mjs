import {mkdir, open, readFile, rename, rm, lstat} from 'node:fs/promises';
import {join} from 'node:path';
import {randomUUID} from 'node:crypto';
import {INITIAL_ANCHOR, proposeCheckpoint, recoverCheckpoint} from './checkpoint.mjs';

/**
 * NEO-004 single-host, cooperative-writer, fail-closed file adapter.
 * This is NOT an independent trust anchor or distributed transaction.
 * Directory must be access-controlled and trusted by the caller.
 */
const STATE = 'checkpoint.json';
const LOCK = '.checkpoint.lock';
const isPlain = x => x !== null && typeof x === 'object' &&
  !Array.isArray(x) && (Object.getPrototypeOf(x) === Object.prototype || Object.getPrototypeOf(x) === null);
const format = (anchor, records) => JSON.stringify({schema:'NEO-004-v1',anchor,records}) + '\n';
const deny = reason => Object.freeze({ok:false,reason,checkpoint:null});
const isPath = s => typeof s === 'string' && s.length > 0 && s.indexOf('\0') === -1;

async function readCurrent(directory) {
  const path = join(directory, STATE);
  try {
    const stat = await lstat(path);
    if (!stat.isFile() || stat.isSymbolicLink()) return null;
    const raw = await readFile(path, 'utf8');
    if (Buffer.byteLength(raw,'utf8') > 4_000_000) return null;
    const state = JSON.parse(raw);
    if (!isPlain(state) || Object.keys(state).sort().join(',') !== 'anchor,records,schema' ||
        state.schema !== 'NEO-004-v1' || !Array.isArray(state.records)) return null;
    if (!recoverCheckpoint(state.records,state.anchor).ok) return null;
    return state;
  } catch (error) {
    if (error.code === 'ENOENT') return {schema:'NEO-004-v1',anchor:INITIAL_ANCHOR,records:[]};
    return null;
  }
}

async function syncDirectory(directory) {
  // On unsupported platforms, fail closed rather than claim durable completion.
  const h = await open(directory,'r');
  try { await h.sync(); } finally { await h.close(); }
}

export async function commitLocalCheckpoint(directory, expectedTrustedAnchor, event) {
  if (!isPath(directory) || !isPlain(expectedTrustedAnchor)) return deny('INVALID_INPUT');
  let locked = false;
  let temp = null;
  const lockPath = join(directory, LOCK);
  try {
    const directoryStat = await lstat(directory);
    if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) return deny('UNTRUSTED_DIRECTORY');
    try {
      await mkdir(lockPath, {mode:0o700});
      locked = true;
    } catch (error) {
      return deny(error.code === 'EEXIST' ? 'LOCKED' : 'LOCK_FAILED');
    }
    const current = await readCurrent(directory);
    if (!current) return deny('CORRUPT_OR_UNREADABLE_STATE');
    const checked = recoverCheckpoint(current.records,expectedTrustedAnchor);
    if (!checked.ok) return deny('TRUSTED_CHECKPOINT_MISMATCH');
    if (current.records.some(record => record.requestId === event?.requestId)) return deny('REPLAY');
    const proposal = proposeCheckpoint(current.records,expectedTrustedAnchor,event);
    if (!proposal.ok) return deny(proposal.reason);
    temp = join(directory,`.checkpoint-${randomUUID()}.tmp`);
    const handle = await open(temp,'wx',0o600);
    try {
      await handle.writeFile(format(proposal.candidate.anchor,proposal.candidate.records),'utf8');
      await handle.sync();
    } finally {
      await handle.close();
    }
    await rename(temp, join(directory,STATE));
    temp = null;
    await syncDirectory(directory);
    return Object.freeze({ok:true,reason:'LOCALLY_COMMITTED_NOT_INDEPENDENTLY_TRUSTED',
      checkpoint:proposal.candidate.anchor});
  } catch {
    return deny('IO_ERROR_OR_UNCERTAIN_COMMIT');
  } finally {
    if (temp) await rm(temp,{force:true}).catch(()=>{});
    if (locked) await rm(lockPath,{recursive:true,force:true}).catch(()=>{});
  }
}

/** Strict read: caller's independently trusted anchor is mandatory.
 * A missing state file is genesis only; a corrupted state is always rejected.
 */
export async function inspectLocalCheckpoint(directory, trustedAnchor) {
  if (!isPath(directory) || !isPlain(trustedAnchor)) return deny('INVALID_INPUT');
  try {
    const stat = await lstat(directory);
    if (!stat.isDirectory() || stat.isSymbolicLink()) return deny('UNTRUSTED_DIRECTORY');
    const state = await readCurrent(directory);
    if (!state) return deny('CORRUPT_OR_UNREADABLE_STATE');
    if (!recoverCheckpoint(state.records,trustedAnchor).ok) return deny('TRUSTED_CHECKPOINT_MISMATCH');
    return Object.freeze({ok:true,reason:'MATCHES_CALLER_ANCHOR',checkpoint:state.anchor});
  } catch {
    return deny('IO_ERROR');
  }
}
