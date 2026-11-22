import {mkdir, open, rename, rm, rmdir, lstat} from 'node:fs/promises';
import {constants} from 'node:fs';
import {join} from 'node:path';
import {randomUUID} from 'node:crypto';
import {verifyReviewLedger, proposeReviewedDecision} from './review-ledger.mjs';
import {classifyReviewRecovery, classifyReviewWritePreflight, REVIEW_INITIAL_POSITION} from './review-recovery.mjs';

/**
 * NEO-012: single-host cooperative-writer file adapter for reviewed decisions.
 * Trust anchors, reviewer keys and policy pin MUST originate from independently authenticated custody.
 * No approval, authority, secrets, or auto-retry. Not suitable for hostile local writers.
 */
const fileName='review-ledger.json', lockName='.review-ledger.lock';
const hex=x=>typeof x==='string' && /^[0-9a-f]{64}$/.test(x);
const pos=x=>x!==null && typeof x==='object' && !Array.isArray(x) &&
  Object.keys(x).sort().join(',')==='count,head' &&
  Number.isSafeInteger(x.count) && x.count>=0 && hex(x.head);
const reject=reason=>Object.freeze({ok:false,reason,authorized:false,position:null});
const good=(reason,position)=>Object.freeze({ok:true,reason,authorized:false,position:Object.freeze({...position})});

async function syncDirectory(dir) {
  const h=await open(dir,'r');
  try { await h.sync(); } finally { await h.close(); }
}
async function readState(dir) {
  // Open first with O_NOFOLLOW and validate the opened descriptor, avoiding
  // the lstat/readFile pathname race in the earlier draft.
  let handle;
  try {
    handle=await open(join(dir,fileName),constants.O_RDONLY|constants.O_NOFOLLOW);
    const stat=await handle.stat();
    if(!stat.isFile() || stat.nlink!==1 || stat.size>4_000_000) return null;
    const data=await handle.readFile('utf8');
    if(Buffer.byteLength(data,'utf8')>4_000_000) return null;
    const parsed=JSON.parse(data);
    if(parsed===null || typeof parsed!=='object' || Array.isArray(parsed) ||
       Object.keys(parsed).sort().join(',')!=='entries,schema' ||
       parsed.schema!=='NEO-012-v1') return null;
    return verifyReviewLedger(parsed.entries).ok ? parsed.entries : null;
  } catch(error) {
    // If we failed to open or parse, only ENOENT on the initial open is genesis.
    if(!handle && error.code==='ENOENT') return [];
    return null;
  } finally {
    if(handle) await handle.close().catch(()=>{});
  }
}
async function usableDirectory(dir) {
  if(typeof dir!=='string' || !dir.length || dir.includes('\0')) return false;
  try { const s=await lstat(dir); return s.isDirectory()&&!s.isSymbolicLink(); }
  catch { return false; }
}
export async function inspectReviewStore(dir, trustedPosition) {
  if(!pos(trustedPosition) || !await usableDirectory(dir)) return reject('INVALID_INPUT_OR_DIRECTORY');
  const entries=await readState(dir);
  if(!entries) return reject('CORRUPT_STORE');
  const check=classifyReviewWritePreflight(entries,trustedPosition);
  return check.status==='MATCH' ? good('MATCHES_TRUSTED_POSITION',trustedPosition) :
    reject('TRUSTED_POSITION_CONFLICT');
}
/**
 * NEO-013: recompute & verify signed review evidence while holding the
 * cooperative single-host lock. Callers cannot pass an arbitrary ledger entry.
 * Reviewer policy, trusted pin and reviewer keys MUST be independently trusted.
 */
export async function commitReviewProposal(dir,trustedBefore,evidence) {
  if(!pos(trustedBefore) || !await usableDirectory(dir)) return reject('INVALID_INPUT_OR_DIRECTORY');
  let lock=false,lockIdentity=null,temp=null,renamed=false;
  const lockPath=join(dir,lockName);
  try {
    try {
      await mkdir(lockPath,{mode:0o700}); lock=true;
      lockIdentity=await lstat(lockPath);
      if(!lockIdentity.isDirectory() || lockIdentity.isSymbolicLink())
        return reject('LOCK_INTEGRITY_FAILURE');
    }
    catch(e) {return reject(e.code==='EEXIST'?'LOCKED':'LOCK_ERROR');}
    const entries=await readState(dir);
    if(!entries) return reject('CORRUPT_STORE');
    const preflight=classifyReviewWritePreflight(entries,trustedBefore);
    if(preflight.status!=='MATCH') return reject('TRUSTED_POSITION_CONFLICT');
    // Re-evaluate both cryptographic signatures and replay protection against
    // the actual current ledger under the same cooperative writer lock.
    if(!evidence || typeof evidence!=='object' || Array.isArray(evidence))
      return reject('INVALID_REVIEW_EVIDENCE');
    const requested=Object.freeze({...evidence,ledger:entries,trustedLedgerHead:trustedBefore.head});
    const validation=proposeReviewedDecision(requested);
    if(!validation.ok) return reject('REVIEW_'+validation.reason);
    const proposal=validation.candidate;
    const candidate=[...entries,proposal.entry];
    const classification=classifyReviewRecovery(candidate,trustedBefore,proposal);
    if(classification.status!=='COMMITTED') return reject('INVALID_PROPOSAL');
    temp=join(dir,`.review-ledger-${randomUUID()}.tmp`);
    const handle=await open(temp,'wx',0o600);
    try {
      await handle.writeFile(JSON.stringify({schema:'NEO-012-v1',entries:candidate})+'\n','utf8');
      await handle.sync();
    } finally { await handle.close(); }
    await rename(temp,join(dir,fileName));
    renamed=true;temp=null;
    await syncDirectory(dir);
    return good('LOCAL_COMMIT_NOT_INDEPENDENTLY_TRUSTED',
      {count:candidate.length,head:proposal.head});
  } catch {
    return reject(renamed?'UNCERTAIN_COMMIT_RECONCILE_REQUIRED':'IO_FAILURE');
  } finally {
    if(temp) await rm(temp,{force:true}).catch(()=>{});
    // Never steal another writer's lock: remove only one created by this operation.
    if(lock && lockIdentity) {
      // Never recursively delete an attacker-substituted path. If the directory
      // changed, leave it in place and require operator investigation.
      try {
        const current=await lstat(lockPath);
        if(current.isDirectory() && !current.isSymbolicLink() &&
           current.dev===lockIdentity.dev && current.ino===lockIdentity.ino)
          await rmdir(lockPath);
      } catch { /* fail closed: do not steal/repair locks */ }
    }
  }
}

/** Read-only post-error assessment; no automatic lock removal or retry. */
export async function reconcileReviewStore(dir,before,proposal) {
  if(!pos(before) || !await usableDirectory(dir)) return reject('INVALID_INPUT_OR_DIRECTORY');
  const entries=await readState(dir);
  if(!entries) return reject('CORRUPT_STORE');
  const classification=classifyReviewRecovery(entries,before,proposal);
  return Object.freeze({ok:classification.status!=='HOLD',reason:classification.reason,
    status:classification.status,authorized:false});
}
export const INITIAL_REVIEW_STORE_POSITION=REVIEW_INITIAL_POSITION;
