import {createHash, timingSafeEqual} from 'node:crypto';

/** NEO-002: offline hash-chain prototype. No persistence, signatures or authority. */
const ZERO = '0'.repeat(64);
const HEX = /^[0-9a-f]{64}$/;
const TYPES = new Set(['DENY', 'READ_ONLY', 'PREPARED']);
const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const plain = o => o !== null && typeof o === 'object' &&
  !Array.isArray(o) && (Object.getPrototypeOf(o) === Object.prototype || Object.getPrototypeOf(o) === null);
const sane = s => typeof s === 'string' && s.length >= 1 && s.length <= 128 && /^[A-Za-z0-9_.:-]+$/.test(s);
export const GENESIS_HASH = ZERO;

export function recordHash(record) {
  // Fixed schema + fixed ordering, not arbitrary JSON canonicalization.
  const data = JSON.stringify(['PALACO-NEO-AUDIT-v1', record.sequence, record.previousHash,
    record.requestId, record.decision, record.reason]);
  return createHash('sha256').update(data, 'utf8').digest('hex');
}
function validRecord(r) {
  return plain(r) && Object.keys(r).sort().join(',') ===
    'decision,hash,previousHash,reason,requestId,sequence' &&
    Number.isSafeInteger(r.sequence) && r.sequence >= 1 && HEX.test(r.previousHash) &&
    sane(r.requestId) && TYPES.has(r.decision) && sane(r.reason) && HEX.test(r.hash);
}
function sameHash(a,b) {
  return timingSafeEqual(Buffer.from(a,'hex'),Buffer.from(b,'hex'));
}
export function appendAudit(records, event) {
  if (!Array.isArray(records) || !verifyAudit(records).ok) throw new Error('UNTRUSTED_CHAIN');
  if (!plain(event) || !sane(event.requestId) || !TYPES.has(event.decision) || !sane(event.reason))
    throw new Error('INVALID_EVENT');
  const sequence = records.length + 1;
  if (!Number.isSafeInteger(sequence)) throw new Error('SEQUENCE_OVERFLOW');
  const r = {sequence, previousHash: records.length ? records.at(-1).hash : ZERO,
    requestId: event.requestId, decision: event.decision, reason: event.reason};
  return Object.freeze({...r, hash: recordHash(r)});
}
export function verifyAudit(records, expectedHead) {
  const bad = reason => Object.freeze({ok:false, reason, head:null, count:0});
  if (!Array.isArray(records) || records.length > 100000) return bad('INVALID_CHAIN');
  let prev = ZERO;
  for (let i=0; i<records.length; i++) {
    const r = records[i];
    if (!validRecord(r) || r.sequence !== i+1 || !sameHash(r.previousHash,prev) ||
        !sameHash(r.hash,recordHash(r))) return bad('BROKEN_CHAIN');
    prev = r.hash;
  }
  if (expectedHead !== undefined && (!HEX.test(expectedHead) || !sameHash(prev,expectedHead)))
    return bad('CHECKPOINT_MISMATCH');
  return Object.freeze({ok:true, reason:'STRUCTURALLY_VALID', head:prev, count:records.length});
}
export function verifyCheckpoint(records, checkpoint) {
  if (!plain(checkpoint) || !Number.isSafeInteger(checkpoint.count) || checkpoint.count < 0 ||
      typeof checkpoint.head !== 'string' || !HEX.test(checkpoint.head))
    return Object.freeze({ok:false, reason:'INVALID_CHECKPOINT'});
  const result = verifyAudit(records, checkpoint.head);
  return Object.freeze({ok:result.ok && result.count === checkpoint.count,
    reason:result.ok && result.count === checkpoint.count ? 'MATCH' : 'MISMATCH'});
}
