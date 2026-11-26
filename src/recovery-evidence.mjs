import {createHash} from 'node:crypto';
import {verifyReviewLedger} from './review-ledger.mjs';
import {classifyReviewRecovery} from './review-recovery.mjs';

/**
 * NEO-017: evidence-only snapshot classification and deterministic receipts.
 * A SHA-256 receipt is NOT a signature, independent anchor, authorization, or lock.
 */
const plain = x => x !== null && typeof x === 'object' && !Array.isArray(x) &&
  (Object.getPrototypeOf(x)===Object.prototype || Object.getPrototypeOf(x)===null);
const exact=(v,fields)=>plain(v) && Object.keys(v).sort().join(',')===[...fields].sort().join(',');
const hash=x=>typeof x==='string' && /^[a-f0-9]{64}$/.test(x);
const beforeShape=b=>exact(b,['count','head']) &&
  Number.isSafeInteger(b.count) && b.count>=0 && b.count<100000 && hash(b.head);
const candidateShape=p=>exact(p,['entry','head']) && plain(p.entry) && hash(p.head);
const deny=reason=>Object.freeze({ok:false,reason,authorized:false,receipt:null});
function receiptHash(before,proposal,observed,status) {
  const message=JSON.stringify(['PALACO-NEO-RECOVERY-EVIDENCE-v1',
    before.count,before.head,proposal.entry.hash,proposal.head,
    observed.count,observed.head,status]);
  return createHash('sha256').update(message).digest('hex');
}
/**
 * Requires the externally trusted before position and a proposal captured
 * before a write. This function does not establish that independent custody.
 */
export function createRecoveryEvidence(entries,before,proposal) {
  if(!Array.isArray(entries) || !beforeShape(before) || !candidateShape(proposal))
    return deny('INVALID_TRUST_INPUT');
  const observed=verifyReviewLedger(entries);
  if(!observed.ok) return deny('INVALID_OBSERVED_LEDGER');
  // Validate full proposed entry as an append of the independently pinned
  // pre-write prefix, not merely a structurally plausible hash string.
  const prefix=entries.slice(0,before.count);
  const trustedPrefix=verifyReviewLedger(prefix,before.head);
  if(observed.count<before.count || !trustedPrefix.ok ||
     trustedPrefix.count!==before.count) return deny('TRUSTED_PREFIX_CONFLICT');
  const append=verifyReviewLedger([...prefix,proposal.entry],proposal.head);
  if(!append.ok || append.count!==before.count+1) return deny('INVALID_PROPOSAL_CHAIN');
  const result=classifyReviewRecovery(entries,before,proposal);
  if(!['COMMITTED','NOT_COMMITTED'].includes(result.status))
    return deny('UNEXPLAINED_STATE');
  const position=Object.freeze({count:observed.count,head:observed.head});
  const receipt=Object.freeze({schema:'NEO-017-v1',status:result.status,
    before:Object.freeze({...before}),proposedHead:proposal.head,
    observed:position,receiptDigest:receiptHash(before,proposal,position,result.status)});
  return Object.freeze({ok:true,reason:'UNSIGNED_RECOVERY_EVIDENCE_ONLY',
    authorized:false,receipt});
}
/** Compare two independent reads, and refuse to call divergent observations stable.
 * Matching receipts do not grant authority or prove filesystem durability.
 */
export function compareRecoveryEvidence(first,second) {
  if(!plain(first) || !plain(second) || first.ok!==true || second.ok!==true ||
     first.authorized!==false || second.authorized!==false ||
     !exact(first.receipt,['schema','status','before','proposedHead','observed','receiptDigest']) ||
     !exact(second.receipt,['schema','status','before','proposedHead','observed','receiptDigest']) ||
     first.receipt.schema!=='NEO-017-v1' || second.receipt.schema!=='NEO-017-v1' ||
     !hash(first.receipt.receiptDigest) || !hash(second.receipt.receiptDigest))
    return Object.freeze({status:'HOLD',reason:'INVALID_EVIDENCE',authorized:false});
  const a=first.receipt,b=second.receipt;
  if(!beforeShape(a.before)||!beforeShape(b.before) ||
     !beforeShape(a.observed)||!beforeShape(b.observed) ||
     !hash(a.proposedHead)||!hash(b.proposedHead)||
     !['COMMITTED','NOT_COMMITTED'].includes(a.status) ||
     !['COMMITTED','NOT_COMMITTED'].includes(b.status))
    return Object.freeze({status:'HOLD',reason:'INVALID_RECEIPT',authorized:false});
  // The digest is public and recomputable; detect accidental/malicious edits,
  // but not fabrication by an adversary who controls all receipt fields.
  const expected=x=>receiptHash(x.before,{entry:{hash:x.proposedHead},head:x.proposedHead},x.observed,x.status);
  if(a.receiptDigest!==expected(a)||b.receiptDigest!==expected(b))
    return Object.freeze({status:'HOLD',reason:'RECEIPT_TAMPERED',authorized:false});
  if(a.receiptDigest!==b.receiptDigest)
    return Object.freeze({status:'HOLD',reason:'CONFLICTING_OBSERVATIONS',authorized:false});
  return Object.freeze({status:'STABLE',reason:'TWO_IDENTICAL_OBSERVATIONS_NO_AUTHORITY',
    authorized:false});
}
