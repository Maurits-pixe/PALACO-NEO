import {createHash,createPublicKey,verify as edVerify} from 'node:crypto';
import {inspectHandoffWitnessConflict,verifyHandoffCheckpointHistory}
 from './cas-handoff-checkpoints.mjs';
import {keyQuorumPolicyDigest} from './cas-key-quorum.mjs';

/** NEO-049 — verification-only, append-only by hash, conflict escalation.
 * Does not adjudicate facts, notify reviewers, close cases or grant authority.
 */
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 (Object.getPrototypeOf(x)===Object.prototype||Object.getPrototypeOf(x)===null);
const exact=(x,fields)=>plain(x)&&Object.keys(x).sort().join(',')===[...fields].sort().join(',');
const ident=x=>typeof x==='string'&&/^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const hex=x=>typeof x==='string'&&/^[0-9a-f]{64}$/.test(x);
const sig=x=>typeof x==='string'&&/^[A-Za-z0-9+/]{86}==$/.test(x)&&
 Buffer.from(x,'base64').toString('base64')===x;
const position=x=>exact(x,['count','head'])&&
 Number.isSafeInteger(x.count)&&x.count>=0&&x.count<=64&&hex(x.head);
const genesis=Object.freeze({count:0,head:'0'.repeat(64)});
const sha=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
const fail=reason=>Object.freeze({ok:false,phase:'HOLD',reason,authorized:false,candidate:null});
const bodyKeys=['schema','namespace','sequence','previousHash','caseId',
 'checkpointId','checkpointSequence','witnessId','conflictDigest',
 'canonicalCheckpointHead','policyDigest','action'];
const recordKeys=['body','reviews','hash'];
const evidenceKeys=['left','right','trust','trustedPredecessor',
 'canonicalHistory','canonicalFloor'];
function key(pem){
 try{
  if(typeof pem!=='string'||!pem.length||pem.length>8192)return null;
  const k=createPublicKey(pem);
  return k.asymmetricKeyType==='ed25519'?k:null;
 }catch{return null;}
}
const fp=k=>k.export({type:'spki',format:'der'}).toString('base64');
const valid=b=>exact(b,bodyKeys)&&
 b.schema==='NEO-049-HANDOFF-CONFLICT-ESCALATION-v1'&&
 ident(b.namespace)&&Number.isSafeInteger(b.sequence)&&b.sequence>=1&&
 b.sequence<=64&&hex(b.previousHash)&&ident(b.caseId)&&
 ident(b.checkpointId)&&Number.isSafeInteger(b.checkpointSequence)&&
 b.checkpointSequence>=1&&b.checkpointSequence<=64&&
 ident(b.witnessId)&&hex(b.conflictDigest)&&hex(b.canonicalCheckpointHead)&&
 hex(b.policyDigest)&&b.action==='ESCALATE_SIGNED_CONFLICT_HOLD';
export function handoffConflictReviewPayload(body,reviewerId,role){
 if(!valid(body)||!ident(reviewerId)||!['OWNER','SECURITY'].includes(role))
  throw new TypeError('INVALID_HANDOFF_CONFLICT_REVIEW');
 return Buffer.from(JSON.stringify([
  'PALACO-NEO-HANDOFF-CONFLICT-ESCALATION-v1',
  body.namespace,body.sequence,body.previousHash,body.caseId,
  body.checkpointId,body.checkpointSequence,body.witnessId,
  body.conflictDigest,body.canonicalCheckpointHead,body.policyDigest,
  body.action,reviewerId,role]),'utf8');
}
export function handoffConflictEntryHash(body,reviews){
 handoffConflictReviewPayload(body,'entry-reviewer','OWNER');
 if(!Array.isArray(reviews)||reviews.length!==2||
    reviews.some(r=>!exact(r,['reviewerId','signature'])||
      !ident(r.reviewerId)||!sig(r.signature))||
    reviews[0].reviewerId===reviews[1].reviewerId)
  throw new TypeError('INVALID_HANDOFF_CONFLICT_REVIEWS');
 return sha(['PALACO-NEO-HANDOFF-CONFLICT-ENTRY-v1',
  handoffConflictReviewPayload(body,'entry-reviewer','OWNER').toString('base64'),
  [...reviews].sort((a,b)=>a.reviewerId<b.reviewerId?-1:1)
   .map(r=>[r.reviewerId,r.signature])]);
}
/** Original signed conflicting declarations AND the canonical NEO-048
 * checkpoint history must both verify. External trust roots are supplied by
 * the caller; cryptographic proof is NOT an operational incident alert.
 */
export function verifyHandoffConflictJournal(entries,evidence,policy,policyPin,
 trustedConflictFloor){
 if(!Array.isArray(entries)||!Array.isArray(evidence)||
    entries.length!==evidence.length||entries.length>64||
    !position(trustedConflictFloor))return fail('INVALID_CONFLICT_JOURNAL_INPUT');
 let policyDigest;
 try{policyDigest=keyQuorumPolicyDigest(policy);}
 catch{return fail('INVALID_REVIEW_POLICY');}
 if(!exact(policyPin,['version','digest'])||
    policyPin.version!==policy.version||policyPin.digest!==policyDigest)
  return fail('UNTRUSTED_CONFLICT_POLICY');
 const reviewers=new Map(policy.reviewers.map(r=>[r.reviewerId,r]));
 const caseIds=new Set(),conflictDigests=new Set(),recorded=[];
 let previous=genesis.head;
 for(let i=0;i<entries.length;i++){
  const entry=entries[i],body=entry?.body,source=evidence[i];
  if(!exact(entry,recordKeys)||!valid(body)||!hex(entry.hash)||
     !Array.isArray(entry.reviews)||entry.reviews.length!==2||
     body.sequence!==i+1||body.previousHash!==previous)
   return fail('BROKEN_CONFLICT_REGISTER');
  if(!exact(source,evidenceKeys)||!position(source.trustedPredecessor)||
     !position(source.canonicalFloor)||!Array.isArray(source.canonicalHistory))
   return fail('INVALID_CONFLICT_EVIDENCE');
  const history=verifyHandoffCheckpointHistory(source.canonicalHistory,
   source.canonicalFloor);
  if(!history.ok)return fail('CHECKPOINT_'+history.reason);
  const n=body.checkpointSequence;
  if(n>source.canonicalHistory.length||
     source.trustedPredecessor.count!==n-1||
     source.trustedPredecessor.head!==(n===1?genesis.head:
       source.canonicalHistory[n-2]?.seal?.hash))
   return fail('UNTRUSTED_CONFLICT_PREDECESSOR');
  const canonical=source.canonicalHistory[n-1];
  if(body.namespace!==policy.namespace||
     body.checkpointId!==canonical.seal.body.checkpointId||
     body.canonicalCheckpointHead!==canonical.seal.hash||
     body.policyDigest!==policyDigest||
     !exact(source.left,['body','witness'])||
     JSON.stringify(source.left.body)!==JSON.stringify(canonical.seal.body)||
     !canonical.seal.witnesses.some(w=>
       w.witnessId===source.left.witness?.witnessId&&
       w.signature===source.left.witness?.signature))
   return fail('CONFLICT_NOT_BOUND_TO_VERIFIED_CHECKPOINT');
  const conflict=inspectHandoffWitnessConflict(source.left,source.right,
   source.trust,source.trustedPredecessor);
  if(!conflict.ok||conflict.phase!=='HANDOFF_WITNESS_CONFLICT_HOLD'||
     !conflict.candidate)return fail('UNVERIFIED_WITNESS_CONTRADICTION');
  if(conflict.candidate.evidenceDigest!==body.conflictDigest||
     conflict.candidate.witnessId!==body.witnessId||
     conflict.candidate.checkpointId!==body.checkpointId||
     conflict.candidate.sequence!==body.checkpointSequence)
   return fail('CONFLICT_FINGERPRINT_MISMATCH');
  if(caseIds.has(body.caseId)||conflictDigests.has(body.conflictDigest))
   return fail('DUPLICATE_CONFLICT_OR_CASE_ID');
  const roles=new Set(),ids=new Set(),keys=new Set();
  for(const review of entry.reviews){
   if(!exact(review,['reviewerId','signature'])||
      !ident(review.reviewerId)||!sig(review.signature)||
      ids.has(review.reviewerId))
    return fail('DUPLICATE_OR_INVALID_REVIEW');
   const reviewer=reviewers.get(review.reviewerId);
   const k=reviewer?key(reviewer.publicKeyPem):null;
   if(!k||reviewer.status!=='ACTIVE'||roles.has(reviewer.role)||
      keys.has(fp(k)))return fail('REVOKED_OR_DUPLICATE_ROLE');
   if(!edVerify(null,handoffConflictReviewPayload(body,review.reviewerId,
      reviewer.role),k,Buffer.from(review.signature,'base64')))
    return fail('INVALID_CONFLICT_REVIEW_SIGNATURE');
   ids.add(review.reviewerId);roles.add(reviewer.role);keys.add(fp(k));
  }
  if(!roles.has('OWNER')||!roles.has('SECURITY'))
   return fail('MISSING_OWNER_SECURITY_QUORUM');
  if(handoffConflictEntryHash(body,entry.reviews)!==entry.hash)
   return fail('TAMPERED_CONFLICT_REGISTER_HASH');
  previous=entry.hash;caseIds.add(body.caseId);
  conflictDigests.add(body.conflictDigest);
  recorded.push(Object.freeze({caseId:body.caseId,checkpointId:body.checkpointId,
   witnessId:body.witnessId,status:'ESCALATED_HOLD'}));
 }
 if(entries.length<trustedConflictFloor.count)return fail('CONFLICT_REGISTER_ROLLBACK');
 const ancestor=trustedConflictFloor.count===0?genesis.head:
  entries[trustedConflictFloor.count-1].hash;
 if(ancestor!==trustedConflictFloor.head)return fail('CONFLICT_REGISTER_FORK');
 return Object.freeze({ok:true,phase:'HANDOFF_CONFLICT_ESCALATION_VERIFIED_HOLD',
  reason:'SIGNED_INCIDENT_REGISTER_NO_RELEASE',authorized:false,
  candidate:Object.freeze({position:Object.freeze({count:entries.length,
   head:previous}),cases:Object.freeze(recorded)})});
}
export const INITIAL_HANDOFF_CONFLICT_POSITION=genesis;
