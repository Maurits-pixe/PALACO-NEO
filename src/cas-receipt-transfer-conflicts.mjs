import {createHash,createPublicKey,verify as edVerify} from 'node:crypto';
import {inspectReceiptIncidentTransferCheckpointConflict,verifyReceiptIncidentTransferCheckpointHistory}
 from './cas-receipt-incident-transfer-checkpoints.mjs';
import {keyQuorumPolicyDigest} from './cas-key-quorum.mjs';

/** NEO-064: dual-review escalation for signed NEO-063 receipt checkpoint contradiction. */
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 (Object.getPrototypeOf(x)===Object.prototype||Object.getPrototypeOf(x)===null);
const exact=(x,fields)=>plain(x)&&Object.keys(x).sort().join(',')===[...fields].sort().join(',');
const ident=x=>typeof x==='string'&&/^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const hex=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const signature=x=>typeof x==='string'&&/^[A-Za-z0-9+/]{86}==$/.test(x)&&
 Buffer.from(x,'base64').toString('base64')===x;
const position=x=>exact(x,['count','head'])&&Number.isSafeInteger(x.count)&&
 x.count>=0&&x.count<=64&&hex(x.head);
const sha=x=>createHash('sha256').update(JSON.stringify(x)).digest('hex');
const fail=reason=>Object.freeze({ok:false,phase:'HOLD',reason,authorized:false,candidate:null});
const genesis=Object.freeze({count:0,head:'0'.repeat(64)});
const bodyFields=['schema','namespace','sequence','previousHash','incidentId',
 'checkpointId','checkpointSequence','canonicalCheckpointHash',
 'custodianId','conflictDigest','policyDigest','action'];
const recordFields=['body','reviews','hash'];
const evidenceFields=['canonicalHistory','canonicalFloor','left','right',
 'trustedPredecessor','trust'];
function key(pem){
 try{
  if(typeof pem!=='string'||!pem.length||pem.length>8192)return null;
  const k=createPublicKey(pem);return k.asymmetricKeyType==='ed25519'?k:null;
 }catch{return null;}
}
const fingerprint=k=>k.export({type:'spki',format:'der'}).toString('base64');
const validBody=b=>exact(b,bodyFields)&&
 b.schema==='NEO-064-INCIDENT-RECEIPT-EQUIVOCATION-v1'&&
 ident(b.namespace)&&Number.isSafeInteger(b.sequence)&&b.sequence>=1&&
 b.sequence<=64&&hex(b.previousHash)&&ident(b.incidentId)&&
 ident(b.checkpointId)&&Number.isSafeInteger(b.checkpointSequence)&&
 b.checkpointSequence>=1&&b.checkpointSequence<=64&&
 hex(b.canonicalCheckpointHash)&&ident(b.custodianId)&&
 hex(b.conflictDigest)&&hex(b.policyDigest)&&
 b.action==='ESCALATE_RECEIPT_CHECKPOINT_CONFLICT_HOLD';
export function receiptTransferConflictReviewPayload(body,reviewerId,role){
 if(!validBody(body)||!ident(reviewerId)||!['OWNER','SECURITY'].includes(role))
  throw new TypeError('INVALID_INCIDENT_RECEIPT_REVIEW');
 return Buffer.from(JSON.stringify(['PALACO-NEO-064-INCIDENT-RECEIPT-REVIEW-v1',
  body.namespace,body.sequence,body.previousHash,body.incidentId,
  body.checkpointId,body.checkpointSequence,body.canonicalCheckpointHash,
  body.custodianId,body.conflictDigest,body.policyDigest,body.action,
  reviewerId,role]),'utf8');
}
export function receiptTransferConflictEntryHash(body,reviews){
 receiptTransferConflictReviewPayload(body,'entry-reviewer','OWNER');
 if(!Array.isArray(reviews)||reviews.length!==2||
    reviews.some(r=>!exact(r,['reviewerId','signature'])||
      !ident(r.reviewerId)||!signature(r.signature))||
    reviews[0].reviewerId===reviews[1].reviewerId)
  throw new TypeError('INVALID_INCIDENT_RECEIPT_REVIEWS');
 return sha(['PALACO-NEO-064-INCIDENT-RECEIPT-ENTRY-v1',
  receiptTransferConflictReviewPayload(body,'entry-reviewer','OWNER')
   .toString('base64'),
  [...reviews].sort((a,b)=>a.reviewerId<b.reviewerId?-1:1)
   .map(r=>[r.reviewerId,r.signature])]);
}
/** Replay complete original NEO-063/062/061/... source evidence and require two
 * distinct ACTIVE OWNER/SECURITY reviewers. External trust roots are assumed
 * authenticated by the caller. Nothing is closed or released.
 */
export function verifyReceiptTransferConflictJournal(entries,evidence,policy,policyPin,trustedFloor){
 if(!Array.isArray(entries)||!Array.isArray(evidence)||
    entries.length!==evidence.length||entries.length>64||
    !position(trustedFloor))return fail('INVALID_CONFLICT_JOURNAL_INPUT');
 let digest;
 try{digest=keyQuorumPolicyDigest(policy);}
 catch{return fail('INVALID_REVIEW_POLICY');}
 if(!exact(policyPin,['version','digest'])||
    policyPin.version!==policy.version||policyPin.digest!==digest)
  return fail('UNTRUSTED_REVIEW_POLICY');
 const reviewers=new Map(policy.reviewers.map(r=>[r.reviewerId,r]));
 const seenCases=new Set(),seenConflicts=new Set(),reported=[];
 let previous=genesis.head;
 for(let i=0;i<entries.length;i++){
  const row=entries[i],b=row?.body,e=evidence[i];
  if(!exact(row,recordFields)||!validBody(b)||!hex(row.hash)||
     !Array.isArray(row.reviews)||row.reviews.length!==2||
     b.sequence!==i+1||b.previousHash!==previous)
   return fail('BROKEN_CONFLICT_JOURNAL_CHAIN');
  if(!exact(e,evidenceFields)||!Array.isArray(e.canonicalHistory)||
     !position(e.canonicalFloor)||!position(e.trustedPredecessor))
   return fail('INVALID_CONFLICT_PROOF');
  const history=verifyReceiptIncidentTransferCheckpointHistory(
   e.canonicalHistory,e.canonicalFloor);
  if(!history.ok)return fail('CHECKPOINT_'+history.reason);
  const index=b.checkpointSequence-1;
  const canonical=e.canonicalHistory[index];
  if(!canonical||e.trustedPredecessor.count!==index||
     e.trustedPredecessor.head!==(index===0?genesis.head:
      e.canonicalHistory[index-1]?.seal?.hash))
   return fail('UNTRUSTED_CONFLICT_PREDECESSOR');
  if(b.namespace!==policy.namespace||
     b.checkpointId!==canonical.seal.body.checkpointId||
     b.canonicalCheckpointHash!==canonical.seal.hash||
     !exact(e.left,['body','attestation'])||
     JSON.stringify(e.left.body)!==JSON.stringify(canonical.seal.body)||
     !canonical.seal.attestations.some(a=>
       a.custodianId===e.left.attestation?.custodianId&&
       a.signature===e.left.attestation?.signature)||
     !canonical.custodianTrust.some(t=>
       t.custodianId===e.trust?.custodianId&&
       t.namespace===e.trust.namespace&&
       t.publicKeyPem===e.trust.publicKeyPem&&
       t.status===e.trust.status&&
       t.expectedCheckpointId===e.trust.expectedCheckpointId))
   return fail('CONFLICT_NOT_ANCHORED_TO_ORIGINAL_CHECKPOINT');
  const conflict=inspectReceiptIncidentTransferCheckpointConflict(
   e.left,e.right,e.trust,e.trustedPredecessor);
  if(!conflict.ok||conflict.phase!=='RECEIPT_INCIDENT_TRANSFER_CHECKPOINT_CONFLICT_HOLD'||
     !conflict.candidate)return fail('INVALID_SIGNED_CHECKPOINT_CONTRADICTION');
  if(b.conflictDigest!==conflict.candidate.evidenceDigest||
     b.custodianId!==conflict.candidate.custodianId||
     b.checkpointId!==conflict.candidate.checkpointId||
     b.checkpointSequence!==conflict.candidate.sequence||
     b.policyDigest!==digest)
   return fail('INCIDENT_CONFLICT_FINGERPRINT_MISMATCH');
  if(seenCases.has(b.incidentId)||seenConflicts.has(b.conflictDigest))
   return fail('REPLAYED_INCIDENT_OR_CONFLICT');
  const roles=new Set(),ids=new Set(),keys=new Set();
  const disputed=key(e.trust.publicKeyPem);
  if(!disputed)return fail('INVALID_DISPUTED_KEY');
  for(const review of row.reviews){
   if(!exact(review,['reviewerId','signature'])||
      !ident(review.reviewerId)||!signature(review.signature)||
      ids.has(review.reviewerId))
    return fail('INVALID_OR_DUPLICATE_REVIEW');
   const reviewer=reviewers.get(review.reviewerId);
   const k=reviewer?key(reviewer.publicKeyPem):null;
   if(!k||reviewer.status!=='ACTIVE'||roles.has(reviewer.role)||
      keys.has(fingerprint(k))||fingerprint(k)===fingerprint(disputed))
    return fail('REVOKED_OR_NONINDEPENDENT_REVIEWER');
   if(!edVerify(null,receiptTransferConflictReviewPayload(
      b,review.reviewerId,reviewer.role),k,
      Buffer.from(review.signature,'base64')))
    return fail('FORGED_REVIEW_SIGNATURE');
   ids.add(review.reviewerId);roles.add(reviewer.role);keys.add(fingerprint(k));
  }
  if(!roles.has('OWNER')||!roles.has('SECURITY'))
   return fail('MISSING_OWNER_SECURITY_QUORUM');
  if(receiptTransferConflictEntryHash(b,row.reviews)!==row.hash)
   return fail('TAMPERED_CONFLICT_ENTRY_HASH');
  previous=row.hash;seenCases.add(b.incidentId);seenConflicts.add(b.conflictDigest);
  reported.push(Object.freeze({incidentId:b.incidentId,
   checkpointId:b.checkpointId,custodianId:b.custodianId,
   conflictDigest:b.conflictDigest,status:'ESCALATED_HOLD'}));
 }
 if(entries.length<trustedFloor.count)return fail('CONFLICT_REGISTER_ROLLBACK');
 const pinned=trustedFloor.count===0?genesis.head:
  entries[trustedFloor.count-1].hash;
 if(pinned!==trustedFloor.head)return fail('CONFLICT_REGISTER_FORK');
 return Object.freeze({ok:true,phase:'RECEIPT_TRANSFER_CONFLICT_JOURNAL_VERIFIED_HOLD',
  reason:'SIGNED_OWNER_SECURITY_ESCALATION_NO_RELEASE',authorized:false,
  candidate:Object.freeze({position:Object.freeze({count:entries.length,
   head:previous}),cases:Object.freeze(reported)})});
}
export const INITIAL_RECEIPT_TRANSFER_CONFLICT_POSITION=genesis;
