import {createHash,createPublicKey,verify as edVerify} from 'node:crypto';
import {inspectReceiptCheckpointEquivocation,verifyReceiptCheckpointHistory}
 from './cas-receipt-checkpoints.mjs';
import {keyQuorumPolicyDigest} from './cas-key-quorum.mjs';

/** NEO-054 — verify-only, dual-reviewed receipt checkpoint incident register. */
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 (Object.getPrototypeOf(x)===Object.prototype||Object.getPrototypeOf(x)===null);
const exact=(x,keys)=>plain(x)&&Object.keys(x).sort().join(',')===[...keys].sort().join(',');
const ident=x=>typeof x==='string'&&/^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const hex=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const sig=x=>typeof x==='string'&&/^[A-Za-z0-9+/]{86}==$/.test(x)&&
 Buffer.from(x,'base64').toString('base64')===x;
const position=x=>exact(x,['count','head'])&&Number.isSafeInteger(x.count)&&
 x.count>=0&&x.count<=64&&hex(x.head);
const fail=reason=>Object.freeze({ok:false,phase:'HOLD',reason,authorized:false,candidate:null});
const genesis=Object.freeze({count:0,head:'0'.repeat(64)});
const sha=x=>createHash('sha256').update(JSON.stringify(x)).digest('hex');
const bodyFields=['schema','namespace','sequence','previousHash','incidentId',
 'checkpointId','checkpointSequence','canonicalCheckpointHash',
 'custodianId','equivocationDigest','policyDigest','action'];
const entryFields=['body','reviews','hash'];
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
 b.schema==='NEO-054-RECEIPT-INCIDENT-v1'&&ident(b.namespace)&&
 Number.isSafeInteger(b.sequence)&&b.sequence>=1&&b.sequence<=64&&
 hex(b.previousHash)&&ident(b.incidentId)&&ident(b.checkpointId)&&
 Number.isSafeInteger(b.checkpointSequence)&&b.checkpointSequence>=1&&
 b.checkpointSequence<=64&&hex(b.canonicalCheckpointHash)&&
 ident(b.custodianId)&&hex(b.equivocationDigest)&&hex(b.policyDigest)&&
 b.action==='ESCALATE_RECEIPT_EQUIVOCATION_HOLD';
export function receiptIncidentReviewPayload(body,reviewerId,role){
 if(!validBody(body)||!ident(reviewerId)||!['OWNER','SECURITY'].includes(role))
  throw new TypeError('INVALID_RECEIPT_INCIDENT_PAYLOAD');
 return Buffer.from(JSON.stringify(['PALACO-NEO-RECEIPT-INCIDENT-REVIEW-v1',
  body.namespace,body.sequence,body.previousHash,body.incidentId,
  body.checkpointId,body.checkpointSequence,body.canonicalCheckpointHash,
  body.custodianId,body.equivocationDigest,body.policyDigest,body.action,
  reviewerId,role]),'utf8');
}
export function receiptIncidentEntryHash(body,reviews){
 receiptIncidentReviewPayload(body,'entry-reviewer','OWNER');
 if(!Array.isArray(reviews)||reviews.length!==2||
    reviews.some(r=>!exact(r,['reviewerId','signature'])||
      !ident(r.reviewerId)||!sig(r.signature))||
    reviews[0].reviewerId===reviews[1].reviewerId)
  throw new TypeError('INVALID_RECEIPT_INCIDENT_ENTRY');
 return sha(['PALACO-NEO-RECEIPT-INCIDENT-ENTRY-v1',
  receiptIncidentReviewPayload(body,'entry-reviewer','OWNER').toString('base64'),
  [...reviews].sort((a,b)=>a.reviewerId<b.reviewerId?-1:1)
   .map(r=>[r.reviewerId,r.signature])]);
}
/** The canonical side must exactly match an independently VERIFIED original
 * NEO-053 checkpoint. The contradictory side must be signed by the SAME
 * pinned custodian key. Never permits incident resolution or release.
 */
export function verifyReceiptIncidentJournal(entries,evidence,policy,policyPin,trustedFloor){
 if(!Array.isArray(entries)||!Array.isArray(evidence)||
    entries.length!==evidence.length||entries.length>64||
    !position(trustedFloor))return fail('INVALID_RECEIPT_INCIDENT_INPUT');
 let policyDigest;
 try{policyDigest=keyQuorumPolicyDigest(policy);}
 catch{return fail('INVALID_INCIDENT_POLICY');}
 if(!exact(policyPin,['version','digest'])||
    policyPin.version!==policy.version||policyPin.digest!==policyDigest)
  return fail('UNTRUSTED_INCIDENT_POLICY');
 const roster=new Map(policy.reviewers.map(x=>[x.reviewerId,x]));
 const cases=new Set(),conflicts=new Set(),output=[];
 let previous=genesis.head;
 for(let i=0;i<entries.length;i++){
  const entry=entries[i],body=entry?.body,source=evidence[i];
  if(!exact(entry,entryFields)||!validBody(body)||!hex(entry.hash)||
     !Array.isArray(entry.reviews)||entry.reviews.length!==2||
     body.sequence!==i+1||body.previousHash!==previous)
   return fail('BROKEN_INCIDENT_REGISTER');
  if(!exact(source,evidenceFields)||!Array.isArray(source.canonicalHistory)||
     !position(source.canonicalFloor)||!position(source.trustedPredecessor))
   return fail('INVALID_INCIDENT_EVIDENCE');
  const history=verifyReceiptCheckpointHistory(source.canonicalHistory,
   source.canonicalFloor);
  if(!history.ok)return fail('CHECKPOINT_'+history.reason);
  const n=body.checkpointSequence,canonical=source.canonicalHistory[n-1];
  if(!canonical||source.trustedPredecessor.count!==n-1||
     source.trustedPredecessor.head!==(n===1?genesis.head:
      source.canonicalHistory[n-2]?.seal?.hash))
   return fail('UNTRUSTED_RECEIPT_INCIDENT_PREDECESSOR');
  if(body.namespace!==policy.namespace||
     body.checkpointId!==canonical.seal.body.checkpointId||
     body.canonicalCheckpointHash!==canonical.seal.hash||
     !exact(source.left,['body','attestation'])||
     JSON.stringify(source.left.body)!==JSON.stringify(canonical.seal.body)||
     !canonical.seal.attestations.some(a=>a.custodianId===
       source.left.attestation?.custodianId&&
       a.signature===source.left.attestation?.signature)||
     !canonical.custodianTrust.some(t=>
       t.custodianId===source.trust?.custodianId&&
       t.namespace===source.trust.namespace&&
       t.publicKeyPem===source.trust.publicKeyPem&&
       t.status===source.trust.status&&
       t.expectedCheckpointId===source.trust.expectedCheckpointId))
   return fail('CONFLICT_NOT_BOUND_TO_CANONICAL_CHECKPOINT');
  const conflict=inspectReceiptCheckpointEquivocation(
   source.left,source.right,source.trust,source.trustedPredecessor);
  if(!conflict.ok||conflict.phase!=='RECEIPT_CHECKPOINT_EQUIVOCATION_HOLD'||
     !conflict.candidate)return fail('UNVERIFIED_RECEIPT_EQUIVOCATION');
  if(body.equivocationDigest!==conflict.candidate.evidenceDigest||
     body.custodianId!==conflict.candidate.custodianId||
     body.checkpointId!==conflict.candidate.checkpointId||
     body.checkpointSequence!==conflict.candidate.sequence||
     body.policyDigest!==policyDigest)
   return fail('INCIDENT_EVIDENCE_CONTEXT_CONFLICT');
  if(cases.has(body.incidentId)||conflicts.has(body.equivocationDigest))
   return fail('REPLAYED_INCIDENT_OR_EQUIVOCATION');
  const roles=new Set(),ids=new Set(),keys=new Set();
  for(const review of entry.reviews){
   if(!exact(review,['reviewerId','signature'])||
      !ident(review.reviewerId)||!sig(review.signature)||
      ids.has(review.reviewerId))
    return fail('INVALID_OR_DUPLICATE_INCIDENT_REVIEW');
   const reviewer=roster.get(review.reviewerId);
   const k=reviewer?key(reviewer.publicKeyPem):null;
   if(!k||reviewer.status!=='ACTIVE'||roles.has(reviewer.role)||
      keys.has(fingerprint(k))||
      fingerprint(k)===fingerprint(key(source.trust.publicKeyPem)))
    return fail('REVOKED_OR_NONINDEPENDENT_INCIDENT_REVIEWER');
   if(!edVerify(null,receiptIncidentReviewPayload(
      body,review.reviewerId,reviewer.role),k,
      Buffer.from(review.signature,'base64')))
    return fail('INVALID_INCIDENT_REVIEW_SIGNATURE');
   ids.add(review.reviewerId);roles.add(reviewer.role);keys.add(fingerprint(k));
  }
  if(!roles.has('OWNER')||!roles.has('SECURITY'))
   return fail('MISSING_OWNER_SECURITY_INCIDENT_REVIEW');
  if(receiptIncidentEntryHash(body,entry.reviews)!==entry.hash)
   return fail('TAMPERED_INCIDENT_ENTRY');
  previous=entry.hash;cases.add(body.incidentId);
  conflicts.add(body.equivocationDigest);
  output.push(Object.freeze({incidentId:body.incidentId,
   checkpointId:body.checkpointId,custodianId:body.custodianId,
   equivocationDigest:body.equivocationDigest,status:'ESCALATED_HOLD'}));
 }
 if(entries.length<trustedFloor.count)return fail('RECEIPT_INCIDENT_ROLLBACK');
 const pinned=trustedFloor.count===0?genesis.head:
  entries[trustedFloor.count-1].hash;
 if(pinned!==trustedFloor.head)return fail('RECEIPT_INCIDENT_FORK');
 return Object.freeze({ok:true,phase:'RECEIPT_INCIDENT_ESCALATION_VERIFIED_HOLD',
  reason:'SIGNED_EQUIVOCATION_INCIDENT_NO_RELEASE',authorized:false,
  candidate:Object.freeze({position:Object.freeze({count:entries.length,
   head:previous}),cases:Object.freeze(output)})});
}
export const INITIAL_RECEIPT_INCIDENT_POSITION=genesis;
