import {createHash,createPublicKey,verify as edVerify} from 'node:crypto';
import {verifyCustodianKeyLifecycle} from './cas-custodian-lifecycle.mjs';
import {keyQuorumPolicyDigest} from './cas-key-quorum.mjs';

/** NEO-046: verification-only emergency key quarantine and successor nomination.
 * No live revocation, no installation of a successor and no permission issued.
 */
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 (Object.getPrototypeOf(x)===Object.prototype||Object.getPrototypeOf(x)===null);
const exact=(x,fields)=>plain(x)&&Object.keys(x).sort().join(',')===[...fields].sort().join(',');
const id=x=>typeof x==='string'&&/^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const hex=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const sig=x=>typeof x==='string'&&/^[A-Za-z0-9+/]{86}==$/.test(x)&&
 Buffer.from(x,'base64').toString('base64')===x;
const pos=x=>exact(x,['count','head'])&&Number.isSafeInteger(x.count)&&
 x.count>=1&&x.count<=64&&hex(x.head);
const fail=reason=>Object.freeze({ok:false,phase:'HOLD',reason,authorized:false,candidate:null});
const genesis=Object.freeze({count:0,head:'0'.repeat(64)});
const bodyKeys=['schema','namespace','sequence','previousHash','incidentId',
 'custodianId','activeKeyFingerprint','successorCustodianId','successorPublicKeyPem',
 'lifecycleDigest','historyPosition','policyDigest','action'];
const entryKeys=['body','reviews','successorSignature','hash'];
function key(pem){
 try{
  if(typeof pem!=='string'||!pem.length||pem.length>8192)return null;
  const k=createPublicKey(pem);return k.asymmetricKeyType==='ed25519'?k:null;
 }catch{return null;}
}
const fp=k=>createHash('sha256').update(k.export({type:'spki',format:'der'})).digest('hex');
const hash=x=>createHash('sha256').update(JSON.stringify(x)).digest('hex');
function validBody(b){
 return exact(b,bodyKeys)&&b.schema==='NEO-046-EMERGENCY-QUARANTINE-v1'&&
 id(b.namespace)&&Number.isSafeInteger(b.sequence)&&b.sequence>=1&&
 b.sequence<=64&&hex(b.previousHash)&&id(b.incidentId)&&
 id(b.custodianId)&&hex(b.activeKeyFingerprint)&&
 id(b.successorCustodianId)&&b.custodianId!==b.successorCustodianId&&
 key(b.successorPublicKeyPem)!==null&&
 pos(b.historyPosition)&&hex(b.lifecycleDigest)&&hex(b.policyDigest)&&
 b.action==='QUARANTINE_ACTIVE_KEY_HOLD';
}
export function emergencyQuarantinePayload(body,signerId,role){
 if(!validBody(body)||!id(signerId)||
    !['OWNER','SECURITY','SUCCESSOR'].includes(role))
  throw new TypeError('INVALID_EMERGENCY_PAYLOAD');
 return Buffer.from(JSON.stringify(['PALACO-NEO-EMERGENCY-QUARANTINE-v1',
  body.namespace,body.sequence,body.previousHash,body.incidentId,
  body.custodianId,body.activeKeyFingerprint,body.successorCustodianId,
  fp(key(body.successorPublicKeyPem)),body.lifecycleDigest,
  body.historyPosition.count,body.historyPosition.head,
  body.policyDigest,body.action,signerId,role]),'utf8');
}
export function emergencyQuarantineEntryHash(body,reviews,successorSignature){
 emergencyQuarantinePayload(body,'entry-hash','OWNER');
 if(!Array.isArray(reviews)||reviews.length!==2||
    reviews.some(r=>!exact(r,['reviewerId','signature'])||
      !id(r.reviewerId)||!sig(r.signature))||
    reviews[0].reviewerId===reviews[1].reviewerId||!sig(successorSignature))
  throw new TypeError('INVALID_EMERGENCY_ENTRY');
 return hash(['PALACO-NEO-EMERGENCY-QUARANTINE-ENTRY-v1',
  emergencyQuarantinePayload(body,'entry-hash','OWNER').toString('base64'),
  [...reviews].sort((a,b)=>a.reviewerId<b.reviewerId?-1:1)
   .map(r=>[r.reviewerId,r.signature]),successorSignature]);
}
/** Verify a full signed quarantine history for the SAME pinned lifecycle.
 * Successor is nominated only; not added to the current custody registry.
 */
export function verifyEmergencyQuarantineJournal(history,rotations,historyFloor,
 lifecyclePin,entries,policy,policyPin,trustedEmergencyFloor){
 if(!Array.isArray(entries)||entries.length>64||
    !exact(trustedEmergencyFloor,['count','head'])||
    !Number.isSafeInteger(trustedEmergencyFloor.count)||
    trustedEmergencyFloor.count<0||trustedEmergencyFloor.count>64||
    !hex(trustedEmergencyFloor.head))return fail('INVALID_EMERGENCY_INPUT');
 const l=verifyCustodianKeyLifecycle(history,rotations,historyFloor,lifecyclePin);
 if(!l.ok)return fail('LIFECYCLE_'+l.reason);
 const snapshot=l.candidate;
 let policyHash;
 try{policyHash=keyQuorumPolicyDigest(policy);}catch{return fail('INVALID_REVIEW_POLICY');}
 if(!exact(policyPin,['version','digest'])||
    policyPin.version!==policy.version||policyPin.digest!==policyHash||
    policy.namespace!==history[0]?.seal?.body?.namespace)
  return fail('UNTRUSTED_EMERGENCY_POLICY');
 const reviewers=new Map(policy.reviewers.map(r=>[r.reviewerId,r]));
 const active=new Map(snapshot.active.map(x=>[x.custodianId,x.fingerprint]));
 const forbidden=new Set([...snapshot.active.map(x=>x.fingerprint),
  ...snapshot.retiredFingerprints]);
 for(const reviewer of policy.reviewers){
  const k=key(reviewer.publicKeyPem);if(k)forbidden.add(fp(k));
 }
 const seenIncidents=new Set(),quarantinedKeys=new Set(),successorKeys=new Set();
 const nominations=[];let head=genesis.head;
 for(let i=0;i<entries.length;i++){
  const e=entries[i],b=e?.body;
  if(!exact(e,entryKeys)||!validBody(b)||!hex(e.hash)||
     b.sequence!==i+1||b.previousHash!==head)
   return fail('BROKEN_EMERGENCY_CHAIN');
  if(b.namespace!==policy.namespace||b.policyDigest!==policyHash||
     b.lifecycleDigest!==snapshot.lifecycleDigest||
     b.historyPosition.count!==snapshot.position.count||
     b.historyPosition.head!==snapshot.position.head)
   return fail('EMERGENCY_CONTEXT_CONFLICT');
  if(active.get(b.custodianId)!==b.activeKeyFingerprint)
   return fail('TARGET_NOT_ACTIVE_KEY');
  if(active.has(b.successorCustodianId)||seenIncidents.has(b.incidentId)||
     quarantinedKeys.has(b.activeKeyFingerprint))
   return fail('INCIDENT_REPLAY_OR_ACTIVE_SUCCESSOR');
  const newKey=key(b.successorPublicKeyPem),newFingerprint=fp(newKey);
  if(forbidden.has(newFingerprint)||successorKeys.has(newFingerprint))
   return fail('REUSED_OR_UNTRUSTED_SUCCESSOR_KEY');
  if(!sig(e.successorSignature)||!edVerify(null,
      emergencyQuarantinePayload(b,b.successorCustodianId,'SUCCESSOR'),
      newKey,Buffer.from(e.successorSignature,'base64')))
   return fail('INVALID_SUCCESSOR_ATTESTATION');
  if(!Array.isArray(e.reviews)||e.reviews.length!==2)
   return fail('MISSING_EMERGENCY_QUORUM');
  const ids=new Set(),roles=new Set(),keys=new Set();
  for(const review of e.reviews){
   if(!exact(review,['reviewerId','signature'])||!id(review.reviewerId)||
      !sig(review.signature)||ids.has(review.reviewerId))
    return fail('INVALID_OR_DUPLICATE_REVIEW');
   const signer=reviewers.get(review.reviewerId);
   const k=signer?key(signer.publicKeyPem):null;
   if(!k||signer.status!=='ACTIVE'||roles.has(signer.role))
    return fail('REVOKED_OR_DUPLICATE_REVIEW_ROLE');
   const fingerprint=fp(k);
   if(keys.has(fingerprint)||!edVerify(null,
      emergencyQuarantinePayload(b,review.reviewerId,signer.role),
      k,Buffer.from(review.signature,'base64')))
    return fail('INVALID_EMERGENCY_REVIEW_SIGNATURE');
   ids.add(review.reviewerId);roles.add(signer.role);keys.add(fingerprint);
  }
  if(!roles.has('OWNER')||!roles.has('SECURITY'))
   return fail('MISSING_OWNER_SECURITY_REVIEW');
  if(emergencyQuarantineEntryHash(b,e.reviews,e.successorSignature)!==e.hash)
   return fail('TAMPERED_EMERGENCY_ENTRY');
  head=e.hash;seenIncidents.add(b.incidentId);
  quarantinedKeys.add(b.activeKeyFingerprint);successorKeys.add(newFingerprint);
  nominations.push(Object.freeze({incidentId:b.incidentId,custodianId:b.custodianId,
   activeKeyFingerprint:b.activeKeyFingerprint,
   successorCustodianId:b.successorCustodianId,
   successorKeyFingerprint:newFingerprint,status:'QUARANTINE_PROPOSED_HOLD'}));
 }
 if(entries.length<trustedEmergencyFloor.count)return fail('EMERGENCY_ROLLBACK');
 const pinned=trustedEmergencyFloor.count===0?genesis.head:
  entries[trustedEmergencyFloor.count-1].hash;
 if(pinned!==trustedEmergencyFloor.head)return fail('EMERGENCY_FORK');
 return Object.freeze({ok:true,phase:'EMERGENCY_QUARANTINE_EVIDENCE_HOLD',
  reason:'SIGNED_ACTIVE_KEY_QUARANTINE_NO_EXECUTION_AUTHORITY',
  authorized:false,candidate:Object.freeze({
   position:Object.freeze({count:entries.length,head}),
   lifecycleDigest:snapshot.lifecycleDigest,
   nominations:Object.freeze(nominations)})});
}
export const INITIAL_EMERGENCY_QUARANTINE_POSITION=genesis;
