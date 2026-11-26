import {createHash,createPublicKey,verify as edVerify} from 'node:crypto';
import {verifyWitnessEquivocationDossier} from './cas-witness-equivocation.mjs';
import {keyQuorumPolicyDigest} from './cas-key-quorum.mjs';

/** NEO-033: verify-only escalation journal. No closure, revocation, write or release. */
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
  (Object.getPrototypeOf(x)===Object.prototype||Object.getPrototypeOf(x)===null);
const exact=(x,keys)=>plain(x)&&Object.keys(x).sort().join(',')===[...keys].sort().join(',');
const id=x=>typeof x==='string'&&/^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const hex=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const pos=x=>exact(x,['count','head'])&&Number.isSafeInteger(x.count)&&
 x.count>=0&&x.count<=256&&hex(x.head);
const bad=reason=>Object.freeze({ok:false,reason,authorized:false,candidate:null});
const HEAD='0'.repeat(64);
const keys=['sequence','previousHash','caseId','action','dossierDigest','reviews','hash'];
const bodyKeys=['sequence','previousHash','caseId','action','dossierDigest'];
const sig=x=>typeof x==='string'&&/^[A-Za-z0-9+/]{86}==$/.test(x)&&
 Buffer.from(x,'base64').toString('base64')===x;
export const INITIAL_ESCALATION_POSITION=Object.freeze({count:0,head:HEAD});
export function escalationReviewPayload(body,policyDigest,reviewerId,role){
 if(!exact(body,bodyKeys)||!Number.isSafeInteger(body.sequence)||body.sequence<1||
    !hex(body.previousHash)||!id(body.caseId)||!['OPEN','REVIEWED_HOLD'].includes(body.action)||
    !hex(body.dossierDigest)||!hex(policyDigest)||!id(reviewerId)||
    !['OWNER','SECURITY'].includes(role))throw new TypeError('INVALID_ESCALATION_PAYLOAD');
 return Buffer.from(JSON.stringify([
   'PALACO-NEO-ESCALATION-REVIEW-v1',body.sequence,body.previousHash,
   body.caseId,body.action,body.dossierDigest,policyDigest,reviewerId,role
 ]),'utf8');
}
export function escalationEntryHash(body,reviews){
 if(!Array.isArray(reviews)||reviews.length!==2||
    reviews.some(r=>!exact(r,['reviewerId','signature'])||!id(r.reviewerId)||!sig(r.signature)))
   throw new TypeError('INVALID_ESCALATION_REVIEWS');
 const ordered=[...reviews].sort((a,b)=>a.reviewerId.localeCompare(b.reviewerId))
  .map(r=>[r.reviewerId,r.signature]);
 return createHash('sha256').update(JSON.stringify([
   'PALACO-NEO-ESCALATION-JOURNAL-v1',body.sequence,body.previousHash,
   body.caseId,body.action,body.dossierDigest,ordered
 ])).digest('hex');
}
/** Require externally pinned old policy and reverify all original signatures. */
export function verifyEscalationJournal(entries,caseEvidence,policy,policyPin,trustedFloor){
 if(!Array.isArray(entries)||!Array.isArray(caseEvidence)||entries.length>256||
    entries.length!==caseEvidence.length||!pos(trustedFloor)||
    !exact(policyPin,['version','digest'])||
    !Number.isSafeInteger(policyPin.version)||policyPin.version<1||!hex(policyPin.digest))
   return bad('INVALID_JOURNAL_INPUT');
 let digest;
 try{digest=keyQuorumPolicyDigest(policy);}catch{return bad('INVALID_POLICY');}
 if(policy.version!==policyPin.version||digest!==policyPin.digest)
   return bad('UNTRUSTED_POLICY_PIN');
 const reviewers=new Map(policy.reviewers.map(r=>[r.reviewerId,r]));
 let head=HEAD;const cases=new Map();
 for(let i=0;i<entries.length;i++){
  const e=entries[i],bundle=caseEvidence[i];
  if(!exact(e,keys)||e.sequence!==i+1||e.previousHash!==head||
    !id(e.caseId)||!hex(e.dossierDigest)||!hex(e.hash)||
    !['OPEN','REVIEWED_HOLD'].includes(e.action)||
    !Array.isArray(e.reviews)||e.reviews.length!==2)
   return bad('BROKEN_ESCALATION_CHAIN');
  if(!exact(bundle,['dossier','witnessTrust']))return bad('MISSING_FORENSIC_EVIDENCE');
  const forensic=verifyWitnessEquivocationDossier(bundle.dossier,bundle.witnessTrust);
  if(forensic.phase!=='ESCALATE_HOLD'||forensic.dossier.digest!==e.dossierDigest)
   return bad('UNVERIFIED_FORENSIC_DOSSIER');
  const previous=cases.get(e.caseId);
  if(e.action==='OPEN'&&previous!==undefined)return bad('CASE_REPLAY');
  if(e.action==='REVIEWED_HOLD'&&previous!==e.dossierDigest)
   return bad('UNOPENED_OR_CHANGED_CASE');
  const body=Object.fromEntries(bodyKeys.map(k=>[k,e[k]]));
  const usedId=new Set(),usedRole=new Set(),usedKey=new Set();
  for(const review of e.reviews){
   if(!exact(review,['reviewerId','signature'])||!id(review.reviewerId)||
      usedId.has(review.reviewerId)||!sig(review.signature))
    return bad('INVALID_OR_DUPLICATE_REVIEW');
   const r=reviewers.get(review.reviewerId);
   if(!r||r.status!=='ACTIVE'||usedRole.has(r.role))
    return bad('REVOKED_OR_DUPLICATE_REVIEW_ROLE');
   let key,payload;
   try {
    key=createPublicKey(r.publicKeyPem);
    payload=escalationReviewPayload(body,digest,r.reviewerId,r.role);
   }catch{return bad('INVALID_REVIEW_KEY_OR_PAYLOAD');}
   if(key.asymmetricKeyType!=='ed25519')return bad('INVALID_REVIEW_KEY_OR_PAYLOAD');
   const fingerprint=key.export({type:'spki',format:'der'}).toString('base64');
   if(usedKey.has(fingerprint)||!edVerify(null,payload,key,Buffer.from(review.signature,'base64')))
    return bad('INVALID_REVIEW_SIGNATURE');
   usedId.add(r.reviewerId);usedRole.add(r.role);usedKey.add(fingerprint);
  }
  if(!usedRole.has('OWNER')||!usedRole.has('SECURITY'))
   return bad('MISSING_DUAL_ROLE_REVIEW');
  if(escalationEntryHash(body,e.reviews)!==e.hash)return bad('TAMPERED_JOURNAL_ENTRY');
  cases.set(e.caseId,e.dossierDigest);head=e.hash;
 }
 if(entries.length<trustedFloor.count)return bad('ROLLBACK_BELOW_TRUSTED_FLOOR');
 const prefix=trustedFloor.count===0?HEAD:entries[trustedFloor.count-1].hash;
 if(prefix!==trustedFloor.head)return bad('FORKED_TRUSTED_FLOOR');
 return Object.freeze({ok:true,reason:'VERIFIED_ESCALATION_EVIDENCE_HOLD_ONLY',
  authorized:false,candidate:Object.freeze({
   position:Object.freeze({count:entries.length,head}),
   cases:Object.freeze([...cases.keys()].sort().map(caseId=>Object.freeze({
    caseId,status:'ESCALATED_HOLD',dossierDigest:cases.get(caseId)
   })))
  })});
}
