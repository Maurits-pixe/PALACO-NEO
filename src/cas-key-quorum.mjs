import {createHash,createPublicKey,verify as edVerify} from 'node:crypto';
import {verifyKeyDecisionChain} from './cas-key-decisions.mjs';

/**
 * NEO-027: verification-only, externally pinned dual-role key governance.
 * Each signed decision requires independent OWNER and SECURITY endorsements.
 * No approvals are issued, keys held, decisions executed or privileges granted.
 */
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
  (Object.getPrototypeOf(x)===Object.prototype||Object.getPrototypeOf(x)===null);
const exact=(x,keys)=>plain(x)&&Object.keys(x).sort().join(',')===[...keys].sort().join(',');
const ident=x=>typeof x==='string'&&/^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const hex=x=>typeof x==='string'&&/^[0-9a-f]{64}$/.test(x);
const positive=x=>Number.isSafeInteger(x)&&x>=1;
const failure=reason=>Object.freeze({ok:false,reason,authorized:false,history:null,position:null});
function publicKey(pem) {
 try {
  if(typeof pem!=='string'||pem.length>8192||pem.length===0)return null;
  const k=createPublicKey(pem);
  if(k.asymmetricKeyType!=='ed25519')return null;
  return k;
 }catch{return null;}
}
function validatePolicy(policy) {
 if(!exact(policy,['schema','namespace','version','reviewers'])||
   policy.schema!=='NEO-027-POLICY-v1'||!ident(policy.namespace)||
   !positive(policy.version)||!Array.isArray(policy.reviewers)||
   policy.reviewers.length<2||policy.reviewers.length>32)
    throw new TypeError('INVALID_QUORUM_POLICY');
 const ids=new Set(),keys=new Set();
 for(const r of policy.reviewers) {
  if(!exact(r,['reviewerId','role','status','publicKeyPem'])||
    !ident(r.reviewerId)||!['OWNER','SECURITY'].includes(r.role)||
    !['ACTIVE','REVOKED'].includes(r.status)||!publicKey(r.publicKeyPem)||
    ids.has(r.reviewerId))throw new TypeError('INVALID_QUORUM_REVIEWER');
  const fingerprint=createHash('sha256').update(
    publicKey(r.publicKeyPem).export({type:'spki',format:'der'})).digest('hex');
  if(keys.has(fingerprint))throw new TypeError('DUPLICATE_REVIEWER_KEY');
  ids.add(r.reviewerId);keys.add(fingerprint);
 }
 if(!policy.reviewers.some(r=>r.role==='OWNER')||
    !policy.reviewers.some(r=>r.role==='SECURITY'))
   throw new TypeError('MISSING_REQUIRED_ROLES');
 return policy.reviewers.map(r=>[r.reviewerId,r.role,r.status,r.publicKeyPem])
  .sort((a,b)=>a[0]<b[0]?-1:a[0]>b[0]?1:0);
}
export function keyQuorumPolicyDigest(policy) {
 const records=validatePolicy(policy);
 return createHash('sha256').update(JSON.stringify([
  'PALACO-NEO-KEY-QUORUM-POLICY-v1',policy.namespace,policy.version,records
 ])).digest('hex');
}
export function keyQuorumReviewPayload(event,reviewerId,role,policyDigest) {
 if(!plain(event)||!ident(event.namespace)||!ident(event.decisionId)||
    !positive(event.sequence)||!hex(event.hash)||!ident(reviewerId)||
    !['OWNER','SECURITY'].includes(role)||!hex(policyDigest))
  throw new TypeError('INVALID_QUORUM_PAYLOAD');
 return Buffer.from(JSON.stringify([
  'PALACO-NEO-KEY-QUORUM-REVIEW-v1',event.namespace,event.decisionId,
  event.sequence,event.hash,policyDigest,reviewerId,role
 ]),'utf8');
}
/**
 * Recheck NEO-026 governor signatures, transition legality and trusted floor
 * before checking each separate OWNER and SECURITY signature.
 * Review endorsements do not establish legal or operational authorization.
 */
export function verifyDualKeyDecisionReviews(events,initialHistory,initialPin,governors,
  trustedPosition,policy,policyPin,endorsements) {
 let policyDigest;
 try{policyDigest=keyQuorumPolicyDigest(policy);}
 catch{return failure('INVALID_QUORUM_POLICY');}
 if(!exact(policyPin,['version','digest'])||!positive(policyPin.version)||
   !hex(policyPin.digest)||policyPin.version!==policy.version||
   policyPin.digest!==policyDigest)return failure('UNTRUSTED_QUORUM_POLICY');
 if(!Array.isArray(events)||!Array.isArray(endorsements)||
    endorsements.length!==events.length||policy.namespace!==initialHistory?.namespace)
   return failure('INVALID_REVIEW_INPUT');
 const chain=verifyKeyDecisionChain(events,initialHistory,initialPin,governors,trustedPosition);
 if(!chain.ok)return failure('DECISION_'+chain.reason);
 const roster=new Map(policy.reviewers.map(r=>[r.reviewerId,r]));
 for(let i=0;i<events.length;i++){
  const event=events[i],item=endorsements[i];
  if(!exact(item,['decisionId','reviews'])||item.decisionId!==event.decisionId||
     !Array.isArray(item.reviews)||item.reviews.length!==2)
    return failure('INCOMPLETE_QUORUM');
  const usedIds=new Set(),usedRoles=new Set();
  for(const review of item.reviews){
   if(!exact(review,['reviewerId','signature'])||!ident(review.reviewerId)||
      usedIds.has(review.reviewerId))return failure('DUPLICATE_REVIEWER');
   const reviewer=roster.get(review.reviewerId);
   if(!reviewer||reviewer.status!=='ACTIVE')
     return failure('UNKNOWN_OR_REVOKED_REVIEWER');
   if(usedRoles.has(reviewer.role))return failure('DUPLICATE_ROLE');
   if(typeof review.signature!=='string'||
      !/^[A-Za-z0-9+/]{86}==$/.test(review.signature))
     return failure('INVALID_REVIEW_SIGNATURE');
   const bytes=Buffer.from(review.signature,'base64');
   if(bytes.length!==64||bytes.toString('base64')!==review.signature)
     return failure('INVALID_REVIEW_SIGNATURE');
   const payload=keyQuorumReviewPayload(event,reviewer.reviewerId,
     reviewer.role,policyDigest);
   try{
    if(!edVerify(null,payload,publicKey(reviewer.publicKeyPem),bytes))
      return failure('INVALID_REVIEW_SIGNATURE');
   }catch{return failure('INVALID_REVIEW_SIGNATURE');}
   usedIds.add(reviewer.reviewerId);usedRoles.add(reviewer.role);
  }
  if(!usedRoles.has('OWNER')||!usedRoles.has('SECURITY'))
   return failure('MISSING_REQUIRED_ROLES');
 }
 return Object.freeze({ok:true,reason:'DUAL_SIGNED_KEY_DECISIONS_VERIFIED_NO_AUTHORITY',
  authorized:false,history:chain.history,position:chain.position});
}
