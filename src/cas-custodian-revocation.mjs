import {createHash,createPublicKey,verify as edVerify} from 'node:crypto';
import {verifyCustodianKeyLifecycle} from './cas-custodian-lifecycle.mjs';
import {keyQuorumPolicyDigest} from './cas-key-quorum.mjs';

/** NEO-045: signed, verification-only revocation register for retired keys. */
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 (Object.getPrototypeOf(x)===Object.prototype||Object.getPrototypeOf(x)===null);
const exact=(x,keys)=>plain(x)&&Object.keys(x).sort().join(',')===[...keys].sort().join(',');
const id=x=>typeof x==='string'&&/^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const hex=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const sig=x=>typeof x==='string'&&/^[A-Za-z0-9+/]{86}==$/.test(x)&&
 Buffer.from(x,'base64').toString('base64')===x;
const position=x=>exact(x,['count','head'])&&Number.isSafeInteger(x.count)&&
 x.count>=0&&x.count<=64&&hex(x.head);
const deny=reason=>Object.freeze({ok:false,phase:'HOLD',reason,authorized:false,candidate:null});
const bodyKeys=['schema','namespace','sequence','previousHash','revocationId',
 'custodianId','keyFingerprint','retiredAtSequence','lifecycleDigest',
 'historyPosition','policyDigest','action'];
const entryKeys=['body','reviews','hash'];
const hash=x=>createHash('sha256').update(JSON.stringify(x)).digest('hex');
const genesis=Object.freeze({count:0,head:'0'.repeat(64)});
function key(pem){
 try{
  if(typeof pem!=='string'||pem.length<1||pem.length>8192)return null;
  const k=createPublicKey(pem);
  return k.asymmetricKeyType==='ed25519'?k:null;
 }catch{return null;}
}
function fingerprint(k){return k.export({type:'spki',format:'der'}).toString('base64');}
function validBody(b){
 return exact(b,bodyKeys)&&b.schema==='NEO-045-CUSTODIAN-REVOCATION-v1'&&
 id(b.namespace)&&Number.isSafeInteger(b.sequence)&&b.sequence>=1&&
 b.sequence<=64&&hex(b.previousHash)&&id(b.revocationId)&&
 id(b.custodianId)&&hex(b.keyFingerprint)&&
 Number.isSafeInteger(b.retiredAtSequence)&&b.retiredAtSequence>=2&&
 b.retiredAtSequence<=64&&hex(b.lifecycleDigest)&&
 position(b.historyPosition)&&hex(b.policyDigest)&&
 b.action==='REVOKE_RETIRED_HOLD';
}
export function custodianRevocationPayload(body,reviewerId,role){
 if(!validBody(body)||!id(reviewerId)||!['OWNER','SECURITY'].includes(role))
  throw new TypeError('INVALID_REVOCATION_PAYLOAD');
 return Buffer.from(JSON.stringify(['PALACO-NEO-CUSTODIAN-REVOCATION-REVIEW-v1',
  body.namespace,body.sequence,body.previousHash,body.revocationId,
  body.custodianId,body.keyFingerprint,body.retiredAtSequence,
  body.lifecycleDigest,body.historyPosition.count,body.historyPosition.head,
  body.policyDigest,body.action,reviewerId,role]),'utf8');
}
export function custodianRevocationEntryHash(body,reviews){
 custodianRevocationPayload(body,'entry-reviewer','OWNER');
 if(!Array.isArray(reviews)||reviews.length!==2||
    reviews.some(r=>!exact(r,['reviewerId','signature'])||!id(r.reviewerId)||!sig(r.signature))||
    reviews[0].reviewerId===reviews[1].reviewerId)
  throw new TypeError('INVALID_REVOCATION_REVIEWS');
 return hash(['PALACO-NEO-CUSTODIAN-REVOCATION-ENTRY-v1',
  custodianRevocationPayload(body,'entry-reviewer','OWNER').toString('base64'),
  [...reviews].sort((a,b)=>a.reviewerId<b.reviewerId?-1:1)
   .map(r=>[r.reviewerId,r.signature])]);
}
/** Every revocation is scoped to a key already retired by a fully checked
 * NEO-044 history; no active key can be revoked here without a prior rotation.
 * The same separately pinned policy is used for all entries in this journal.
 */
export function verifyCustodianRevocationJournal(history,rotations,historyFloor,
 lifecyclePin,entries,policy,policyPin,trustedRevocationFloor){
 if(!Array.isArray(entries)||entries.length>64||!position(trustedRevocationFloor)||
    !Array.isArray(history)||!Array.isArray(rotations))
  return deny('INVALID_REVOCATION_INPUT');
 const lifecycle=verifyCustodianKeyLifecycle(history,rotations,historyFloor,lifecyclePin);
 if(!lifecycle.ok)return deny('LIFECYCLE_'+lifecycle.reason);
 const snapshot=lifecycle.candidate;
 let digest;
 try{digest=keyQuorumPolicyDigest(policy);}
 catch{return deny('INVALID_REVIEW_POLICY');}
 if(!exact(policyPin,['version','digest'])||policyPin.version!==policy.version||
    policyPin.digest!==digest||policy.namespace!==history[0]?.seal?.body?.namespace)
  return deny('UNTRUSTED_REVOCATION_POLICY');
 const retiredByIdentity=new Map();
 for(const t of snapshot.transitions){
  if(t.action==='RETIRED_ROTATED'||t.action==='RETIRED_MISSING')
   retiredByIdentity.set(t.fingerprint,[t.custodianId,t.sequence]);
 }
 const reviewers=new Map(policy.reviewers.map(x=>[x.reviewerId,x]));
 const usedIds=new Set(),usedFingerprints=new Set(),records=[];
 let previous=genesis.head;
 for(let i=0;i<entries.length;i++){
  const e=entries[i],b=e?.body;
  if(!exact(e,entryKeys)||!validBody(b)||!hex(e.hash)||
     b.sequence!==i+1||b.previousHash!==previous)
   return deny('BROKEN_REVOCATION_CHAIN');
  if(b.namespace!==policy.namespace||b.policyDigest!==digest||
     b.lifecycleDigest!==snapshot.lifecycleDigest||
     b.historyPosition.count!==snapshot.position.count||
     b.historyPosition.head!==snapshot.position.head)
   return deny('REVOCATION_CONTEXT_CONFLICT');
  const retired=retiredByIdentity.get(b.keyFingerprint);
  if(!retired||retired[0]!==b.custodianId||
     retired[1]!==b.retiredAtSequence||
     snapshot.active.some(x=>x.fingerprint===b.keyFingerprint))
   return deny('KEY_NOT_VERIFIABLY_RETIRED');
  if(usedIds.has(b.revocationId)||usedFingerprints.has(b.keyFingerprint))
   return deny('DUPLICATE_REVOCATION_OR_KEY');
  if(!Array.isArray(e.reviews)||e.reviews.length!==2)
   return deny('MISSING_DUAL_REVIEW');
  const ids=new Set(),roles=new Set(),keys=new Set();
  for(const review of e.reviews){
   if(!exact(review,['reviewerId','signature'])||
      !id(review.reviewerId)||!sig(review.signature)||ids.has(review.reviewerId))
    return deny('INVALID_OR_DUPLICATE_REVIEW');
   const reviewer=reviewers.get(review.reviewerId),k=reviewer?key(reviewer.publicKeyPem):null;
   if(!k||reviewer.status!=='ACTIVE'||roles.has(reviewer.role))
    return deny('REVOKED_OR_DUPLICATE_ROLE');
   const fp=fingerprint(k);
   if(keys.has(fp)||!edVerify(null,
      custodianRevocationPayload(b,reviewer.reviewerId,reviewer.role),
      k,Buffer.from(review.signature,'base64')))
    return deny('INVALID_REVOCATION_SIGNATURE');
   ids.add(review.reviewerId);roles.add(reviewer.role);keys.add(fp);
  }
  if(!roles.has('OWNER')||!roles.has('SECURITY'))
   return deny('MISSING_DUAL_ROLE_REVIEW');
  if(custodianRevocationEntryHash(b,e.reviews)!==e.hash)
   return deny('TAMPERED_REVOCATION_ENTRY');
  previous=e.hash;
  usedIds.add(b.revocationId);usedFingerprints.add(b.keyFingerprint);
  records.push(Object.freeze({revocationId:b.revocationId,
   custodianId:b.custodianId,keyFingerprint:b.keyFingerprint,
   status:'REVOKED_HOLD',sequence:b.sequence}));
 }
 if(entries.length<trustedRevocationFloor.count)
  return deny('REVOCATION_ROLLBACK');
 const pinnedHead=trustedRevocationFloor.count===0?genesis.head:
  entries[trustedRevocationFloor.count-1].hash;
 if(pinnedHead!==trustedRevocationFloor.head)
  return deny('REVOCATION_FORK');
 return Object.freeze({ok:true,phase:'REVOCATION_HISTORY_VERIFIED_HOLD',
  reason:'SIGNED_RETIRED_KEY_REVOCATIONS_NO_AUTHORITY',authorized:false,
  candidate:Object.freeze({position:Object.freeze({count:entries.length,head:previous}),
   lifecycleDigest:snapshot.lifecycleDigest,
   revoked:Object.freeze(records)})});
}
export const INITIAL_CUSTODIAN_REVOCATION_POSITION=genesis;
