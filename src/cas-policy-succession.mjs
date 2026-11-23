import {createHash,createPublicKey,verify as verifySignature} from 'node:crypto';
import {keyQuorumPolicyDigest} from './cas-key-quorum.mjs';

/**
 * NEO-028: verified policy succession under the PREVIOUS owner's and security
 * review keys. No signing, policy publication, external pin update or authority.
 * The mandatory OWNER+SECURITY rule is IMMUTABLE in this draft.
 */
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 (Object.getPrototypeOf(x)===Object.prototype||Object.getPrototypeOf(x)===null);
const exact=(x,keys)=>object(x)&&Object.keys(x).sort().join(',')===[...keys].sort().join(',');
const id=x=>typeof x==='string'&&/^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const hex=x=>typeof x==='string'&&/^[0-9a-f]{64}$/.test(x);
const positive=x=>Number.isSafeInteger(x)&&x>=1;
const reject=reason=>Object.freeze({ok:false,reason,authorized:false,policy:null,position:null});
const GENESIS='0'.repeat(64);
const pin=p=>({version:p.version,digest:keyQuorumPolicyDigest(p)});
const bodyKeys=['namespace','sequence','previousHash','changeId','beforeVersion','beforeDigest','afterVersion','afterDigest'];
const eventKeys=[...bodyKeys,'nextPolicy','reviews','hash'];
const floor=x=>exact(x,['count','head'])&&Number.isSafeInteger(x.count)&&
 x.count>=0&&x.count<=256&&hex(x.head);
const verifyKey=pem=>{
 try {
  const key=createPublicKey(pem);
  return key.asymmetricKeyType==='ed25519'?key:null;
 }catch{return null;}
};
/** Domain-separated payload signed against the pinned PREVIOUS policy. */
export function policySuccessionPayload(body,reviewerId,role) {
 if(!exact(body,bodyKeys)||!id(body.namespace)||!positive(body.sequence)||
    !hex(body.previousHash)||!id(body.changeId)||!positive(body.beforeVersion)||
    body.afterVersion!==body.beforeVersion+1||
    !hex(body.beforeDigest)||!hex(body.afterDigest)||
    !id(reviewerId)||!['OWNER','SECURITY'].includes(role))
  throw new TypeError('INVALID_POLICY_SUCCESSION_PAYLOAD');
 return Buffer.from(JSON.stringify([
  'PALACO-NEO-QUORUM-POLICY-SUCCESSION-v1',
  body.namespace,body.sequence,body.previousHash,body.changeId,
  body.beforeVersion,body.beforeDigest,body.afterVersion,body.afterDigest,
  reviewerId,role
 ]),'utf8');
}
function entryHash(body,reviews) {
 const ordered=[...reviews].sort((a,b)=>a.reviewerId<b.reviewerId?-1:1)
  .map(r=>[r.reviewerId,r.signature]);
 return createHash('sha256').update(JSON.stringify([
   'PALACO-NEO-QUORUM-POLICY-CHAIN-v1',
   body.namespace,body.sequence,body.previousHash,body.changeId,
   body.beforeVersion,body.beforeDigest,body.afterVersion,body.afterDigest,
   ordered])).digest('hex');
}
/**
 * A new policy may add distinct keys, revoke reviewers or rotate one key.
 * Existing reviewer identities may NEVER change roles, and revoked entries
 * cannot be resurrected. New policy must retain an ACTIVE owner and security.
 */
function policyTransitionAllowed(oldPolicy,nextPolicy) {
 if(oldPolicy.schema!==nextPolicy.schema||oldPolicy.namespace!==nextPolicy.namespace||
    nextPolicy.version!==oldPolicy.version+1)return false;
 const old=new Map(oldPolicy.reviewers.map(x=>[x.reviewerId,x]));
 const next=new Map(nextPolicy.reviewers.map(x=>[x.reviewerId,x]));
 if(old.size!==oldPolicy.reviewers.length||next.size!==nextPolicy.reviewers.length)
   return false;
 let changed=0;
 for(const r of oldPolicy.reviewers){
  const n=next.get(r.reviewerId);
  if(!n||n.role!==r.role||(r.status==='REVOKED'&&n.status!=='REVOKED'))
   return false;
  if(n.publicKeyPem!==r.publicKeyPem||n.status!==r.status){
   if(r.status==='REVOKED'||n.status==='REVOKED'&&n.publicKeyPem!==r.publicKeyPem)
     return false;
   changed++;
  }
 }
 changed+=nextPolicy.reviewers.length-oldPolicy.reviewers.length;
 if(changed!==1)return false; // exactly one auditable change per event
 for(const role of ['OWNER','SECURITY']){
  if(!nextPolicy.reviewers.some(r=>r.role===role&&r.status==='ACTIVE'))
    return false;
 }
 return true;
}
/** Replay a chain from a separately authenticated initial policy + head. */
export function verifyPolicySuccessionChain(events,initialPolicy,initialPin,trustedFloor) {
 if(!Array.isArray(events)||events.length>256||!floor(trustedFloor)||
    !exact(initialPin,['version','digest'])||!positive(initialPin.version)||
    !hex(initialPin.digest))return reject('INVALID_INPUT');
 let initialDigest;
 try{initialDigest=keyQuorumPolicyDigest(initialPolicy);}
 catch{return reject('INVALID_INITIAL_POLICY');}
 if(initialPin.version!==initialPolicy.version||initialPin.digest!==initialDigest)
   return reject('UNTRUSTED_INITIAL_POLICY');
 let current=initialPolicy,head=GENESIS;
 const ids=new Set();
 for(let i=0;i<events.length;i++){
  const e=events[i];
  if(!exact(e,eventKeys)||!id(e.changeId)||ids.has(e.changeId)||
     e.sequence!==i+1||e.previousHash!==head||!hex(e.hash)||
     e.namespace!==current.namespace||!Array.isArray(e.reviews)||
     e.reviews.length!==2)
    return reject('INVALID_POLICY_CHAIN');
  let nextDigest;
  try{nextDigest=keyQuorumPolicyDigest(e.nextPolicy);}
  catch{return reject('INVALID_SUCCESSOR_POLICY');}
  if(e.beforeVersion!==current.version||e.afterVersion!==e.nextPolicy.version||
     e.beforeDigest!==keyQuorumPolicyDigest(current)||e.afterDigest!==nextDigest||
     !policyTransitionAllowed(current,e.nextPolicy))
    return reject('UNEXPECTED_POLICY_TRANSITION');
  const body=Object.fromEntries(bodyKeys.map(k=>[k,e[k]]));
  const roster=new Map(current.reviewers.map(r=>[r.reviewerId,r]));
  const seenIds=new Set(),seenRoles=new Set(),seenKeys=new Set();
  for(const review of e.reviews){
   if(!exact(review,['reviewerId','signature'])||!id(review.reviewerId)||
      seenIds.has(review.reviewerId))return reject('DUPLICATE_REVIEWER');
   const reviewer=roster.get(review.reviewerId);
   if(!reviewer||reviewer.status!=='ACTIVE')return reject('UNKNOWN_OR_REVOKED_REVIEWER');
   if(seenRoles.has(reviewer.role))return reject('DUPLICATE_ROLE');
   const key=verifyKey(reviewer.publicKeyPem);
   if(!key||typeof review.signature!=='string'||
      !/^[A-Za-z0-9+/]{86}==$/.test(review.signature))
    return reject('INVALID_REVIEW_SIGNATURE');
   const signature=Buffer.from(review.signature,'base64');
   const fingerprint=key.export({type:'spki',format:'der'}).toString('base64');
   if(seenKeys.has(fingerprint)||signature.length!==64||
      signature.toString('base64')!==review.signature)
     return reject('DUPLICATE_KEY_OR_INVALID_SIGNATURE');
   let payload;
   try{payload=policySuccessionPayload(body,review.reviewerId,reviewer.role);}
   catch{return reject('INVALID_POLICY_RECORD');}
   if(!verifySignature(null,payload,key,signature))
     return reject('INVALID_REVIEW_SIGNATURE');
   seenIds.add(review.reviewerId);seenRoles.add(reviewer.role);seenKeys.add(fingerprint);
  }
  if(!seenRoles.has('OWNER')||!seenRoles.has('SECURITY'))
    return reject('MISSING_QUORUM_ROLE');
  if(entryHash(body,e.reviews)!==e.hash)return reject('BROKEN_CHAIN_HASH');
  ids.add(e.changeId);head=e.hash;current=e.nextPolicy;
 }
 if(events.length<trustedFloor.count)return reject('ROLLBACK_BELOW_TRUSTED_FLOOR');
 const actualFloor=trustedFloor.count===0?GENESIS:events[trustedFloor.count-1].hash;
 if(actualFloor!==trustedFloor.head)return reject('TRUSTED_FLOOR_CONFLICT');
 return Object.freeze({ok:true,reason:'VERIFIED_POLICY_SUCCESSION_NOT_AUTHORIZATION',
  authorized:false,policy:current,position:Object.freeze({count:events.length,head})});
}
export function policySuccessionEntryHash(body,reviews) {
 // Public canonical hash helper; never treated as a signature.
 policySuccessionPayload(body,'dummy-reviewer','OWNER');
 if(!Array.isArray(reviews)||reviews.length!==2||
    reviews.some(r=>!exact(r,['reviewerId','signature'])||!id(r.reviewerId)||
    typeof r.signature!=='string'))throw new TypeError('INVALID_REVIEWS');
 return entryHash(body,reviews);
}
export const INITIAL_POLICY_SUCCESSION_POSITION=Object.freeze({count:0,head:GENESIS});
