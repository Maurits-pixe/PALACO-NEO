import {createPublicKey,verify as edVerify} from 'node:crypto';
import {keyQuorumPolicyDigest} from './cas-key-quorum.mjs';

/** NEO-043: verification of explicit old/new custodian key continuity. */
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 (Object.getPrototypeOf(x)===Object.prototype||Object.getPrototypeOf(x)===null);
const exact=(x,fields)=>plain(x)&&Object.keys(x).sort().join(',')===[...fields].sort().join(',');
const id=x=>typeof x==='string'&&/^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const hex=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const sig=x=>typeof x==='string'&&/^[A-Za-z0-9+/]{86}==$/.test(x)&&
 Buffer.from(x,'base64').toString('base64')===x;
const fail=reason=>Object.freeze({ok:false,phase:'HOLD',reason,authorized:false});
const bodyFields=['schema','namespace','rotationId','custodianId','oldKeyPem',
 'newKeyPem','atSequence','previousHistoryHead','checkpointId','policyDigest'];
const proofFields=['body','oldSignature','newSignature','reviews'];
function key(pem){
 try{
  if(typeof pem!=='string'||pem.length<1||pem.length>8192)return null;
  const k=createPublicKey(pem);
  return k.asymmetricKeyType==='ed25519'?k:null;
 }catch{return null;}
}
function fp(k){return k.export({type:'spki',format:'der'}).toString('base64');}
function validBody(b){
 return exact(b,bodyFields)&&b.schema==='NEO-043-CUSTODIAN-ROTATION-v1'&&
 id(b.namespace)&&id(b.rotationId)&&id(b.custodianId)&&
 id(b.checkpointId)&&Number.isSafeInteger(b.atSequence)&&
 b.atSequence>=2&&b.atSequence<=64&&hex(b.previousHistoryHead)&&
 hex(b.policyDigest)&&key(b.oldKeyPem)!==null&&key(b.newKeyPem)!==null&&
 fp(key(b.oldKeyPem))!==fp(key(b.newKeyPem));
}
export function custodianRotationPayload(body,signerId,role){
 if(!validBody(body)||!id(signerId)||
    !['OLD_CUSTODIAN','NEW_CUSTODIAN','OWNER','SECURITY'].includes(role))
  throw new TypeError('INVALID_CUSTODIAN_ROTATION_PAYLOAD');
 return Buffer.from(JSON.stringify([
  'PALACO-NEO-CUSTODIAN-KEY-ROTATION-v1',body.namespace,body.rotationId,
  body.custodianId,fp(key(body.oldKeyPem)),fp(key(body.newKeyPem)),
  body.atSequence,body.previousHistoryHead,body.checkpointId,
  body.policyDigest,signerId,role
 ]),'utf8');
}
function validSignature(k,b,signerId,role,s){
 return sig(s)&&edVerify(null,custodianRotationPayload(b,signerId,role),
  k,Buffer.from(s,'base64'));
}
/** Verifies signatures, but never approves or executes a key rotation. */
export function verifyCustodianRotation(proof,policy,policyPin,expected){
 if(!exact(proof,proofFields)||!validBody(proof.body)||
    !exact(expected,['namespace','custodianId','oldKeyPem','newKeyPem',
      'atSequence','previousHistoryHead','checkpointId'])||
    !Array.isArray(proof.reviews)||proof.reviews.length!==2)
  return fail('INVALID_ROTATION_INPUT');
 const b=proof.body;
 if(b.namespace!==expected.namespace||b.custodianId!==expected.custodianId||
    b.atSequence!==expected.atSequence||
    b.previousHistoryHead!==expected.previousHistoryHead||
    b.checkpointId!==expected.checkpointId||
    fp(key(b.oldKeyPem))!==fp(key(expected.oldKeyPem))||
    fp(key(b.newKeyPem))!==fp(key(expected.newKeyPem)))
  return fail('ROTATION_CONTEXT_CONFLICT');
 let digest;
 try{digest=keyQuorumPolicyDigest(policy);}catch{return fail('INVALID_ROTATION_POLICY');}
 if(!exact(policyPin,['version','digest'])||policyPin.version!==policy.version||
    policyPin.digest!==digest||b.policyDigest!==digest||
    policy.namespace!==b.namespace)return fail('UNTRUSTED_ROTATION_POLICY');
 if(!validSignature(key(b.oldKeyPem),b,b.custodianId,'OLD_CUSTODIAN',proof.oldSignature)||
    !validSignature(key(b.newKeyPem),b,b.custodianId,'NEW_CUSTODIAN',proof.newSignature))
  return fail('INVALID_CUSTODIAN_CONTINUITY_SIGNATURE');
 const roster=new Map(policy.reviewers.map(r=>[r.reviewerId,r]));
 const usedIds=new Set(),usedRoles=new Set(),usedKeys=new Set([
  fp(key(b.oldKeyPem)),fp(key(b.newKeyPem))
 ]);
 for(const r of proof.reviews){
  if(!exact(r,['reviewerId','signature'])||!id(r.reviewerId)||
     usedIds.has(r.reviewerId))return fail('INVALID_DUPLICATE_REVIEWER');
  const reviewer=roster.get(r.reviewerId),k=reviewer?key(reviewer.publicKeyPem):null;
  if(!k||reviewer.status!=='ACTIVE'||usedRoles.has(reviewer.role)||
      usedKeys.has(fp(k)))return fail('REVOKED_OR_NONINDEPENDENT_REVIEWER');
  if(!validSignature(k,b,r.reviewerId,reviewer.role,r.signature))
   return fail('INVALID_ROTATION_REVIEW_SIGNATURE');
  usedIds.add(r.reviewerId);usedRoles.add(reviewer.role);usedKeys.add(fp(k));
 }
 if(!usedRoles.has('OWNER')||!usedRoles.has('SECURITY'))
  return fail('MISSING_OWNER_SECURITY_REVIEW');
 return Object.freeze({ok:true,phase:'SIGNED_ROTATION_EVIDENCE_ONLY',
  reason:'CUSTODIAN_KEY_CONTINUITY_VERIFIED_NO_AUTHORITY',authorized:false});
}
