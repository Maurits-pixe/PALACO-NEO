import {createHash,createPublicKey,verify as edVerify} from 'node:crypto';
import {custodianKeyHistoryDigest,proposeCustodianKeyRotation} from './cas-key-history.mjs';

/**
 * NEO-026: externally pinned, signed custodian key-governance transitions.
 * Verification only: no signing, no key custody, no trusted time, no authority.
 */
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 (Object.getPrototypeOf(x)===Object.prototype||Object.getPrototypeOf(x)===null);
const exact=(x,fields)=>plain(x)&&Object.keys(x).sort().join(',')===[...fields].sort().join(',');
const hex=x=>typeof x==='string'&&/^[0-9a-f]{64}$/.test(x);
const id=x=>typeof x==='string'&&/^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const rev=x=>Number.isSafeInteger(x)&&x>=1;
const deny=reason=>Object.freeze({ok:false,reason,authorized:false,history:null,position:null});
const GENESIS='0'.repeat(64);
const historyPin=h=>({version:h.version,digest:custodianKeyHistoryDigest(h)});
const eventBodyFields=['namespace','sequence','previousHash','decisionId','type','custodianId',
 'beforeDigest','afterDigest','beforeVersion','afterVersion','effectiveRevision','successorPublicKeyPem'];
const eventFields=[...eventBodyFields,'nextHistory','governorId','signature','hash'];
const signatureFields=['namespace','governorId','publicKeyPem','status'];

export function keyDecisionPayload(body,governorId) {
 if(!exact(body,eventBodyFields)||!id(body.namespace)||!id(governorId)||
    !rev(body.sequence)||!hex(body.previousHash)||!id(body.decisionId)||
    !['ROTATE','COMPROMISE'].includes(body.type)||!id(body.custodianId)||
    !hex(body.beforeDigest)||!hex(body.afterDigest)||
    !rev(body.beforeVersion)||body.afterVersion!==body.beforeVersion+1||
    !rev(body.effectiveRevision)||
    !(body.successorPublicKeyPem===null||typeof body.successorPublicKeyPem==='string'))
   throw new TypeError('INVALID_KEY_DECISION');
 return Buffer.from(JSON.stringify(['PALACO-NEO-KEY-DECISION-SIGNATURE-v1',
  governorId,body.namespace,body.sequence,body.previousHash,body.decisionId,
  body.type,body.custodianId,body.beforeDigest,body.afterDigest,
  body.beforeVersion,body.afterVersion,body.effectiveRevision,
  body.successorPublicKeyPem]),'utf8');
}
function recordHash(e) {
 const body=Object.fromEntries(eventBodyFields.map(k=>[k,e[k]]));
 return createHash('sha256').update(JSON.stringify([
  'PALACO-NEO-KEY-DECISION-CHAIN-v1',keyDecisionPayload(body,e.governorId).toString('base64'),
  e.signature])).digest('hex');
}
function compromisedTransition(before,body) {
 if(body.successorPublicKeyPem!==null)return null;
 const matches=before.epochs.filter(e=>e.custodianId===body.custodianId&&
   e.fromRevision===body.effectiveRevision&&e.status==='TRUSTED');
 if(matches.length!==1)return null;
 const epochs=before.epochs.map(e=>e===matches[0]?{...e,status:'COMPROMISED'}:{...e});
 return {schema:'NEO-025-KEY-HISTORY-v1',namespace:before.namespace,
  version:before.version+1,epochs};
}
export function verifyKeyDecisionChain(events,initialHistory,initialPin,governors,trustedPosition) {
 if(!Array.isArray(events)||events.length>256||
    !exact(initialPin,['version','digest'])||!rev(initialPin.version)||!hex(initialPin.digest)||
    !exact(trustedPosition,['count','head'])||
    !Number.isSafeInteger(trustedPosition.count)||trustedPosition.count<0||
    trustedPosition.count>256||!hex(trustedPosition.head)||
    !Array.isArray(governors)||governors.length<1||governors.length>16)
   return deny('INVALID_INPUT');
 let history,original;
 try{original=custodianKeyHistoryDigest(initialHistory);}catch{return deny('INVALID_INITIAL_HISTORY');}
 if(original!==initialPin.digest||initialHistory.version!==initialPin.version)
   return deny('UNTRUSTED_INITIAL_HISTORY');
 const trusted=new Map();
 for(const g of governors) {
  if(!exact(g,signatureFields)||!id(g.namespace)||!id(g.governorId)||
     g.namespace!==initialHistory.namespace||trusted.has(g.governorId)||
     !['ACTIVE','REVOKED'].includes(g.status)||typeof g.publicKeyPem!=='string'||
     g.publicKeyPem.length>8192)return deny('INVALID_GOVERNOR_REGISTRY');
  try{
   const k=createPublicKey(g.publicKeyPem);
   if(k.asymmetricKeyType!=='ed25519')return deny('INVALID_GOVERNOR_REGISTRY');
   trusted.set(g.governorId,{...g,key:k});
  }catch{return deny('INVALID_GOVERNOR_REGISTRY');}
 }
 history=initialHistory;let head=GENESIS;const decisions=new Set();
 for(let i=0;i<events.length;i++) {
  const e=events[i];
  if(!exact(e,eventFields)||e.sequence!==i+1||e.previousHash!==head||
     e.namespace!==initialHistory.namespace||!id(e.decisionId)||
     decisions.has(e.decisionId)||!hex(e.hash)||!id(e.governorId))
     return deny('INVALID_DECISION_CHAIN');
  const governor=trusted.get(e.governorId);
  if(!governor||governor.status!=='ACTIVE')
    return deny('UNTRUSTED_OR_REVOKED_GOVERNOR');
  let body,payload,expectedHash,nextHash;
  try{
   body=Object.fromEntries(eventBodyFields.map(k=>[k,e[k]]));
   payload=keyDecisionPayload(body,e.governorId);
   expectedHash=recordHash(e);
   nextHash=custodianKeyHistoryDigest(e.nextHistory);
  }catch{return deny('INVALID_DECISION_RECORD');}
  if(e.hash!==expectedHash||e.beforeVersion!==history.version||
     e.afterVersion!==e.nextHistory.version||
     e.beforeDigest!==custodianKeyHistoryDigest(history)||
     e.afterDigest!==nextHash)return deny('DECISION_HISTORY_MISMATCH');
  if(typeof e.signature!=='string'||!/^[A-Za-z0-9+/]{86}==$/.test(e.signature))
    return deny('INVALID_DECISION_SIGNATURE');
  const sig=Buffer.from(e.signature,'base64');
  if(sig.length!==64||sig.toString('base64')!==e.signature||
     !edVerify(null,payload,governor.key,sig))
    return deny('INVALID_DECISION_SIGNATURE');
  let proposed;
  if(e.type==='ROTATE'){
   const result=proposeCustodianKeyRotation(history,historyPin(history),{
     custodianId:e.custodianId,cutoverRevision:e.effectiveRevision,
     successorPublicKeyPem:e.successorPublicKeyPem});
   if(!result.ok)return deny('INVALID_ROTATION_TRANSITION');
   proposed=result.candidate.history;
  } else if(e.type==='COMPROMISE') {
   proposed=compromisedTransition(history,e);
   if(!proposed)return deny('INVALID_COMPROMISE_TRANSITION');
  }else return deny('INVALID_DECISION_TYPE');
  if(custodianKeyHistoryDigest(proposed)!==nextHash)
    return deny('UNEXPECTED_HISTORY_MUTATION');
  decisions.add(e.decisionId);history=e.nextHistory;head=e.hash;
 }
 if(events.length<trustedPosition.count)return deny('ROLLBACK_BELOW_PINNED_FLOOR');
 const floor=trustedPosition.count===0?GENESIS:events[trustedPosition.count-1].hash;
 if(floor!==trustedPosition.head)return deny('TRUSTED_DECISION_FLOOR_CONFLICT');
 return Object.freeze({ok:true,reason:'SIGNED_KEY_DECISIONS_VERIFIED_NO_AUTHORITY',
  authorized:false,history,position:Object.freeze({count:events.length,head})});
}
export const INITIAL_KEY_DECISION_POSITION=Object.freeze({count:0,head:GENESIS});
