import {createHash,createPublicKey,verify as edVerify} from 'node:crypto';
import {classifyRecoveryHandoff} from './recovery-handoff.mjs';

/**
 * NEO-022: read-only evidence for an EXTERNAL anchor compare-and-swap (CAS).
 * This module neither writes to a custodian nor authorizes one to write.
 */
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
  (Object.getPrototypeOf(x)===Object.prototype||Object.getPrototypeOf(x)===null);
const exact=(x,keys)=>plain(x)&&Object.keys(x).sort().join(',')===[...keys].sort().join(',');
const hex=x=>typeof x==='string'&&/^[0-9a-f]{64}$/.test(x);
const id=x=>typeof x==='string'&&/^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const anchor=x=>exact(x,['namespace','revision','digest'])&&id(x.namespace)&&
  Number.isSafeInteger(x.revision)&&x.revision>=1&&hex(x.digest);
const deny=reason=>Object.freeze({ok:false,reason,authorized:false,candidate:null});

function planDigest(plan) {
 if(!exact(plan,['schema','namespace','challenge','before','after','proposedRegistry'])||
    plan.schema!=='NEO-021-v1'||!id(plan.namespace)||!hex(plan.challenge)||
    !anchor(plan.before)||!anchor(plan.after)||
    plan.before.namespace!==plan.namespace||plan.after.namespace!==plan.namespace||
    plan.after.revision!==plan.before.revision+1)
   throw new TypeError('INVALID_PLAN');
 // Bound to the specific plan. JSON representation is purposefully restricted
 // to canonical fields, not arbitrary user-supplied object serialization.
 return createHash('sha256').update(JSON.stringify([
   'PALACO-NEO-ANCHOR-CAS-PLAN-v1',plan.namespace,plan.challenge,
   plan.before.revision,plan.before.digest,plan.after.revision,plan.after.digest
 ])).digest('hex');
}
export function anchorCASPayload(cas) {
 if(!exact(cas,['namespace','operationId','planDigest','before','after','outcome'])||
    !id(cas.namespace)||!id(cas.operationId)||!hex(cas.planDigest)||
    !anchor(cas.before)||!anchor(cas.after)||
    cas.before.namespace!==cas.namespace||cas.after.namespace!==cas.namespace||
    cas.after.revision!==cas.before.revision+1||
    !['APPLIED','REJECTED'].includes(cas.outcome))
    throw new TypeError('INVALID_CAS_RECEIPT');
 return Buffer.from(JSON.stringify([
   'PALACO-NEO-ANCHOR-CAS-RECEIPT-v1',cas.namespace,cas.operationId,
   cas.planDigest,cas.before.revision,cas.before.digest,
   cas.after.revision,cas.after.digest,cas.outcome
 ]),'utf8');
}
/** The plan is only eligible for a hypothetical external CAS if local state
 * is already advanced and the independent external anchor is still BEFORE.
 */
export function prepareAnchorCAS(plan,observedRegistry,externalAnchor,operationId) {
 if(!id(operationId))return deny('INVALID_OPERATION_ID');
 const phase=classifyRecoveryHandoff(plan,observedRegistry,externalAnchor);
 if(phase.phase!=='PENDING_ANCHOR_CAS')return deny('HANDOFF_'+phase.reason);
 let digest;
 try{digest=planDigest(plan);}catch{return deny('INVALID_PLAN');}
 const candidate=Object.freeze({
   namespace:plan.namespace,operationId,planDigest:digest,
   before:Object.freeze({...plan.before}),after:Object.freeze({...plan.after}),
   outcome:'APPLIED'
 });
 return Object.freeze({ok:true,reason:'EXTERNAL_CAS_REQUEST_ONLY',
   authorized:false,candidate});
}
/**
 * Externally signed CAS receipt verifier. An APPLIED receipt only establishes
 * the signer attested an outcome. It does not prove atomic storage or release.
 */
export function verifyAnchorCASReceipt(plan,receipt,trust) {
 if(!exact(receipt,['cas','custodianId','signature'])||
    !exact(trust,['namespace','custodianId','publicKeyPem','status','expectedOperationId','trustedBefore'])||
    !id(trust.namespace)||!id(trust.custodianId)||!id(trust.expectedOperationId)||
    !anchor(trust.trustedBefore)||!['ACTIVE','REVOKED'].includes(trust.status)||
    typeof trust.publicKeyPem!=='string'||trust.publicKeyPem.length>8192)
   return deny('INVALID_TRUST_INPUT');
 let payload,digest;
 try{payload=anchorCASPayload(receipt.cas);digest=planDigest(plan);}
 catch{return deny('INVALID_RECEIPT_OR_PLAN');}
 const cas=receipt.cas;
 if(trust.status!=='ACTIVE')return deny('REVOKED_CUSTODIAN');
 if(receipt.custodianId!==trust.custodianId||
    cas.namespace!==trust.namespace||plan.namespace!==trust.namespace)
   return deny('CUSTODIAN_OR_NAMESPACE_MISMATCH');
 if(cas.operationId!==trust.expectedOperationId)return deny('OPERATION_REPLAY_OR_MISMATCH');
 if(cas.planDigest!==digest||cas.outcome!=='APPLIED'||
    cas.before.revision!==plan.before.revision||cas.before.digest!==plan.before.digest||
    cas.after.revision!==plan.after.revision||cas.after.digest!==plan.after.digest)
   return deny('CAS_PLAN_MISMATCH');
 if(trust.trustedBefore.namespace!==cas.before.namespace||
    trust.trustedBefore.revision!==cas.before.revision||
    trust.trustedBefore.digest!==cas.before.digest)
   return deny('TRUSTED_BEFORE_CONFLICT');
 if(typeof receipt.signature!=='string'||!/^[A-Za-z0-9+/]{86}==$/.test(receipt.signature))
   return deny('INVALID_SIGNATURE');
 try{
   const bytes=Buffer.from(receipt.signature,'base64');
   if(bytes.length!==64||bytes.toString('base64')!==receipt.signature)
     return deny('INVALID_SIGNATURE');
   const key=createPublicKey(trust.publicKeyPem);
   // Include the custodian identity in the signature domain.
   const signed=Buffer.from(JSON.stringify(['PALACO-NEO-CUSTODIAN-ATTEST-v1',
      receipt.custodianId,payload.toString('base64')]),'utf8');
   if(key.asymmetricKeyType!=='ed25519'||!edVerify(null,signed,key,bytes))
     return deny('INVALID_CUSTODIAN_SIGNATURE');
 }catch{return deny('INVALID_CUSTODIAN_SIGNATURE');}
 return Object.freeze({ok:true,reason:'EXTERNAL_CAS_RECEIPT_VERIFIED_NO_AUTHORITY',
    authorized:false,candidate:Object.freeze({...cas})});
}
export function anchorCASSigningPayload(cas,custodianId) {
 if(!id(custodianId))throw new TypeError('INVALID_CUSTODIAN');
 return Buffer.from(JSON.stringify(['PALACO-NEO-CUSTODIAN-ATTEST-v1',
  custodianId,anchorCASPayload(cas).toString('base64')]),'utf8');
}
