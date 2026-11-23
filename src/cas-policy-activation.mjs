import {createHash,createPublicKey,verify as edVerify} from 'node:crypto';
import {keyQuorumPolicyDigest} from './cas-key-quorum.mjs';
import {verifyPolicySuccessionChain} from './cas-policy-succession.mjs';

/**
 * NEO-029: read-only policy activation request and signed external CAS receipt.
 * Independent custody, operation replay prevention and atomic policy activation
 * are required at the actual custodian, NOT implemented here.
 */
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 (Object.getPrototypeOf(x)===Object.prototype||Object.getPrototypeOf(x)===null);
const exact=(x,fields)=>plain(x)&&Object.keys(x).sort().join(',')===[...fields].sort().join(',');
const id=x=>typeof x==='string'&&/^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const hex=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const pos=x=>exact(x,['count','head'])&&Number.isSafeInteger(x.count)&&
 x.count>=0&&x.count<=256&&hex(x.head);
const pin=x=>exact(x,['version','digest'])&&Number.isSafeInteger(x.version)&&
 x.version>=1&&hex(x.digest);
const denied=reason=>Object.freeze({ok:false,reason,authorized:false,candidate:null});
const state=(phase,reason)=>Object.freeze({phase,reason,authorized:false});
const requestFields=['schema','namespace','operationId','changeId','decisionHead','before','after'];
const receiptFields=['request','custodianId','outcome','signature'];
function validRequest(r){
 return exact(r,requestFields)&&r.schema==='NEO-029-CAS-v1'&&
 id(r.namespace)&&id(r.operationId)&&id(r.changeId)&&hex(r.decisionHead)&&
 pin(r.before)&&pin(r.after)&&r.after.version===r.before.version+1;
}
function matching(a,b){return a.version===b.version&&a.digest===b.digest;}
export function policyActivationPayload(request,custodianId,outcome){
 if(!validRequest(request)||!id(custodianId)||!['APPLIED','REJECTED'].includes(outcome))
  throw new TypeError('INVALID_POLICY_ACTIVATION_PAYLOAD');
 return Buffer.from(JSON.stringify([
  'PALACO-NEO-POLICY-ACTIVATION-CAS-v1',custodianId,outcome,
  request.namespace,request.operationId,request.changeId,request.decisionHead,
  request.before.version,request.before.digest,
  request.after.version,request.after.digest
 ]),'utf8');
}
/** Verify the ENTIRE signed succession chain and bind only the last change.
 * This is an offline request proposal; no external write occurs.
 */
export function preparePolicyActivation(events,initialPolicy,initialPin,decisionFloor,
 externallyPinnedPolicy,operationId){
 if(!Array.isArray(events)||events.length===0||!id(operationId)||
    !pin(externallyPinnedPolicy))return denied('INVALID_ACTIVATION_INPUT');
 const checked=verifyPolicySuccessionChain(events,initialPolicy,initialPin,decisionFloor);
 if(!checked.ok)return denied('CHAIN_'+checked.reason);
 const last=events.at(-1);
 if(checked.position.count!==events.length||checked.position.head!==last.hash)
  return denied('UNVERIFIED_DECISION_HEAD');
 const preceding=events.length===1?initialPolicy:events.at(-2).nextPolicy;
 let beforeDigest,afterDigest;
 try{
  beforeDigest=keyQuorumPolicyDigest(preceding);
  afterDigest=keyQuorumPolicyDigest(checked.policy);
 }catch{return denied('INVALID_POLICY');}
 if(preceding.version!==last.beforeVersion||checked.policy.version!==last.afterVersion||
    last.beforeDigest!==beforeDigest||last.afterDigest!==afterDigest)
  return denied('DECISION_POLICY_CONFLICT');
 const before={version:preceding.version,digest:beforeDigest};
 if(!matching(externallyPinnedPolicy,before))
  return denied('EXTERNAL_POLICY_VERSION_CONFLICT');
 const request=Object.freeze({
  schema:'NEO-029-CAS-v1',namespace:checked.policy.namespace,
  operationId,changeId:last.changeId,decisionHead:last.hash,
  before:Object.freeze(before),
  after:Object.freeze({version:checked.policy.version,digest:afterDigest})
 });
 return Object.freeze({ok:true,reason:'EXTERNAL_ACTIVATION_REQUEST_ONLY',
  authorized:false,candidate:request});
}
/** Externally signed receipt is evidence of the custodian's assertion only.
 * Fresh and independently pinned signer trust is a caller obligation.
 */
export function verifyPolicyActivationReceipt(request,receipt,trust){
 if(!validRequest(request)||!exact(receipt,receiptFields)||
    !exact(trust,['namespace','custodianId','publicKeyPem','status','expectedOperationId','trustedBefore'])||
    !id(trust.namespace)||!id(trust.custodianId)||!id(trust.expectedOperationId)||
    !pin(trust.trustedBefore)||typeof trust.publicKeyPem!=='string'||
    trust.publicKeyPem.length>8192||!['ACTIVE','REVOKED'].includes(trust.status))
  return denied('INVALID_RECEIPT_OR_TRUST');
 if(trust.status!=='ACTIVE')return denied('REVOKED_CUSTODIAN');
 if(request.namespace!==trust.namespace||receipt.custodianId!==trust.custodianId)
  return denied('CUSTODIAN_OR_NAMESPACE_MISMATCH');
 if(request.operationId!==trust.expectedOperationId)
  return denied('OPERATION_REPLAY_OR_MISMATCH');
 if(!matching(trust.trustedBefore,request.before))
  return denied('TRUSTED_BEFORE_CONFLICT');
 if(!validRequest(receipt.request)||
    JSON.stringify(receipt.request)!==JSON.stringify(request)||
    receipt.outcome!=='APPLIED')
  return denied('CAS_RECEIPT_MISMATCH');
 if(typeof receipt.signature!=='string'||!/^[A-Za-z0-9+/]{86}==$/.test(receipt.signature))
  return denied('INVALID_SIGNATURE');
 try{
  const signature=Buffer.from(receipt.signature,'base64');
  if(signature.length!==64||signature.toString('base64')!==receipt.signature)
   return denied('INVALID_SIGNATURE');
  const key=createPublicKey(trust.publicKeyPem);
  if(key.asymmetricKeyType!=='ed25519'||
     !edVerify(null,policyActivationPayload(request,receipt.custodianId,receipt.outcome),key,signature))
   return denied('INVALID_CUSTODIAN_SIGNATURE');
 }catch{return denied('INVALID_CUSTODIAN_SIGNATURE');}
 const evidenceDigest=createHash('sha256').update(JSON.stringify([
  'PALACO-NEO-ACTIVATION-RECEIPT-DIGEST-v1',
  policyActivationPayload(request,receipt.custodianId,receipt.outcome).toString('base64'),
  receipt.signature])).digest('hex');
 return Object.freeze({ok:true,reason:'SIGNED_EXTERNAL_ASSERTION_ONLY',authorized:false,
  candidate:Object.freeze({evidenceDigest})});
}
/** Read-only two-sided recovery classification. An APPLIED receipt alone cannot
 * imply durable activation: independently observed external state must advance.
 */
export function reconcilePolicyActivation(request,observedExternalPolicy,verifiedReceipt){
 if(!validRequest(request)||!pin(observedExternalPolicy))
  return state('HOLD','INVALID_RECONCILIATION_INPUT');
 const old=matching(observedExternalPolicy,request.before);
 const next=matching(observedExternalPolicy,request.after);
 if(!old&&!next)return state('HOLD','UNKNOWN_OR_FORKED_POLICY');
 if(verifiedReceipt===null){
  return old?state('NOT_COMMITTED','EXTERNAL_REMAINS_BEFORE'):
   state('HOLD','EXTERNAL_ADVANCED_WITHOUT_VERIFIED_RECEIPT');
 }
 if(!plain(verifiedReceipt)||verifiedReceipt.ok!==true||
    verifiedReceipt.authorized!==false||!plain(verifiedReceipt.candidate)||
    !hex(verifiedReceipt.candidate.evidenceDigest)||
    verifiedReceipt.reason!=='SIGNED_EXTERNAL_ASSERTION_ONLY')
  return state('HOLD','UNVERIFIED_ACTIVATION_RECEIPT');
 return old?state('HOLD','SIGNED_APPLIED_BUT_EXTERNAL_STILL_BEFORE'):
  state('OBSERVED_COMMITTED','SIGNED_ASSERTION_AND_EXTERNAL_AFTER_NO_AUTHORITY');
}
