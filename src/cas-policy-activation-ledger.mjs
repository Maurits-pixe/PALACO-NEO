import {createHash,createPublicKey,verify as verifySignature} from 'node:crypto';
import {verifyPolicyActivationReceipt,policyActivationPayload} from './cas-policy-activation.mjs';

/**
 * NEO-030: read-only verification of complete signed policy CAS evidence and
 * an externally pinned, independently signed checkpoint. No persistence or
 * authority. A custodian assertion does not prove an actual durable commit.
 */
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 (Object.getPrototypeOf(x)===Object.prototype||Object.getPrototypeOf(x)===null);
const exact=(x,keys)=>plain(x)&&Object.keys(x).sort().join(',')===[...keys].sort().join(',');
const hex=x=>typeof x==='string'&&/^[0-9a-f]{64}$/.test(x);
const id=x=>typeof x==='string'&&/^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const number=x=>Number.isSafeInteger(x)&&x>=0;
const pin=x=>exact(x,['version','digest'])&&Number.isSafeInteger(x.version)&&x.version>=1&&hex(x.digest);
const position=x=>exact(x,['count','head'])&&number(x.count)&&x.count<=256&&hex(x.head);
const failure=reason=>Object.freeze({ok:false,reason,authorized:false,candidate:null});
const check=(phase,reason)=>Object.freeze({phase,reason,authorized:false});
const GENESIS='0'.repeat(64);
const entryKeys=['sequence','previousHash','request','receipt','hash'];
const signedKeys=['namespace','count','head','activePolicy'];
const sealKeys=['checkpoint','witnessId','signature'];
function entryHash(e) {
 const payload=policyActivationPayload(e.request,e.receipt.custodianId,e.receipt.outcome);
 return createHash('sha256').update(JSON.stringify([
  'PALACO-NEO-POLICY-ACTIVATION-LEDGER-v1',e.sequence,e.previousHash,
  payload.toString('base64'),e.receipt.signature])).digest('hex');
}
/** Chain verification consumes the COMPLETE original signed receipts.
 * Each trust object MUST be obtained from independent authenticated custody,
 * never reconstructed from data in a receipt.
 */
export function verifyPolicyActivationLedger(entries,externalTrust,initialPolicy,trustedFloor) {
 if(!Array.isArray(entries)||!Array.isArray(externalTrust)||
   entries.length!==externalTrust.length||entries.length>256||
   !pin(initialPolicy)||!position(trustedFloor))return failure('INVALID_LEDGER_INPUT');
 let head=GENESIS,active=initialPolicy;
 const operations=new Set(),changes=new Set();
 for(let i=0;i<entries.length;i++){
  const entry=entries[i],trust=externalTrust[i];
  if(!exact(entry,entryKeys)||entry.sequence!==i+1||
    entry.previousHash!==head||!hex(entry.hash))
   return failure('BROKEN_ACTIVATION_CHAIN');
  const request=entry.request,receipt=entry.receipt;
  if(!plain(request)||!plain(receipt)||!id(request.operationId)||
     !id(request.changeId)||operations.has(request.operationId)||
     changes.has(request.changeId))
   return failure('DUPLICATE_OPERATION_OR_CHANGE');
  if(!pin(request.before)||!pin(request.after)||
    request.before.version!==active.version||request.before.digest!==active.digest)
   return failure('NONCONTIGUOUS_POLICY_HISTORY');
  const verified=verifyPolicyActivationReceipt(request,receipt,trust);
  if(!verified.ok)return failure('SIGNED_RECEIPT_'+verified.reason);
  let digest;
  try{digest=entryHash(entry);}catch{return failure('INVALID_ACTIVATION_RECORD');}
  if(entry.hash!==digest)return failure('ACTIVATION_ENTRY_HASH_MISMATCH');
  head=entry.hash;active=request.after;
  operations.add(request.operationId);changes.add(request.changeId);
 }
 if(entries.length<trustedFloor.count)return failure('ROLLBACK_BELOW_TRUSTED_FLOOR');
 const floorHead=trustedFloor.count===0?GENESIS:entries[trustedFloor.count-1].hash;
 if(floorHead!==trustedFloor.head)return failure('TRUSTED_LEDGER_FLOOR_CONFLICT');
 return Object.freeze({ok:true,reason:'SIGNED_LEDGER_STRUCTURALLY_VERIFIED_NO_AUTHORITY',
  authorized:false,candidate:Object.freeze({position:Object.freeze({count:entries.length,head}),
  activePolicy:Object.freeze({...active})})});
}
export function policyActivationEntryHash(entry) {
 if(!exact(entry,['sequence','previousHash','request','receipt'])||
    !Number.isSafeInteger(entry.sequence)||entry.sequence<1||!hex(entry.previousHash))
  throw new TypeError('INVALID_ACTIVATION_ENTRY');
 return entryHash(entry);
}
export function policyCheckpointPayload(checkpoint,witnessId) {
 if(!exact(checkpoint,signedKeys)||!id(checkpoint.namespace)||
    !position({count:checkpoint.count,head:checkpoint.head})||
    !pin(checkpoint.activePolicy)||!id(witnessId))
  throw new TypeError('INVALID_POLICY_CHECKPOINT');
 return Buffer.from(JSON.stringify([
  'PALACO-NEO-POLICY-ACTIVATION-CHECKPOINT-v1',witnessId,
  checkpoint.namespace,checkpoint.count,checkpoint.head,
  checkpoint.activePolicy.version,checkpoint.activePolicy.digest
 ]),'utf8');
}
/** Checkpoint key MUST be independently pinned and separate from CAS custodian.
 * A verified signature establishes the witness assertion, not physical
 * independence or storage durability.
 */
export function verifyPolicyActivationCheckpoint(entries,externalTrust,initialPolicy,
 trustedFloor,seal,witnessTrust) {
 if(!exact(seal,sealKeys)||
    !exact(witnessTrust,['namespace','witnessId','publicKeyPem','status','trustedCheckpointFloor'])||
    !id(witnessTrust.namespace)||!id(witnessTrust.witnessId)||
    typeof witnessTrust.publicKeyPem!=='string'||witnessTrust.publicKeyPem.length>8192||
    !['ACTIVE','REVOKED'].includes(witnessTrust.status)||
    !position(witnessTrust.trustedCheckpointFloor))
   return failure('INVALID_CHECKPOINT_TRUST');
 if(witnessTrust.status!=='ACTIVE')return failure('REVOKED_CHECKPOINT_WITNESS');
 if(seal.witnessId!==witnessTrust.witnessId||
    seal.checkpoint?.namespace!==witnessTrust.namespace||
    (Array.isArray(entries)&&entries.length>0&&entries[0]?.request?.namespace!==witnessTrust.namespace))
   return failure('CHECKPOINT_NAMESPACE_CONFLICT');
 const verified=verifyPolicyActivationLedger(entries,externalTrust,initialPolicy,trustedFloor);
 if(!verified.ok)return failure('LEDGER_'+verified.reason);
 const {position:observed,activePolicy}=verified.candidate,cp=seal.checkpoint;
 if(!plain(cp)||cp.count!==observed.count||cp.head!==observed.head||
    !pin(cp.activePolicy)||cp.activePolicy.version!==activePolicy.version||
    cp.activePolicy.digest!==activePolicy.digest)
   return failure('CHECKPOINT_STATE_CONFLICT');
 if(cp.count<witnessTrust.trustedCheckpointFloor.count)
   return failure('CHECKPOINT_ROLLBACK');
 if(cp.count===witnessTrust.trustedCheckpointFloor.count&&
   cp.head!==witnessTrust.trustedCheckpointFloor.head)
   return failure('CHECKPOINT_FORK');
 if(cp.count>witnessTrust.trustedCheckpointFloor.count&&
    (witnessTrust.trustedCheckpointFloor.count>entries.length||
      (witnessTrust.trustedCheckpointFloor.count===0?GENESIS:
        entries[witnessTrust.trustedCheckpointFloor.count-1].hash)!==
          witnessTrust.trustedCheckpointFloor.head))
   return failure('CHECKPOINT_FLOOR_CONFLICT');
 if(typeof seal.signature!=='string'||!/^[A-Za-z0-9+/]{86}==$/.test(seal.signature))
   return failure('INVALID_CHECKPOINT_SIGNATURE');
 try{
  const sig=Buffer.from(seal.signature,'base64'),key=createPublicKey(witnessTrust.publicKeyPem);
  if(sig.length!==64||sig.toString('base64')!==seal.signature||
    key.asymmetricKeyType!=='ed25519'||
    !verifySignature(null,policyCheckpointPayload(cp,seal.witnessId),key,sig))
    return failure('INVALID_CHECKPOINT_SIGNATURE');
 }catch{return failure('INVALID_CHECKPOINT_SIGNATURE');}
 return Object.freeze({ok:true,reason:'SIGNED_CHECKPOINT_OBSERVED_NO_AUTHORITY',
  authorized:false,candidate:Object.freeze({position:observed,activePolicy})});
}
/** This comparison is read-only, not an external database read. */
export function reconcileActivationCheckpoint(observedPolicy,checkpoint) {
 if(!pin(observedPolicy)||!plain(checkpoint)||!pin(checkpoint.activePolicy))
  return check('HOLD','INVALID_OBSERVATION');
 return observedPolicy.version===checkpoint.activePolicy.version&&
   observedPolicy.digest===checkpoint.activePolicy.digest
  ?check('MATCH','CHECKPOINT_POLICY_OBSERVED_NO_AUTHORITY')
  :check('HOLD','EXTERNAL_POLICY_DIFFERS_FROM_CHECKPOINT');
}
export const INITIAL_POLICY_ACTIVATION_POSITION=Object.freeze({count:0,head:GENESIS});
