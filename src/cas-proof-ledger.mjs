import {createHash} from 'node:crypto';
import {verifyAnchorCASReceipt,anchorCASPayload} from './anchor-cas.mjs';

/**
 * NEO-023: pure CAS proof ledger and anchored observation comparison.
 * It does not hold custody, issue signatures, persist entries, or authorize.
 */
const genesis='0'.repeat(64);
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
  (Object.getPrototypeOf(x)===Object.prototype||Object.getPrototypeOf(x)===null);
const exact=(x,fields)=>plain(x)&&Object.keys(x).sort().join(',')===[...fields].sort().join(',');
const hex=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const id=x=>typeof x==='string'&&/^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const position=x=>exact(x,['count','head'])&&Number.isSafeInteger(x.count)&&
 x.count>=0&&x.count<=10000&&hex(x.head);
const fail=reason=>Object.freeze({ok:false,reason,authorized:false,candidate:null});
const status=(phase,reason)=>Object.freeze({phase,reason,authorized:false});
const fields=['sequence','previousHash','operationId','custodianId','receiptDigest',
 'beforeRevision','beforeDigest','afterRevision','afterDigest','hash'];
const recordHash=e=>createHash('sha256').update(JSON.stringify([
 'PALACO-NEO-CAS-PROOF-LEDGER-v1',e.sequence,e.previousHash,e.operationId,
 e.custodianId,e.receiptDigest,e.beforeRevision,e.beforeDigest,
 e.afterRevision,e.afterDigest])).digest('hex');
const receiptHash=r=>createHash('sha256').update(JSON.stringify([
 'PALACO-NEO-CAS-SIGNED-RECEIPT-v1',r.custodianId,
 anchorCASPayload(r.cas).toString('base64'),r.signature])).digest('hex');

/** Validate the entire hash chain; only SHA256 structural linkage, not signatures. */
export function verifyCASProofLedger(entries,trustedFloor=undefined) {
 if(!Array.isArray(entries)||entries.length>10000||
    (trustedFloor!==undefined&&!position(trustedFloor)))return fail('INVALID_LEDGER_INPUT');
 let head=genesis;const operations=new Set();
 for(let i=0;i<entries.length;i++) {
   const e=entries[i];
   if(!exact(e,fields)||e.sequence!==i+1||!hex(e.previousHash)||
      e.previousHash!==head||!id(e.operationId)||!id(e.custodianId)||
      !hex(e.receiptDigest)||!hex(e.beforeDigest)||!hex(e.afterDigest)||
      !Number.isSafeInteger(e.beforeRevision)||e.beforeRevision<1||
      e.afterRevision!==e.beforeRevision+1||
      !hex(e.hash)||e.hash!==recordHash(e)||operations.has(e.operationId))
     return fail('BROKEN_PROOF_CHAIN');
   if(i>0 && (e.beforeRevision!==entries[i-1].afterRevision||
      e.beforeDigest!==entries[i-1].afterDigest))
     return fail('NONCONTIGUOUS_ANCHOR_HISTORY');
   operations.add(e.operationId);head=e.hash;
 }
 if(trustedFloor!==undefined) {
   if(entries.length<trustedFloor.count)return fail('ROLLBACK_BELOW_TRUSTED_FLOOR');
   const observedFloor=trustedFloor.count===0?genesis:entries[trustedFloor.count-1].hash;
   if(observedFloor!==trustedFloor.head)return fail('TRUSTED_FLOOR_CONFLICT');
 }
 return Object.freeze({ok:true,reason:'STRUCTURAL_PROOFS_ONLY',
   authorized:false,position:Object.freeze({count:entries.length,head})});
}

/** Requires externally authentic, fresh trust for a specific signed CAS receipt.
 * A verified receipt is the custodian's assertion, not independently proven execution.
 */
export function proposeCASProofAppend(entries,trustedHead,plan,receipt,trust) {
 if(!position(trustedHead))return fail('INVALID_TRUSTED_HEAD');
 const state=verifyCASProofLedger(entries,trustedHead);
 if(!state.ok||state.position.count!==trustedHead.count||
    state.position.head!==trustedHead.head)return fail('TRUSTED_HEAD_CONFLICT');
 const verified=verifyAnchorCASReceipt(plan,receipt,trust);
 if(!verified.ok)return fail('CAS_'+verified.reason);
 if(entries.length>=10000)return fail('LEDGER_FULL');
 const cas=verified.candidate;
 if(entries.some(x=>x.operationId===cas.operationId))return fail('OPERATION_REPLAY');
 const previous=entries.at(-1);
 if(previous&&(previous.afterRevision!==cas.before.revision||
    previous.afterDigest!==cas.before.digest))
   return fail('NONCONTIGUOUS_ANCHOR_HISTORY');
 let digest;
 try{digest=receiptHash(receipt);}catch{return fail('INVALID_RECEIPT');}
 const body={sequence:entries.length+1,previousHash:state.position.head,
   operationId:cas.operationId,custodianId:receipt.custodianId,receiptDigest:digest,
   beforeRevision:cas.before.revision,beforeDigest:cas.before.digest,
   afterRevision:cas.after.revision,afterDigest:cas.after.digest};
 const entry=Object.freeze({...body,hash:recordHash(body)});
 return Object.freeze({ok:true,reason:'SIGNED_CAS_PROOF_PROPOSED_NO_AUTHORITY',
   authorized:false,candidate:Object.freeze({entry,position:Object.freeze({
     count:entries.length+1,head:entry.hash})})});
}

/** Compares two supplied observations against a separately authenticated floor.
 * Equivalence does NOT establish independent sources or external persistence.
 */
export function compareCASProofObservations(first,second,trustedFloor) {
 if(!position(trustedFloor))return status('HOLD','INVALID_TRUSTED_FLOOR');
 const a=verifyCASProofLedger(first,trustedFloor),b=verifyCASProofLedger(second,trustedFloor);
 if(!a.ok||!b.ok)return status('HOLD','INVALID_OR_ROLLED_BACK_OBSERVATION');
 if(a.position.count!==b.position.count||a.position.head!==b.position.head)
   return status('HOLD','CONFLICTING_OBSERVATIONS');
 return status('STABLE','MATCHING_STRUCTURAL_OBSERVATIONS_NO_AUTHORITY');
}
export const INITIAL_CAS_PROOF_POSITION=Object.freeze({count:0,head:genesis});
