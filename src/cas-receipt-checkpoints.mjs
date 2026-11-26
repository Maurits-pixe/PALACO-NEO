import {createHash,createPublicKey,verify as edVerify} from 'node:crypto';
import {verifyEscalationReceiptSuccession,INITIAL_RECEIPT_SUCCESSION_POSITION}
 from './cas-escalation-receipt-succession.mjs';

/** NEO-053: verification-only, independently signed receipt checkpoints. */
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 (Object.getPrototypeOf(x)===Object.prototype||Object.getPrototypeOf(x)===null);
const exact=(x,fields)=>plain(x)&&Object.keys(x).sort().join(',')===[...fields].sort().join(',');
const ident=x=>typeof x==='string'&&/^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const hex=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const signature=x=>typeof x==='string'&&/^[A-Za-z0-9+/]{86}==$/.test(x)&&
 Buffer.from(x,'base64').toString('base64')===x;
const position=x=>exact(x,['count','head'])&&Number.isSafeInteger(x.count)&&
 x.count>=0&&x.count<=64&&hex(x.head);
const hash=x=>createHash('sha256').update(JSON.stringify(x)).digest('hex');
const fail=reason=>Object.freeze({ok:false,phase:'HOLD',reason,authorized:false,candidate:null});
const success=(phase,reason,candidate)=>Object.freeze({ok:true,phase,reason,authorized:false,candidate});
const GENESIS=Object.freeze({count:0,head:'0'.repeat(64)});
const bodyFields=['schema','namespace','checkpointId','sequence','previousHash','receiptPosition'];
const claimFields=['custodianId','signature'];
const trustFields=['namespace','custodianId','publicKeyPem','status','expectedCheckpointId'];
const sealFields=['body','attestations','hash'];
const recordFields=['source','seal','custodianTrust','expectedCustodianIds'];
const sourceFields=['entries','trustedReceiptFloor'];
function key(pem){
 try{
  if(typeof pem!=='string'||!pem.length||pem.length>8192)return null;
  const k=createPublicKey(pem);return k.asymmetricKeyType==='ed25519'?k:null;
 }catch{return null;}
}
const fingerprint=k=>k.export({type:'spki',format:'der'}).toString('base64');
const validBody=b=>exact(b,bodyFields)&&b.schema==='NEO-053-RECEIPT-CHECKPOINT-v1'&&
 ident(b.namespace)&&ident(b.checkpointId)&&
 Number.isSafeInteger(b.sequence)&&b.sequence>=1&&b.sequence<=64&&
 hex(b.previousHash)&&position(b.receiptPosition)&&b.receiptPosition.count>=1;
export function receiptCheckpointPayload(body,custodianId){
 if(!validBody(body)||!ident(custodianId))
  throw new TypeError('INVALID_RECEIPT_CHECKPOINT_PAYLOAD');
 return Buffer.from(JSON.stringify(['PALACO-NEO-053-RECEIPT-CHECKPOINT-v1',
  body.namespace,body.checkpointId,body.sequence,body.previousHash,
  body.receiptPosition.count,body.receiptPosition.head,custodianId]),'utf8');
}
export function receiptCheckpointHash(body,attestations){
 receiptCheckpointPayload(body,'entry-hash');
 if(!Array.isArray(attestations)||attestations.length<2||attestations.length>16||
    attestations.some(x=>!exact(x,claimFields)||!ident(x.custodianId)||
     !signature(x.signature))||
    new Set(attestations.map(x=>x.custodianId)).size!==attestations.length)
  throw new TypeError('INVALID_RECEIPT_CHECKPOINT_ATTESTATIONS');
 return hash(['PALACO-NEO-053-RECEIPT-CHECKPOINT-ENTRY-v1',
  receiptCheckpointPayload(body,'entry-hash').toString('base64'),
  [...attestations].sort((a,b)=>a.custodianId<b.custodianId?-1:1)
   .map(x=>[x.custodianId,x.signature])]);
}
/** Replays all original NEO-052/051/... evidence for every checkpoint,
 * enforces historical witness key continuity and the earlier receipt prefix.
 * Callers must independently authenticate witness trust roots and floors.
 */
export function verifyReceiptCheckpointHistory(records,trustedFloor){
 if(!Array.isArray(records)||records.length>64||!position(trustedFloor))
  return fail('INVALID_RECEIPT_CHECKPOINT_INPUT');
 if(records.length<trustedFloor.count)return fail('RECEIPT_CHECKPOINT_ROLLBACK');
 let head=GENESIS.head,namespace=null,priorReceipt=GENESIS,priorEntries=[];
 const usedIds=new Set(),usedKeys=new Map(),custodianKeys=new Map(),out=[];
 for(let i=0;i<records.length;i++){
  const record=records[i];
  if(!exact(record,recordFields)||!exact(record?.source,sourceFields)||
     !exact(record?.seal,sealFields)||!validBody(record.seal.body)||
     !hex(record.seal.hash)||!Array.isArray(record.seal.attestations)||
     !Array.isArray(record.custodianTrust)||!Array.isArray(record.expectedCustodianIds))
   return fail('INVALID_RECEIPT_CHECKPOINT_ENTRY');
  const b=record.seal.body,source=record.source;
  if(b.sequence!==i+1||b.previousHash!==head)return fail('BROKEN_CHECKPOINT_CHAIN');
  if(usedIds.has(b.checkpointId))return fail('REPLAYED_RECEIPT_CHECKPOINT_ID');
  if(namespace!==null&&namespace!==b.namespace)return fail('CHECKPOINT_NAMESPACE_CONFLICT');
  if(!Array.isArray(source.entries)||!position(source.trustedReceiptFloor))
   return fail('INVALID_RECEIPT_SOURCE');
  const verified=verifyEscalationReceiptSuccession(source.entries,source.trustedReceiptFloor);
  if(!verified.ok)return fail('RECEIPT_'+verified.reason);
  const actual=verified.candidate.position;
  if(b.receiptPosition.count!==actual.count||b.receiptPosition.head!==actual.head||
     source.entries.some(entry=>entry?.transfer?.bundle?.namespace!==b.namespace))
   return fail('RECEIPT_CHECKPOINT_CONTEXT_CONFLICT');
  if(actual.count<priorReceipt.count)return fail('RECEIPT_REGISTER_ROLLBACK');
  for(let j=0;j<priorEntries.length;j++){
   if(source.entries[j]?.hash!==priorEntries[j])
    return fail('RECEIPT_REGISTER_PREFIX_REWRITTEN');
  }
  const rosterIds=record.expectedCustodianIds;
  if(rosterIds.length<2||rosterIds.length>16||
     rosterIds.length!==record.custodianTrust.length||
     rosterIds.length!==record.seal.attestations.length||
     rosterIds.some(x=>!ident(x))||new Set(rosterIds).size!==rosterIds.length)
   return fail('INVALID_CHECKPOINT_CUSTODIAN_ROSTER');
  const excluded=new Set();
  for(const receipt of source.entries){
   for(const recipient of receipt.transfer.trusts){
    const k=key(recipient.publicKeyPem);
    if(!k)return fail('INVALID_ARCHIVE_RECIPIENT_TRUST');
    excluded.add(fingerprint(k));
   }
   for(const checkpoint of receipt.transfer.bundle.records){
    for(const trustee of checkpoint.custodianTrust){
     const k=key(trustee.publicKeyPem);
     if(!k)return fail('INVALID_UPSTREAM_CUSTODIAN_TRUST');
     excluded.add(fingerprint(k));
    }
   }
  }
  const roster=new Map(),currentKeys=new Set();
  for(const trust of record.custodianTrust){
   if(!exact(trust,trustFields)||!rosterIds.includes(trust.custodianId)||
      roster.has(trust.custodianId)||trust.namespace!==b.namespace||
      trust.expectedCheckpointId!==b.checkpointId||trust.status!=='ACTIVE')
    return fail('INVALID_OR_REVOKED_CHECKPOINT_CUSTODIAN');
   const k=key(trust.publicKeyPem);
   if(!k)return fail('INVALID_CHECKPOINT_CUSTODIAN_KEY');
   const fp=fingerprint(k);
   if(currentKeys.has(fp)||excluded.has(fp))return fail('NONINDEPENDENT_CHECKPOINT_CUSTODIAN');
   const old=custodianKeys.get(trust.custodianId);
   if(old!==undefined&&old!==fp)return fail('CUSTODIAN_KEY_CHANGED_WITHOUT_PROOF');
   const owner=usedKeys.get(fp);
   if(owner!==undefined&&owner!==trust.custodianId)
    return fail('CUSTODIAN_KEY_REASSIGNED');
   roster.set(trust.custodianId,k);currentKeys.add(fp);
  }
  const signed=new Set();
  for(const att of record.seal.attestations){
   if(!exact(att,claimFields)||!ident(att.custodianId)||
      !signature(att.signature)||!roster.has(att.custodianId)||
      signed.has(att.custodianId))
    return fail('INVALID_OR_DUPLICATE_CUSTODIAN_ATTESTATION');
   if(!edVerify(null,receiptCheckpointPayload(b,att.custodianId),
      roster.get(att.custodianId),Buffer.from(att.signature,'base64')))
    return fail('FORGED_CHECKPOINT_ATTESTATION');
   signed.add(att.custodianId);
  }
  if(signed.size!==roster.size)return fail('MISSING_CHECKPOINT_ATTESTATION');
  if(receiptCheckpointHash(b,record.seal.attestations)!==record.seal.hash)
   return fail('TAMPERED_RECEIPT_CHECKPOINT_HASH');
  for(const t of record.custodianTrust){
   const fp=fingerprint(roster.get(t.custodianId));
   custodianKeys.set(t.custodianId,fp);usedKeys.set(fp,t.custodianId);
  }
  usedIds.add(b.checkpointId);namespace=b.namespace;head=record.seal.hash;
  priorReceipt=actual;priorEntries=source.entries.map(x=>x.hash);
  out.push(Object.freeze({sequence:i+1,checkpointId:b.checkpointId,
   head,receiptPosition:actual}));
 }
 const anchor=trustedFloor.count===0?GENESIS.head:
  out[trustedFloor.count-1].head;
 if(anchor!==trustedFloor.head)return fail('TRUSTED_RECEIPT_CHECKPOINT_FORK');
 return success('RECEIPT_CHECKPOINT_HISTORY_VERIFIED_HOLD',
  'INDEPENDENTLY_SIGNED_RECEIPT_CHECKPOINTS_NO_AUTHORITY',
  Object.freeze({position:Object.freeze({count:records.length,head}),
   checkpoints:Object.freeze(out)}));
}
/** Cryptographic equivocation only; does not select a canonical branch. */
export function inspectReceiptCheckpointEquivocation(left,right,trust,predecessor){
 if(!exact(left,['body','attestation'])||!exact(right,['body','attestation'])||
    !validBody(left.body)||!validBody(right.body)||!exact(trust,trustFields)||
    !position(predecessor))return fail('INVALID_RECEIPT_EQUIVOCATION_INPUT');
 const a=left.body,b=right.body;
 if(a.namespace!==b.namespace||a.checkpointId!==b.checkpointId||
    a.sequence!==b.sequence||a.previousHash!==b.previousHash||
    a.sequence!==predecessor.count+1||a.previousHash!==predecessor.head||
    trust.namespace!==a.namespace||trust.status!=='ACTIVE'||
    trust.expectedCheckpointId!==a.checkpointId)
  return fail('UNRELATED_RECEIPT_CHECKPOINTS');
 const k=key(trust.publicKeyPem);
 if(!k)return fail('INVALID_EQUIVOCATION_TRUST_KEY');
 for(const claim of [left,right]){
  if(!exact(claim.attestation,claimFields)||
     claim.attestation.custodianId!==trust.custodianId||
     !signature(claim.attestation.signature)||
     !edVerify(null,receiptCheckpointPayload(claim.body,trust.custodianId),
       k,Buffer.from(claim.attestation.signature,'base64')))
   return fail('UNVERIFIED_RECEIPT_CHECKPOINT_CLAIM');
 }
 if(a.receiptPosition.count===b.receiptPosition.count&&
    a.receiptPosition.head===b.receiptPosition.head)
  return success('NO_PROVEN_CONFLICT','MATCHING_SIGNED_RECEIPT_POSITION',null);
 const positions=[a.receiptPosition,b.receiptPosition]
  .map(p=>[p.count,p.head]).sort((x,y)=>x[0]-y[0]||
    (x[1]<y[1]?-1:x[1]>y[1]?1:0));
 return success('RECEIPT_CHECKPOINT_EQUIVOCATION_HOLD',
  'TWO_CONTRADICTORY_SIGNED_RECEIPT_POSITIONS',
  Object.freeze({custodianId:trust.custodianId,checkpointId:a.checkpointId,
   sequence:a.sequence,positions:Object.freeze(positions),
   evidenceDigest:hash(['PALACO-NEO-053-RECEIPT-EQUIVOCATION-v1',
    a.namespace,a.checkpointId,a.sequence,a.previousHash,trust.custodianId,
    fingerprint(k),positions])}));
}
export const INITIAL_RECEIPT_CHECKPOINT_POSITION=GENESIS;
