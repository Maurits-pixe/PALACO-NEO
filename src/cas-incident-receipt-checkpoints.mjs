import {createHash,createPublicKey,verify as edVerify} from 'node:crypto';
import {verifyIncidentTransferReceiptHistory} from './cas-incident-transfer-receipts.mjs';

/** NEO-058: read-only signed checkpoints for complete NEO-057 registers. */
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 (Object.getPrototypeOf(x)===Object.prototype||Object.getPrototypeOf(x)===null);
const exact=(x,k)=>plain(x)&&Object.keys(x).sort().join(',')===[...k].sort().join(',');
const ident=x=>typeof x==='string'&&/^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const hex=x=>typeof x==='string'&&/^[0-9a-f]{64}$/.test(x);
const sig=x=>typeof x==='string'&&/^[A-Za-z0-9+/]{86}==$/.test(x)&&
 Buffer.from(x,'base64').toString('base64')===x;
const position=x=>exact(x,['count','head'])&&Number.isSafeInteger(x.count)&&
 x.count>=0&&x.count<=64&&hex(x.head);
const sha=x=>createHash('sha256').update(JSON.stringify(x)).digest('hex');
const fail=reason=>Object.freeze({ok:false,phase:'HOLD',reason,authorized:false,candidate:null});
const success=(phase,reason,candidate)=>Object.freeze({ok:true,phase,reason,authorized:false,candidate});
const genesis=Object.freeze({count:0,head:'0'.repeat(64)});
const bodyFields=['schema','namespace','checkpointId','sequence','previousHash','receiptPosition'];
const trustFields=['namespace','custodianId','publicKeyPem','status','expectedCheckpointId'];
const attFields=['custodianId','signature'];
const sealFields=['body','attestations','hash'];
const rowFields=['source','seal','custodianTrust','expectedCustodianIds'];
const sourceFields=['entries','trustedReceiptFloor'];
function key(pem){
 try{
  if(typeof pem!=='string'||!pem.length||pem.length>8192)return null;
  const k=createPublicKey(pem);return k.asymmetricKeyType==='ed25519'?k:null;
 }catch{return null;}
}
const fingerprint=k=>k.export({type:'spki',format:'der'}).toString('base64');
const validBody=b=>exact(b,bodyFields)&&
 b.schema==='NEO-058-INCIDENT-RECEIPT-CHECKPOINT-v1'&&
 ident(b.namespace)&&ident(b.checkpointId)&&
 Number.isSafeInteger(b.sequence)&&b.sequence>=1&&b.sequence<=64&&
 hex(b.previousHash)&&position(b.receiptPosition)&&b.receiptPosition.count>=1;
export function incidentReceiptCheckpointPayload(body,custodianId){
 if(!validBody(body)||!ident(custodianId))
  throw new TypeError('INVALID_INCIDENT_RECEIPT_CHECKPOINT');
 return Buffer.from(JSON.stringify(['PALACO-NEO-058-INCIDENT-RECEIPT-CHECKPOINT-v1',
  body.namespace,body.checkpointId,body.sequence,body.previousHash,
  body.receiptPosition.count,body.receiptPosition.head,custodianId]),'utf8');
}
export function incidentReceiptCheckpointHash(body,attestations){
 incidentReceiptCheckpointPayload(body,'entry-hash');
 if(!Array.isArray(attestations)||attestations.length<2||attestations.length>16||
    attestations.some(a=>!exact(a,attFields)||!ident(a.custodianId)||!sig(a.signature))||
    new Set(attestations.map(a=>a.custodianId)).size!==attestations.length)
  throw new TypeError('INVALID_INCIDENT_RECEIPT_ATTESTATIONS');
 return sha(['PALACO-NEO-058-INCIDENT-RECEIPT-CHECKPOINT-ENTRY-v1',
  incidentReceiptCheckpointPayload(body,'entry-hash').toString('base64'),
  [...attestations].sort((a,b)=>a.custodianId<b.custodianId?-1:1)
   .map(a=>[a.custodianId,a.signature])]);
}
/** Replays every original NEO-057/056/055/... proof before accepting a head.
 * Caller is responsible for independent key roots and monotonic external pins.
 */
export function verifyIncidentReceiptCheckpointHistory(rows,trustedFloor){
 if(!Array.isArray(rows)||rows.length>64||!position(trustedFloor))
  return fail('INVALID_INCIDENT_RECEIPT_CHECKPOINT_INPUT');
 if(rows.length<trustedFloor.count)return fail('INCIDENT_RECEIPT_CHECKPOINT_ROLLBACK');
 let head=genesis.head,namespace=null,prior=genesis,priorEntries=[];
 const ids=new Set(),keyOwners=new Map(),identityKeys=new Map(),out=[];
 for(let i=0;i<rows.length;i++){
  const row=rows[i];
  if(!exact(row,rowFields)||!exact(row?.source,sourceFields)||
     !exact(row?.seal,sealFields)||!validBody(row.seal.body)||
     !hex(row.seal.hash)||!Array.isArray(row.seal.attestations)||
     !Array.isArray(row.custodianTrust)||!Array.isArray(row.expectedCustodianIds))
   return fail('INVALID_INCIDENT_RECEIPT_CHECKPOINT_ROW');
  const b=row.seal.body,s=row.source;
  if(b.sequence!==i+1||b.previousHash!==head)
   return fail('BROKEN_INCIDENT_RECEIPT_CHECKPOINT_CHAIN');
  if(ids.has(b.checkpointId))return fail('REPLAYED_INCIDENT_RECEIPT_CHECKPOINT_ID');
  if(namespace!==null&&namespace!==b.namespace)return fail('CHECKPOINT_NAMESPACE_CHANGED');
  const verified=verifyIncidentTransferReceiptHistory(s.entries,s.trustedReceiptFloor);
  if(!verified.ok)return fail('RECEIPT_'+verified.reason);
  const p=verified.candidate.position;
  if(p.count!==b.receiptPosition.count||p.head!==b.receiptPosition.head||
     s.entries.some(e=>e?.transfer?.bundle?.namespace!==b.namespace))
   return fail('INCIDENT_RECEIPT_CHECKPOINT_CONTEXT_CONFLICT');
  if(p.count<prior.count)return fail('INCIDENT_RECEIPT_HISTORY_ROLLBACK');
  for(let j=0;j<priorEntries.length;j++){
   if(s.entries[j]?.hash!==priorEntries[j])
    return fail('INCIDENT_RECEIPT_PREFIX_REWRITTEN');
  }
  const expected=row.expectedCustodianIds;
  if(expected.length<2||expected.length>16||
     expected.length!==row.custodianTrust.length||
     expected.length!==row.seal.attestations.length||
     expected.some(x=>!ident(x))||new Set(expected).size!==expected.length)
   return fail('INVALID_INCIDENT_RECEIPT_CUSTODIAN_ROSTER');
  const excluded=new Set();
  for(const receipt of s.entries){
   for(const t of receipt.transfer.trusts){
    const k=key(t.publicKeyPem);
    if(!k)return fail('INVALID_ARCHIVE_RECIPIENT_KEY');
    excluded.add(fingerprint(k));
   }
   for(const incident of receipt.transfer.bundle.records){
    for(const t of incident.custodianTrust){
     const k=key(t.publicKeyPem);
     if(!k)return fail('INVALID_INCIDENT_CHECKPOINT_KEY');
     excluded.add(fingerprint(k));
    }
   }
  }
  const roster=new Map(),rosterKeys=new Set();
  for(const t of row.custodianTrust){
   if(!exact(t,trustFields)||!expected.includes(t.custodianId)||
      roster.has(t.custodianId)||t.namespace!==b.namespace||
      t.expectedCheckpointId!==b.checkpointId||t.status!=='ACTIVE')
    return fail('INVALID_OR_REVOKED_RECEIPT_CUSTODIAN');
   const k=key(t.publicKeyPem);
   if(!k)return fail('INVALID_RECEIPT_CUSTODIAN_PUBLIC_KEY');
   const f=fingerprint(k);
   if(rosterKeys.has(f)||excluded.has(f))
    return fail('NONINDEPENDENT_INCIDENT_RECEIPT_CUSTODIAN');
   if(identityKeys.has(t.custodianId)&&identityKeys.get(t.custodianId)!==f)
    return fail('RECEIPT_CUSTODIAN_KEY_CHANGED');
   if(keyOwners.has(f)&&keyOwners.get(f)!==t.custodianId)
    return fail('RECEIPT_CUSTODIAN_KEY_REASSIGNED');
   roster.set(t.custodianId,k);rosterKeys.add(f);
  }
  const signed=new Set();
  for(const att of row.seal.attestations){
   if(!exact(att,attFields)||!ident(att.custodianId)||!sig(att.signature)||
      !roster.has(att.custodianId)||signed.has(att.custodianId))
    return fail('INVALID_OR_DUPLICATE_RECEIPT_ATTESTATION');
   if(!edVerify(null,incidentReceiptCheckpointPayload(b,att.custodianId),
      roster.get(att.custodianId),Buffer.from(att.signature,'base64')))
    return fail('FORGED_RECEIPT_CHECKPOINT_ATTESTATION');
   signed.add(att.custodianId);
  }
  if(signed.size!==roster.size)return fail('MISSING_RECEIPT_CUSTODIAN_ATTESTATION');
  if(incidentReceiptCheckpointHash(b,row.seal.attestations)!==row.seal.hash)
   return fail('TAMPERED_INCIDENT_RECEIPT_CHECKPOINT_HASH');
  for(const t of row.custodianTrust){
   const f=fingerprint(roster.get(t.custodianId));
   identityKeys.set(t.custodianId,f);keyOwners.set(f,t.custodianId);
  }
  ids.add(b.checkpointId);head=row.seal.hash;namespace=b.namespace;
  prior=p;priorEntries=s.entries.map(x=>x.hash);
  out.push(Object.freeze({sequence:i+1,checkpointId:b.checkpointId,head,
   receiptPosition:p}));
 }
 const known=trustedFloor.count===0?genesis.head:out[trustedFloor.count-1].head;
 if(known!==trustedFloor.head)return fail('TRUSTED_INCIDENT_RECEIPT_CHECKPOINT_FORK');
 return success('INCIDENT_RECEIPT_CHECKPOINT_HISTORY_VERIFIED_HOLD',
  'INDEPENDENTLY_SIGNED_RECEIPT_HISTORY_NO_AUTHORITY',
  Object.freeze({position:Object.freeze({count:rows.length,head}),
   checkpoints:Object.freeze(out)}));
}
/** Both statements from one independently pinned Ed25519 key: forensic only. */
export function inspectIncidentReceiptCheckpointConflict(left,right,trust,predecessor){
 if(!exact(left,['body','attestation'])||!exact(right,['body','attestation'])||
    !validBody(left.body)||!validBody(right.body)||!exact(trust,trustFields)||
    !position(predecessor))return fail('INVALID_RECEIPT_CHECKPOINT_CONFLICT_INPUT');
 const a=left.body,b=right.body;
 if(a.namespace!==b.namespace||a.checkpointId!==b.checkpointId||
    a.sequence!==b.sequence||a.previousHash!==b.previousHash||
    a.sequence!==predecessor.count+1||a.previousHash!==predecessor.head||
    trust.namespace!==a.namespace||trust.status!=='ACTIVE'||
    trust.expectedCheckpointId!==a.checkpointId)
  return fail('UNRELATED_CHECKPOINT_CLAIMS');
 const k=key(trust.publicKeyPem);
 if(!k)return fail('INVALID_CONFLICT_CUSTODIAN_TRUST_KEY');
 for(const x of [left,right]){
  if(!exact(x.attestation,attFields)||
     x.attestation.custodianId!==trust.custodianId||
     !sig(x.attestation.signature)||
     !edVerify(null,incidentReceiptCheckpointPayload(x.body,trust.custodianId),
       k,Buffer.from(x.attestation.signature,'base64')))
   return fail('UNVERIFIED_RECEIPT_CHECKPOINT_CLAIM');
 }
 if(a.receiptPosition.count===b.receiptPosition.count&&
    a.receiptPosition.head===b.receiptPosition.head)
  return success('NO_PROVEN_CONFLICT','MATCHING_RECEIPT_REGISTER_POSITION',null);
 const states=[a.receiptPosition,b.receiptPosition].map(p=>[p.count,p.head])
  .sort((x,y)=>x[0]-y[0]||(x[1]<y[1]?-1:x[1]>y[1]?1:0));
 return success('INCIDENT_RECEIPT_CHECKPOINT_CONFLICT_HOLD',
  'TWO_INCOMPATIBLE_SIGNED_RECEIPT_POSITIONS',
  Object.freeze({checkpointId:a.checkpointId,custodianId:trust.custodianId,
   sequence:a.sequence,states:Object.freeze(states),
   evidenceDigest:sha(['PALACO-NEO-058-RECEIPT-CHECKPOINT-CONFLICT-v1',
    a.namespace,a.checkpointId,a.sequence,a.previousHash,trust.custodianId,
    fingerprint(k),states])}));
}
export const INITIAL_INCIDENT_RECEIPT_CHECKPOINT_POSITION=genesis;
