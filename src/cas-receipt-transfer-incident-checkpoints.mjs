import {createHash,createPublicKey,verify as edVerify} from 'node:crypto';
import {verifyReceiptTransferConflictJournal} from './cas-receipt-transfer-conflicts.mjs';

/** NEO-065 — signed checkpoint history of NEO-064 OWNER/SECURITY incident escalations. */
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 (Object.getPrototypeOf(x)===Object.prototype||Object.getPrototypeOf(x)===null);
const exact=(x,k)=>obj(x)&&Object.keys(x).sort().join(',')===[...k].sort().join(',');
const id=x=>typeof x==='string'&&/^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const hex=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const sig=x=>typeof x==='string'&&/^[A-Za-z0-9+/]{86}==$/.test(x)&&
 Buffer.from(x,'base64').toString('base64')===x;
const pos=x=>exact(x,['count','head'])&&Number.isSafeInteger(x.count)&&x.count>=0&&x.count<=64&&hex(x.head);
const sha=x=>createHash('sha256').update(JSON.stringify(x)).digest('hex');
const deny=reason=>Object.freeze({ok:false,phase:'HOLD',reason,authorized:false,candidate:null});
const accept=(phase,reason,candidate)=>Object.freeze({ok:true,phase,reason,authorized:false,candidate});
const genesis=Object.freeze({count:0,head:'0'.repeat(64)});
const bodyKeys=['schema','namespace','checkpointId','sequence','previousHash','incidentPosition'];
const trustKeys=['namespace','custodianId','publicKeyPem','status','expectedCheckpointId'];
const attKeys=['custodianId','signature'];
const sealKeys=['body','attestations','hash'];
const sourceKeys=['entries','evidence','policy','policyPin','trustedIncidentFloor'];
const rowKeys=['source','seal','custodianTrust','expectedCustodianIds'];
function key(pem){
 try{if(typeof pem!=='string'||!pem.length||pem.length>8192)return null;
  const k=createPublicKey(pem);return k.asymmetricKeyType==='ed25519'?k:null;
 }catch{return null;}
}
const fp=k=>k.export({type:'spki',format:'der'}).toString('base64');
const validBody=b=>exact(b,bodyKeys)&&
 b.schema==='NEO-065-RECEIPT-INCIDENT-CHECKPOINT-v1'&&id(b.namespace)&&
 id(b.checkpointId)&&Number.isSafeInteger(b.sequence)&&
 b.sequence>=1&&b.sequence<=64&&hex(b.previousHash)&&
 pos(b.incidentPosition)&&b.incidentPosition.count>=1;
export function receiptTransferIncidentCheckpointPayload(body,custodianId){
 if(!validBody(body)||!id(custodianId))
  throw new TypeError('INVALID_RECEIPT_INCIDENT_CHECKPOINT');
 return Buffer.from(JSON.stringify(['PALACO-NEO-065-RECEIPT-INCIDENT-CHECKPOINT-v1',
  body.namespace,body.checkpointId,body.sequence,body.previousHash,
  body.incidentPosition.count,body.incidentPosition.head,custodianId]),'utf8');
}
export function receiptTransferIncidentCheckpointHash(body,attestations){
 receiptTransferIncidentCheckpointPayload(body,'entry-hash');
 if(!Array.isArray(attestations)||attestations.length<2||attestations.length>16||
    attestations.some(a=>!exact(a,attKeys)||!id(a.custodianId)||!sig(a.signature))||
    new Set(attestations.map(a=>a.custodianId)).size!==attestations.length)
  throw new TypeError('INVALID_RECEIPT_INCIDENT_CHECKPOINT_ATTESTATIONS');
 return sha(['PALACO-NEO-065-RECEIPT-INCIDENT-ENTRY-v1',
  receiptTransferIncidentCheckpointPayload(body,'entry-hash').toString('base64'),
  [...attestations].sort((a,b)=>a.custodianId<b.custodianId?-1:1)
   .map(a=>[a.custodianId,a.signature])]);
}
export function verifyReceiptTransferIncidentCheckpointHistory(records,trustedFloor){
 if(!Array.isArray(records)||records.length>64||!pos(trustedFloor))
  return deny('INVALID_RECEIPT_INCIDENT_CHECKPOINT_INPUT');
 if(records.length<trustedFloor.count)return deny('RECEIPT_INCIDENT_CHECKPOINT_ROLLBACK');
 let head=genesis.head,namespace=null,previous=genesis,priorEntries=[];
 const ids=new Set(),keyOwners=new Map(),identityKeys=new Map(),history=[];
 for(let i=0;i<records.length;i++){
  const row=records[i];
  if(!exact(row,rowKeys)||!exact(row?.source,sourceKeys)||
     !exact(row?.seal,sealKeys)||!validBody(row.seal.body)||
     !hex(row.seal.hash)||!Array.isArray(row.seal.attestations)||
     !Array.isArray(row.custodianTrust)||!Array.isArray(row.expectedCustodianIds))
   return deny('INVALID_RECEIPT_INCIDENT_CHECKPOINT_ROW');
  const b=row.seal.body,s=row.source;
  if(b.sequence!==i+1||b.previousHash!==head)
   return deny('BROKEN_RECEIPT_INCIDENT_CHECKPOINT_CHAIN');
  if(ids.has(b.checkpointId))return deny('REPLAYED_RECEIPT_INCIDENT_CHECKPOINT_ID');
  if(namespace!==null&&namespace!==b.namespace)
   return deny('CHECKPOINT_NAMESPACE_CHANGED');
  const proof=verifyReceiptTransferConflictJournal(s.entries,s.evidence,
   s.policy,s.policyPin,s.trustedIncidentFloor);
  if(!proof.ok)return deny('INCIDENT_'+proof.reason);
  const p=proof.candidate.position;
  if(s.policy.namespace!==b.namespace||
     p.count!==b.incidentPosition.count||p.head!==b.incidentPosition.head)
   return deny('INCIDENT_CHECKPOINT_SCOPE_CONFLICT');
  if(p.count<previous.count)return deny('INCIDENT_HISTORY_ROLLBACK');
  for(let j=0;j<priorEntries.length;j++){
   if(s.entries[j]?.hash!==priorEntries[j])
    return deny('INCIDENT_HISTORY_PREFIX_REWRITTEN');
  }
  const expected=row.expectedCustodianIds;
  if(expected.length<2||expected.length>16||
     expected.length!==row.custodianTrust.length||
     expected.length!==row.seal.attestations.length||
     expected.some(x=>!id(x))||new Set(expected).size!==expected.length)
   return deny('INVALID_CHECKPOINT_CUSTODIAN_ROSTER');
  const excluded=new Set();
  for(const review of s.policy.reviewers){
   const k=key(review.publicKeyPem);
   if(!k)return deny('INVALID_REVIEWER_KEY');
   excluded.add(fp(k));
  }
  for(const e of s.evidence){
   const k=key(e?.trust?.publicKeyPem);
   if(!k)return deny('INVALID_DISPUTED_KEY');
   excluded.add(fp(k));
   for(const original of e.canonicalHistory){
    for(const t of original.custodianTrust){
     const witness=key(t.publicKeyPem);
     if(!witness)return deny('INVALID_ORIGINAL_CUSTODIAN_KEY');
     excluded.add(fp(witness));
    }
   }
  }
  const roster=new Map(),rosterKeys=new Set();
  for(const t of row.custodianTrust){
   if(!exact(t,trustKeys)||!expected.includes(t.custodianId)||
      roster.has(t.custodianId)||t.namespace!==b.namespace||
      t.expectedCheckpointId!==b.checkpointId||t.status!=='ACTIVE')
    return deny('INVALID_OR_REVOKED_CHECKPOINT_CUSTODIAN');
   const k=key(t.publicKeyPem);
   if(!k)return deny('INVALID_CHECKPOINT_CUSTODIAN_KEY');
   const fingerprint=fp(k);
   if(rosterKeys.has(fingerprint)||excluded.has(fingerprint))
    return deny('NONINDEPENDENT_CHECKPOINT_CUSTODIAN');
   if(identityKeys.has(t.custodianId)&&identityKeys.get(t.custodianId)!==fingerprint)
    return deny('CHECKPOINT_CUSTODIAN_KEY_CHANGED');
   if(keyOwners.has(fingerprint)&&keyOwners.get(fingerprint)!==t.custodianId)
    return deny('CHECKPOINT_CUSTODIAN_KEY_REASSIGNED');
   roster.set(t.custodianId,k);rosterKeys.add(fingerprint);
  }
  const signed=new Set();
  for(const a of row.seal.attestations){
   if(!exact(a,attKeys)||!id(a.custodianId)||!sig(a.signature)||
      !roster.has(a.custodianId)||signed.has(a.custodianId))
    return deny('INVALID_OR_DUPLICATE_CUSTODIAN_ATTESTATION');
   if(!edVerify(null,receiptTransferIncidentCheckpointPayload(b,a.custodianId),
      roster.get(a.custodianId),Buffer.from(a.signature,'base64')))
    return deny('FORGED_CHECKPOINT_ATTESTATION');
   signed.add(a.custodianId);
  }
  if(signed.size!==roster.size)return deny('MISSING_CUSTODIAN_ATTESTATION');
  if(receiptTransferIncidentCheckpointHash(b,row.seal.attestations)!==row.seal.hash)
   return deny('TAMPERED_RECEIPT_INCIDENT_CHECKPOINT_HASH');
  for(const t of row.custodianTrust){
   const fingerprint=fp(roster.get(t.custodianId));
   identityKeys.set(t.custodianId,fingerprint);keyOwners.set(fingerprint,t.custodianId);
  }
  ids.add(b.checkpointId);head=row.seal.hash;namespace=b.namespace;
  previous=p;priorEntries=s.entries.map(x=>x.hash);
  history.push(Object.freeze({sequence:i+1,checkpointId:b.checkpointId,head,
   incidentPosition:p}));
 }
 const ancestor=trustedFloor.count===0?genesis.head:history[trustedFloor.count-1].head;
 if(ancestor!==trustedFloor.head)return deny('TRUSTED_RECEIPT_INCIDENT_CHECKPOINT_FORK');
 return accept('RECEIPT_TRANSFER_INCIDENT_CHECKPOINT_HISTORY_VERIFIED_HOLD',
  'SIGNED_INCIDENT_CHECKPOINTS_NO_AUTHORITY',
  Object.freeze({position:Object.freeze({count:records.length,head}),
   checkpoints:Object.freeze(history)}));
}
export function inspectReceiptTransferIncidentCheckpointConflict(left,right,trust,predecessor){
 if(!exact(left,['body','attestation'])||!exact(right,['body','attestation'])||
    !validBody(left.body)||!validBody(right.body)||
    !exact(trust,trustKeys)||!pos(predecessor))
  return deny('INVALID_CHECKPOINT_CONFLICT_INPUT');
 const a=left.body,b=right.body;
 if(a.namespace!==b.namespace||a.checkpointId!==b.checkpointId||
    a.sequence!==b.sequence||a.previousHash!==b.previousHash||
    a.sequence!==predecessor.count+1||a.previousHash!==predecessor.head||
    trust.namespace!==a.namespace||trust.expectedCheckpointId!==a.checkpointId||
    trust.status!=='ACTIVE')
  return deny('UNRELATED_CHECKPOINT_CLAIMS');
 const k=key(trust.publicKeyPem);
 if(!k)return deny('INVALID_CONFLICT_CUSTODIAN_KEY');
 for(const claim of [left,right]){
  if(!exact(claim.attestation,attKeys)||
     claim.attestation.custodianId!==trust.custodianId||
     !sig(claim.attestation.signature)||
     !edVerify(null,receiptTransferIncidentCheckpointPayload(claim.body,trust.custodianId),
      k,Buffer.from(claim.attestation.signature,'base64')))
   return deny('UNVERIFIED_CHECKPOINT_CONFLICT_CLAIM');
 }
 if(a.incidentPosition.count===b.incidentPosition.count&&
    a.incidentPosition.head===b.incidentPosition.head)
  return accept('NO_PROVEN_CONFLICT','MATCHING_SIGNED_INCIDENT_POSITION',null);
 const positions=[a.incidentPosition,b.incidentPosition].map(p=>[p.count,p.head])
  .sort((x,y)=>x[0]-y[0]||(x[1]<y[1]?-1:x[1]>y[1]?1:0));
 return accept('RECEIPT_TRANSFER_INCIDENT_CHECKPOINT_CONFLICT_HOLD',
  'TWO_INCOMPATIBLE_SIGNED_INCIDENT_POSITIONS',
  Object.freeze({custodianId:trust.custodianId,checkpointId:a.checkpointId,
   sequence:a.sequence,positions:Object.freeze(positions),
   evidenceDigest:sha(['PALACO-NEO-065-INCIDENT-CHECKPOINT-CONFLICT-v1',
    a.namespace,a.checkpointId,a.sequence,a.previousHash,
    trust.custodianId,fp(k),positions])}));
}
export const INITIAL_RECEIPT_TRANSFER_INCIDENT_CHECKPOINT_POSITION=genesis;
