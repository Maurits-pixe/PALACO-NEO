import {createHash,createPublicKey} from 'node:crypto';
import {incidentEvidenceTransferDigest,verifyIncidentEvidenceTransfer}
 from './cas-incident-evidence-transfer.mjs';

/** NEO-057: non-authorizing succession of complete signed NEO-056 transfers. */
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 (Object.getPrototypeOf(x)===Object.prototype||Object.getPrototypeOf(x)===null);
const exact=(x,k)=>plain(x)&&Object.keys(x).sort().join(',')===[...k].sort().join(',');
const id=x=>typeof x==='string'&&/^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const hex=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const pos=x=>exact(x,['count','head'])&&Number.isSafeInteger(x.count)&&x.count>=0&&x.count<=64&&hex(x.head);
const sha=x=>createHash('sha256').update(JSON.stringify(x)).digest('hex');
const genesis=Object.freeze({count:0,head:'0'.repeat(64)});
const deny=reason=>Object.freeze({ok:false,phase:'HOLD',reason,authorized:false,candidate:null});
const inputKeys=['bundle','receipts','trusts','expectedRecipientIds','trustedTransferDigest'];
const bodyKeys=['schema','sequence','previousHash','transferId','transferDigest','checkpointPosition'];
const entryKeys=['body','transfer','hash'];
function fingerprint(pem){
 try{if(typeof pem!=='string'||pem.length===0||pem.length>8192)return null;
  const k=createPublicKey(pem);return k.asymmetricKeyType==='ed25519'?
   k.export({type:'spki',format:'der'}).toString('base64'):null;
 }catch{return null;}
}
const validBody=b=>exact(b,bodyKeys)&&b.schema==='NEO-057-INCIDENT-TRANSFER-RECEIPT-v1'&&
 Number.isSafeInteger(b.sequence)&&b.sequence>=1&&b.sequence<=64&&
 hex(b.previousHash)&&id(b.transferId)&&hex(b.transferDigest)&&
 pos(b.checkpointPosition)&&b.checkpointPosition.count>=1;
export function incidentTransferReceiptEntryHash(body,transfer){
 if(!validBody(body)||!exact(transfer,inputKeys)||
    !Array.isArray(transfer.receipts)||!Array.isArray(transfer.trusts)||
    !Array.isArray(transfer.expectedRecipientIds))
  throw new TypeError('INVALID_INCIDENT_RECEIPT_ENTRY');
 const statements=transfer.receipts.map(r=>[r.recipientId,r.signature])
  .sort((a,b)=>a[0]<b[0]?-1:a[0]>b[0]?1:0);
 const roster=transfer.trusts.map(t=>{
  const fp=fingerprint(t.publicKeyPem);
  if(!fp)throw new TypeError('INVALID_INCIDENT_RECEIPT_KEY');
  return [t.namespace,t.recipientId,fp,t.status,t.expectedTransferId];
 }).sort((a,b)=>a[1]<b[1]?-1:a[1]>b[1]?1:0);
 return sha(['PALACO-NEO-057-INCIDENT-TRANSFER-RECEIPT-v1',
  body.schema,body.sequence,body.previousHash,body.transferId,
  body.transferDigest,body.checkpointPosition.count,body.checkpointPosition.head,
  statements,roster,[...transfer.expectedRecipientIds].sort()]);
}
export function verifyIncidentTransferReceiptHistory(records,trustedFloor){
 if(!Array.isArray(records)||records.length>64||!pos(trustedFloor))
  return deny('INVALID_RECEIPT_HISTORY_INPUT');
 if(records.length<trustedFloor.count)return deny('RECEIPT_HISTORY_ROLLBACK');
 const ids=new Set(),keys=new Map(),owners=new Map(),results=[];
 let head=genesis.head,namespace=null,priorPosition=genesis,priorManifest=[];
 for(let i=0;i<records.length;i++){
  const entry=records[i],b=entry?.body,t=entry?.transfer;
  if(!exact(entry,entryKeys)||!validBody(b)||!exact(t,inputKeys)||
     !hex(entry.hash)||b.sequence!==i+1||b.previousHash!==head)
   return deny('BROKEN_RECEIPT_HISTORY_CHAIN');
  if(ids.has(b.transferId))return deny('TRANSFER_ID_REPLAY');
  if(namespace!==null&&t.bundle?.namespace!==namespace)
   return deny('TRANSFER_NAMESPACE_CHANGED');
  const verified=verifyIncidentEvidenceTransfer(t.bundle,t.receipts,t.trusts,
    t.expectedRecipientIds,t.trustedTransferDigest);
  if(!verified.ok)return deny('TRANSFER_'+verified.reason);
  const c=verified.candidate;
  if(b.transferId!==c.transferId||b.transferDigest!==c.transferDigest||
     b.checkpointPosition.count!==c.checkpointPosition.count||
     b.checkpointPosition.head!==c.checkpointPosition.head)
   return deny('TRANSFER_CONTEXT_CONFLICT');
  if(c.checkpointPosition.count<priorPosition.count)
   return deny('CHECKPOINT_ROLLBACK');
  if(priorManifest.some((item,j)=>
    t.bundle.manifest.items[j]?.checkpointHash!==item.checkpointHash||
    t.bundle.manifest.items[j]?.evidenceDigest!==item.evidenceDigest))
   return deny('ORIGINAL_CHECKPOINT_PREFIX_REWRITTEN');
  for(const trust of t.trusts){
   const fp=fingerprint(trust.publicKeyPem);
   if(!fp)return deny('INVALID_RECIPIENT_KEY');
   if(keys.has(trust.recipientId)&&keys.get(trust.recipientId)!==fp)
    return deny('RECIPIENT_KEY_CHANGED');
   if(owners.has(fp)&&owners.get(fp)!==trust.recipientId)
    return deny('RECIPIENT_KEY_REASSIGNED');
   keys.set(trust.recipientId,fp);owners.set(fp,trust.recipientId);
  }
  let computed;
  try{computed=incidentTransferReceiptEntryHash(b,t);}
  catch{return deny('INVALID_RECEIPT_COMMITMENT');}
  if(computed!==entry.hash)return deny('TAMPERED_RECEIPT_ENTRY');
  head=entry.hash;namespace=t.bundle.namespace;ids.add(b.transferId);
  priorPosition=c.checkpointPosition;
  priorManifest=t.bundle.manifest.items.map(x=>({
   checkpointHash:x.checkpointHash,evidenceDigest:x.evidenceDigest
  }));
  results.push(Object.freeze({sequence:i+1,transferId:b.transferId,
   transferDigest:b.transferDigest,checkpointPosition:c.checkpointPosition,
   recipientIds:Object.freeze([...c.recipientIds]),status:'RECEIPT_EVIDENCE_HOLD'}));
 }
 const ancestor=trustedFloor.count===0?genesis.head:records[trustedFloor.count-1].hash;
 if(ancestor!==trustedFloor.head)return deny('TRUSTED_RECEIPT_FORK');
 return Object.freeze({ok:true,phase:'INCIDENT_TRANSFER_RECEIPT_HISTORY_VERIFIED_HOLD',
  reason:'SIGNED_INCIDENT_RECEIPT_LINEAGE_NO_STORAGE_AUTHORITY',authorized:false,
  candidate:Object.freeze({position:Object.freeze({count:records.length,head}),
   receipts:Object.freeze(results)})});
}
/** Full NEO-056 proof validation on both sides prevents forged contradictions. */
export function inspectIncidentArchiveContradiction(left,right,recipientId){
 if(!exact(left,inputKeys)||!exact(right,inputKeys)||!id(recipientId))
  return deny('INVALID_ARCHIVE_CONTRADICTION_INPUT');
 const a=verifyIncidentEvidenceTransfer(left.bundle,left.receipts,left.trusts,
  left.expectedRecipientIds,left.trustedTransferDigest);
 const b=verifyIncidentEvidenceTransfer(right.bundle,right.receipts,right.trusts,
  right.expectedRecipientIds,right.trustedTransferDigest);
 if(!a.ok||!b.ok)return deny('UNVERIFIED_ARCHIVE_TRANSFER');
 if(left.bundle.namespace!==right.bundle.namespace||
    a.candidate.transferId!==b.candidate.transferId)
  return deny('UNRELATED_TRANSFER_CLAIMS');
 const ta=left.trusts.find(x=>x.recipientId===recipientId);
 const tb=right.trusts.find(x=>x.recipientId===recipientId);
 const fa=ta?fingerprint(ta.publicKeyPem):null;
 if(!fa||!tb||fingerprint(tb.publicKeyPem)!==fa||
    !a.candidate.recipientIds.includes(recipientId)||
    !b.candidate.recipientIds.includes(recipientId))
  return deny('UNRELATED_RECIPIENT_KEY');
 const d=[a.candidate.transferDigest,b.candidate.transferDigest];
 if(d[0]===d[1])return Object.freeze({ok:true,phase:'NO_PROVEN_CONFLICT',
  reason:'SAME_SIGNED_TRANSFER',authorized:false,candidate:null});
 d.sort();
 return Object.freeze({ok:true,phase:'INCIDENT_ARCHIVE_CONTRADICTION_HOLD',
  reason:'TWO_CONTRADICTORY_SIGNED_INCIDENT_TRANSFERS',authorized:false,
  candidate:Object.freeze({transferId:a.candidate.transferId,recipientId,
   digests:Object.freeze(d),
   evidenceDigest:sha(['PALACO-NEO-057-ARCHIVE-CONTRADICTION-v1',
    left.bundle.namespace,a.candidate.transferId,recipientId,fa,d])})});
}
export const INITIAL_INCIDENT_TRANSFER_RECEIPT_POSITION=genesis;
