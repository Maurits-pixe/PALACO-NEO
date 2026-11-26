import {createHash,createPublicKey,verify as edVerify} from 'node:crypto';
import {verifyReceiptIncidentCheckpointHistory} from './cas-receipt-incident-checkpoints.mjs';

/** NEO-061: evidence-only transfer of complete NEO-060 receipt-incident checkpoints. */
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
const deny=reason=>Object.freeze({ok:false,phase:'HOLD',reason,authorized:false,candidate:null});
const bundleFields=['schema','namespace','transferId','trustedCheckpointFloor','records','manifest'];
const manifestFields=['schema','count','checkpointHead','items','contentDigest'];
const itemFields=['sequence','checkpointId','checkpointHash','evidenceDigest'];
const trustFields=['namespace','recipientId','publicKeyPem','status','expectedTransferId'];
const receiptFields=['recipientId','signature'];
function key(pem){
 try{
  if(typeof pem!=='string'||!pem.length||pem.length>8192)return null;
  const k=createPublicKey(pem);return k.asymmetricKeyType==='ed25519'?k:null;
 }catch{return null;}
}
const fingerprint=k=>k.export({type:'spki',format:'der'}).toString('base64');
function manifestValid(m){
 return exact(m,manifestFields)&&m.schema==='NEO-061-INCIDENT-EVIDENCE-MANIFEST-v1'&&
 Number.isSafeInteger(m.count)&&m.count>=1&&m.count<=64&&hex(m.checkpointHead)&&
 Array.isArray(m.items)&&m.items.length===m.count&&
 m.items.every(x=>exact(x,itemFields)&&Number.isSafeInteger(x.sequence)&&
  x.sequence>=1&&x.sequence<=64&&ident(x.checkpointId)&&
  hex(x.checkpointHash)&&hex(x.evidenceDigest))&&hex(m.contentDigest);
}
export function receiptIncidentEvidenceManifest(records){
 if(!Array.isArray(records)||records.length<1||records.length>64)
  throw new TypeError('INVALID_INCIDENT_EVIDENCE_RECORDS');
 const items=records.map((r,i)=>{
  if(!plain(r)||!plain(r.seal)||!plain(r.seal.body)||
     !ident(r.seal.body.checkpointId)||!hex(r.seal.hash))
   throw new TypeError('INVALID_INCIDENT_EVIDENCE_RECORD');
  return {sequence:i+1,checkpointId:r.seal.body.checkpointId,
   checkpointHash:r.seal.hash,
   evidenceDigest:hash(['PALACO-NEO-061-INCIDENT-EVIDENCE-v1',r])};
 });
 return Object.freeze({schema:'NEO-061-INCIDENT-EVIDENCE-MANIFEST-v1',
  count:items.length,checkpointHead:items.at(-1).checkpointHash,
  items,contentDigest:hash(['PALACO-NEO-061-INCIDENT-MANIFEST-v1',items])});
}
const validBundle=b=>exact(b,bundleFields)&&
 b.schema==='NEO-061-INCIDENT-EVIDENCE-TRANSFER-v1'&&
 ident(b.namespace)&&ident(b.transferId)&&position(b.trustedCheckpointFloor)&&
 Array.isArray(b.records)&&manifestValid(b.manifest);
export function receiptIncidentEvidenceTransferDigest(bundle){
 if(!validBundle(bundle))throw new TypeError('INVALID_INCIDENT_TRANSFER_BUNDLE');
 return hash(['PALACO-NEO-061-INCIDENT-TRANSFER-v1',
  bundle.namespace,bundle.transferId,bundle.trustedCheckpointFloor.count,
  bundle.trustedCheckpointFloor.head,bundle.manifest]);
}
export function receiptIncidentEvidenceReceiptPayload(bundle,recipientId){
 if(!validBundle(bundle)||!ident(recipientId))
  throw new TypeError('INVALID_INCIDENT_TRANSFER_RECEIPT');
 return Buffer.from(JSON.stringify(['PALACO-NEO-061-INCIDENT-RECEIPT-v1',
  bundle.namespace,bundle.transferId,receiptIncidentEvidenceTransferDigest(bundle),
  recipientId]),'utf8');
}
/** Verifies full original bytes and all nested NEO-055/054/... proofs;
 * signed archive receipts are declarations, not proof of remote storage.
 */
export function verifyReceiptIncidentEvidenceTransfer(
 bundle,receipts,trusts,expectedRecipientIds,trustedTransferDigest=null
){
 if(!validBundle(bundle)||!Array.isArray(receipts)||!Array.isArray(trusts)||
    !Array.isArray(expectedRecipientIds)||expectedRecipientIds.length<2||
    expectedRecipientIds.length>16||
    receipts.length!==expectedRecipientIds.length||
    trusts.length!==expectedRecipientIds.length||
    expectedRecipientIds.some(x=>!ident(x))||
    new Set(expectedRecipientIds).size!==expectedRecipientIds.length)
  return deny('INVALID_INCIDENT_TRANSFER_INPUT');
 if(bundle.records.length!==bundle.manifest.count)
  return deny('INCOMPLETE_INCIDENT_EVIDENCE');
 let actualManifest;
 try{actualManifest=receiptIncidentEvidenceManifest(bundle.records);}
 catch{return deny('INVALID_ORIGINAL_INCIDENT_EVIDENCE');}
 if(JSON.stringify(actualManifest)!==JSON.stringify(bundle.manifest))
  return deny('INCIDENT_MANIFEST_SUBSTITUTION');
 const verified=verifyReceiptIncidentCheckpointHistory(bundle.records,
   bundle.trustedCheckpointFloor);
 if(!verified.ok)return deny('CHECKPOINT_'+verified.reason);
 if(verified.candidate.position.count!==bundle.manifest.count||
    verified.candidate.position.head!==bundle.manifest.checkpointHead||
    bundle.records.some(r=>r.seal.body.namespace!==bundle.namespace))
  return deny('INCIDENT_EVIDENCE_SCOPE_MISMATCH');
 const digest=receiptIncidentEvidenceTransferDigest(bundle);
 if(trustedTransferDigest!==null&&
    (!hex(trustedTransferDigest)||trustedTransferDigest!==digest))
  return deny('EXTERNAL_INCIDENT_TRANSFER_PIN_CONFLICT');
 const excluded=new Set();
 for(const checkpoint of bundle.records){
  for(const trust of checkpoint.custodianTrust){
   const k=key(trust.publicKeyPem);
   if(!k)return deny('INVALID_CHECKPOINT_CUSTODIAN_TRUST');
   excluded.add(fingerprint(k));
  }
  for(const reviewer of checkpoint.source.policy.reviewers){
   const k=key(reviewer.publicKeyPem);
   if(!k)return deny('INVALID_INCIDENT_REVIEWER_TRUST');
   excluded.add(fingerprint(k));
  }
  for(const incident of checkpoint.source.evidence){
   const k=key(incident.trust?.publicKeyPem);
   if(!k)return deny('INVALID_DISPUTED_CUSTODIAN_TRUST');
   excluded.add(fingerprint(k));
  }
 }
 const roster=new Map(),keys=new Set();
 for(const t of trusts){
  if(!exact(t,trustFields)||!expectedRecipientIds.includes(t.recipientId)||
     roster.has(t.recipientId)||t.namespace!==bundle.namespace||
     t.expectedTransferId!==bundle.transferId||t.status!=='ACTIVE')
   return deny('INVALID_OR_REVOKED_INCIDENT_RECIPIENT');
  const k=key(t.publicKeyPem);
  if(!k)return deny('INVALID_INCIDENT_RECIPIENT_KEY');
  const f=fingerprint(k);
  if(keys.has(f)||excluded.has(f))return deny('NONINDEPENDENT_INCIDENT_RECIPIENT');
  keys.add(f);roster.set(t.recipientId,k);
 }
 const seen=new Set();
 for(const receipt of receipts){
  if(!exact(receipt,receiptFields)||!ident(receipt.recipientId)||
     !signature(receipt.signature)||!roster.has(receipt.recipientId)||
     seen.has(receipt.recipientId))
   return deny('INVALID_OR_DUPLICATE_INCIDENT_RECEIPT');
  if(!edVerify(null,receiptIncidentEvidenceReceiptPayload(bundle,receipt.recipientId),
     roster.get(receipt.recipientId),Buffer.from(receipt.signature,'base64')))
   return deny('FORGED_INCIDENT_ARCHIVE_RECEIPT');
  seen.add(receipt.recipientId);
 }
 if(seen.size!==roster.size)return deny('MISSING_INCIDENT_ARCHIVE_RECEIPT');
 return Object.freeze({ok:true,phase:'INCIDENT_EVIDENCE_TRANSFER_VERIFIED_HOLD',
  reason:'SIGNED_INCIDENT_TRANSFER_DIGESTS_NO_STORAGE_AUTHORITY',authorized:false,
  candidate:Object.freeze({transferId:bundle.transferId,transferDigest:digest,
   checkpointPosition:verified.candidate.position,
   manifestDigest:bundle.manifest.contentDigest,
   recipientIds:Object.freeze([...seen].sort())})});
}
