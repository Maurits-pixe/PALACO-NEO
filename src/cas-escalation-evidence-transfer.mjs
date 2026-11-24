import {createHash,createPublicKey,verify as edVerify} from 'node:crypto';
import {verifyEscalationCheckpointHistory} from './cas-escalation-checkpoints.mjs';

/** NEO-051: complete evidence handoff and signed archive receipts. Verify-only. */
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 (Object.getPrototypeOf(x)===Object.prototype||Object.getPrototypeOf(x)===null);
const exact=(x,keys)=>plain(x)&&Object.keys(x).sort().join(',')===[...keys].sort().join(',');
const id=x=>typeof x==='string'&&/^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const hex=x=>typeof x==='string'&&/^[0-9a-f]{64}$/.test(x);
const b64=x=>typeof x==='string'&&/^[A-Za-z0-9+/]{86}==$/.test(x)&&
 Buffer.from(x,'base64').toString('base64')===x;
const pos=x=>exact(x,['count','head'])&&Number.isSafeInteger(x.count)&&x.count>=1&&x.count<=64&&hex(x.head);
const fail=reason=>Object.freeze({ok:false,phase:'HOLD',reason,authorized:false,candidate:null});
const sha=x=>createHash('sha256').update(JSON.stringify(x)).digest('hex');
const bundleFields=['schema','namespace','transferId','trustedCheckpointFloor','records','manifest'];
const manifestFields=['schema','count','checkpointHead','items','contentDigest'];
const itemFields=['sequence','checkpointId','checkpointHash','evidenceDigest'];
const receiptFields=['recipientId','signature'];
const trustFields=['namespace','recipientId','publicKeyPem','status','expectedTransferId'];
function key(pem){
 try{
  if(typeof pem!=='string'||!pem.length||pem.length>8192)return null;
  const k=createPublicKey(pem);
  return k.asymmetricKeyType==='ed25519'?k:null;
 }catch{return null;}
}
const fingerprint=k=>k.export({type:'spki',format:'der'}).toString('base64');
function manifestValid(m){
 return exact(m,manifestFields)&&m.schema==='NEO-051-EVIDENCE-MANIFEST-v1'&&
 Number.isSafeInteger(m.count)&&m.count>=1&&m.count<=64&&hex(m.checkpointHead)&&
 Array.isArray(m.items)&&m.items.length===m.count&&
 m.items.every(x=>exact(x,itemFields)&&Number.isSafeInteger(x.sequence)&&
  x.sequence>=1&&x.sequence<=64&&id(x.checkpointId)&&
  hex(x.checkpointHash)&&hex(x.evidenceDigest))&&hex(m.contentDigest);
}
function entriesOf(records){
 if(!Array.isArray(records)||records.length<1||records.length>64)
  throw new TypeError('INVALID_EVIDENCE_RECORDS');
 return records.map((record,i)=>{
  if(!plain(record)||!plain(record.seal)||!plain(record.seal.body)||
     !id(record.seal.body.checkpointId)||!hex(record.seal.hash))
   throw new TypeError('INVALID_EVIDENCE_RECORD');
  return {sequence:i+1,checkpointId:record.seal.body.checkpointId,
   checkpointHash:record.seal.hash,
   evidenceDigest:sha(['PALACO-NEO-051-ORIGINAL-EVIDENCE-v1',record])};
 });
}
/** Manifest generation is deterministic; it makes no assertion of validity. */
export function escalationEvidenceManifest(records){
 const items=entriesOf(records);
 return Object.freeze({schema:'NEO-051-EVIDENCE-MANIFEST-v1',
  count:items.length,checkpointHead:items.at(-1).checkpointHash,
  items,contentDigest:sha(['PALACO-NEO-051-EVIDENCE-MANIFEST-v1',items])});
}
function validBundle(b){
 return exact(b,bundleFields)&&b.schema==='NEO-051-ESCALATION-EVIDENCE-BUNDLE-v1'&&
 id(b.namespace)&&id(b.transferId)&&pos(b.trustedCheckpointFloor)&&
 Array.isArray(b.records)&&manifestValid(b.manifest);
}
export function escalationEvidenceTransferDigest(bundle){
 if(!validBundle(bundle))throw new TypeError('INVALID_ESCALATION_EVIDENCE_BUNDLE');
 return sha(['PALACO-NEO-051-ESCALATION-EVIDENCE-TRANSFER-v1',
  bundle.namespace,bundle.transferId,bundle.trustedCheckpointFloor.count,
  bundle.trustedCheckpointFloor.head,bundle.manifest]);
}
export function escalationEvidenceReceiptPayload(bundle,recipientId){
 if(!validBundle(bundle)||!id(recipientId))
  throw new TypeError('INVALID_ESCALATION_RECEIPT');
 return Buffer.from(JSON.stringify([
  'PALACO-NEO-051-ARCHIVE-RECEIPT-v1',
  bundle.namespace,bundle.transferId,
  escalationEvidenceTransferDigest(bundle),recipientId
 ]),'utf8');
}
/** Receipt is a signed assertion of a named digest, not proof of physical
 * custody. Original evidence must reverify independently of the signatures.
 */
export function verifyEscalationEvidenceTransfer(
 bundle,receipts,trusts,expectedRecipientIds,pinnedTransferDigest=null
){
 if(!validBundle(bundle)||!Array.isArray(receipts)||!Array.isArray(trusts)||
    !Array.isArray(expectedRecipientIds)||expectedRecipientIds.length<2||
    expectedRecipientIds.length>16||
    receipts.length!==expectedRecipientIds.length||
    trusts.length!==expectedRecipientIds.length||
    expectedRecipientIds.some(x=>!id(x))||
    new Set(expectedRecipientIds).size!==expectedRecipientIds.length)
  return fail('INVALID_TRANSFER_INPUT');
 if(bundle.records.length!==bundle.manifest.count)
  return fail('MISSING_OR_EXTRA_EVIDENCE_RECORDS');
 let expected;
 try{expected=escalationEvidenceManifest(bundle.records);}
 catch{return fail('INVALID_SOURCE_EVIDENCE');}
 if(JSON.stringify(expected)!==JSON.stringify(bundle.manifest))
  return fail('MANIFEST_OR_EVIDENCE_SUBSTITUTED');
 if(bundle.manifest.checkpointHead!==
    bundle.records[bundle.records.length-1].seal.hash)
  return fail('MANIFEST_CHECKPOINT_MISMATCH');
 const history=verifyEscalationCheckpointHistory(bundle.records,
  bundle.trustedCheckpointFloor);
 if(!history.ok)return fail('CHECKPOINT_'+history.reason);
 if(history.candidate.position.count!==bundle.manifest.count||
    history.candidate.position.head!==bundle.manifest.checkpointHead||
    bundle.records.some(r=>r.seal.body.namespace!==bundle.namespace))
  return fail('EVIDENCE_CHECKPOINT_CONTEXT_CONFLICT');
 const digest=escalationEvidenceTransferDigest(bundle);
 if(pinnedTransferDigest!==null&&
    (!hex(pinnedTransferDigest)||pinnedTransferDigest!==digest))
  return fail('EXTERNAL_TRANSFER_PIN_CONFLICT');
 const excluded=new Set();
 for(const item of bundle.records){
  for(const t of item.custodianTrust){
   const k=key(t.publicKeyPem);
   if(!k)return fail('INVALID_SOURCE_CUSTODIAN_KEY');
   excluded.add(fingerprint(k));
  }
  for(const r of item.source.policy.reviewers){
   const k=key(r.publicKeyPem);
   if(!k)return fail('INVALID_SOURCE_REVIEWER_KEY');
   excluded.add(fingerprint(k));
  }
 }
 const roster=new Map(),usedKeys=new Set();
 for(const t of trusts){
  if(!exact(t,trustFields)||!expectedRecipientIds.includes(t.recipientId)||
     roster.has(t.recipientId)||t.namespace!==bundle.namespace||
     t.expectedTransferId!==bundle.transferId||t.status!=='ACTIVE')
   return fail('INVALID_OR_REVOKED_RECIPIENT');
  const k=key(t.publicKeyPem);
  if(!k)return fail('INVALID_RECIPIENT_KEY');
  const f=fingerprint(k);
  if(usedKeys.has(f)||excluded.has(f))
   return fail('NONINDEPENDENT_RECIPIENT_KEY');
  roster.set(t.recipientId,k);usedKeys.add(f);
 }
 const seen=new Set();
 for(const receipt of receipts){
  if(!exact(receipt,receiptFields)||!id(receipt.recipientId)||
     !b64(receipt.signature)||seen.has(receipt.recipientId)||
     !roster.has(receipt.recipientId))
   return fail('INVALID_OR_DUPLICATE_RECEIPT');
  const k=roster.get(receipt.recipientId);
  if(!edVerify(null,escalationEvidenceReceiptPayload(bundle,
     receipt.recipientId),k,Buffer.from(receipt.signature,'base64')))
   return fail('INVALID_ARCHIVE_RECEIPT_SIGNATURE');
  seen.add(receipt.recipientId);
 }
 if(seen.size!==roster.size)return fail('MISSING_ARCHIVE_RECEIPT');
 return Object.freeze({ok:true,phase:'ESCALATION_EVIDENCE_TRANSFER_VERIFIED_HOLD',
  reason:'SIGNED_DIGEST_RECEIPTS_NO_PROOF_OF_STORAGE',authorized:false,
  candidate:Object.freeze({
   transferId:bundle.transferId,
   transferDigest:digest,
   checkpointPosition:history.candidate.position,
   recipientIds:Object.freeze([...seen].sort()),
   manifestDigest:bundle.manifest.contentDigest
  })});
}
