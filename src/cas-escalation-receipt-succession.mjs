import {createHash,createPublicKey} from 'node:crypto';
import {verifyEscalationEvidenceTransfer} from './cas-escalation-evidence-transfer.mjs';

/** NEO-052 — complete, read-only receipt succession with signed contradiction evidence. */
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 (Object.getPrototypeOf(x)===Object.prototype||Object.getPrototypeOf(x)===null);
const exact=(x,keys)=>plain(x)&&Object.keys(x).sort().join(',')===[...keys].sort().join(',');
const id=x=>typeof x==='string'&&/^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const hex=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const pos=x=>exact(x,['count','head'])&&Number.isSafeInteger(x.count)&&x.count>=0&&x.count<=64&&hex(x.head);
const hash=x=>createHash('sha256').update(JSON.stringify(x)).digest('hex');
const deny=reason=>Object.freeze({ok:false,phase:'HOLD',reason,authorized:false,candidate:null});
const genesis=Object.freeze({count:0,head:'0'.repeat(64)});
const inputFields=['bundle','receipts','trusts','expectedRecipientIds','pinnedTransferDigest'];
const bodyFields=['schema','sequence','previousHash','transferId','transferDigest','checkpointPosition'];
const entryFields=['body','transfer','hash'];
function fingerprint(pem){
 try{
  if(typeof pem!=='string'||!pem.length||pem.length>8192)return null;
  const k=createPublicKey(pem);
  return k.asymmetricKeyType==='ed25519'?
    k.export({type:'spki',format:'der'}).toString('base64'):null;
 }catch{return null;}
}
function validBody(b){
 return exact(b,bodyFields)&&b.schema==='NEO-052-RECEIPT-SUCCESSION-v1'&&
 Number.isSafeInteger(b.sequence)&&b.sequence>=1&&b.sequence<=64&&
 hex(b.previousHash)&&id(b.transferId)&&hex(b.transferDigest)&&
 pos(b.checkpointPosition)&&b.checkpointPosition.count>=1;
}
export function escalationReceiptSuccessionEntryHash(body,transfer){
 if(!validBody(body)||!exact(transfer,inputFields)||
   !Array.isArray(transfer.receipts)||!Array.isArray(transfer.trusts)||
   !Array.isArray(transfer.expectedRecipientIds))throw new TypeError('INVALID_RECEIPT_SUCCESSION_ENTRY');
 const receipts=transfer.receipts.map(r=>[r.recipientId,r.signature])
  .sort((a,b)=>a[0]<b[0]?-1:a[0]>b[0]?1:0);
 const roster=transfer.trusts.map(t=>{
  const fp=fingerprint(t.publicKeyPem);
  if(fp===null)throw new TypeError('INVALID_RECEIPT_SUCCESSION_ROSTER');
  return [t.namespace,t.recipientId,fp,t.status,t.expectedTransferId];
 }).sort((a,b)=>a[1]<b[1]?-1:a[1]>b[1]?1:0);
 return hash(['PALACO-NEO-RECEIPT-SUCCESSION-v1',body.schema,
  body.sequence,body.previousHash,body.transferId,body.transferDigest,
  body.checkpointPosition.count,body.checkpointPosition.head,
  receipts,roster,[...transfer.expectedRecipientIds].sort()]);
}
/** Every NEO-051 package is reverified from its complete original evidence.
 * A separately authenticated monotonic floor is essential for rollback safety.
 */
export function verifyEscalationReceiptSuccession(records,trustedFloor){
 if(!Array.isArray(records)||records.length>64||!pos(trustedFloor))
  return deny('INVALID_RECEIPT_HISTORY_INPUT');
 if(records.length<trustedFloor.count)return deny('RECEIPT_HISTORY_ROLLBACK');
 const transferIds=new Set(),recipientKeys=new Map(),historicOwners=new Map();
 let namespace=null,head=genesis.head,previousCheckpoint=genesis;
 let priorRecords=null;
 const receipts=[];
 for(let i=0;i<records.length;i++){
  const entry=records[i],b=entry?.body,t=entry?.transfer;
  if(!exact(entry,entryFields)||!validBody(b)||!exact(t,inputFields)||
     !hex(entry.hash)||b.sequence!==i+1||b.previousHash!==head)
   return deny('BROKEN_RECEIPT_SUCCESSION_CHAIN');
  if(transferIds.has(b.transferId))return deny('TRANSFER_ID_REPLAY');
  if(namespace!==null&&namespace!==t.bundle?.namespace)
   return deny('TRANSFER_NAMESPACE_CHANGED');
  const result=verifyEscalationEvidenceTransfer(t.bundle,t.receipts,
    t.trusts,t.expectedRecipientIds,t.pinnedTransferDigest);
  if(!result.ok)return deny('TRANSFER_'+result.reason);
  const candidate=result.candidate;
  if(b.transferId!==candidate.transferId||b.transferDigest!==candidate.transferDigest||
     b.checkpointPosition.count!==candidate.checkpointPosition.count||
     b.checkpointPosition.head!==candidate.checkpointPosition.head)
   return deny('TRANSFER_SUCCESSION_CONTEXT_CONFLICT');
  if(b.checkpointPosition.count<previousCheckpoint.count)
   return deny('TRANSFER_CHECKPOINT_ROLLBACK');
  if(priorRecords!==null&&priorRecords.some((r,index)=>
     t.bundle.records[index]?.seal?.hash!==r.seal.hash||
     false))
   return deny('TRANSFER_CHECKPOINT_HISTORY_REWRITTEN');
  // Compare original evidence commitment as well as signed checkpoint headers.
  if(priorRecords!==null&&priorRecords.some((r,index)=>
    t.bundle.manifest.items[index]?.evidenceDigest!==r.evidenceDigest))
   return deny('TRANSFER_EVIDENCE_HISTORY_REWRITTEN');
  for(const trust of t.trusts){
   const fp=fingerprint(trust.publicKeyPem);
   if(fp===null)return deny('INVALID_HISTORICAL_RECIPIENT_KEY');
   const old=recipientKeys.get(trust.recipientId);
   if(old!==undefined&&old!==fp)return deny('RECIPIENT_KEY_CHANGED_WITHOUT_PROOF');
   const owner=historicOwners.get(fp);
   if(owner!==undefined&&owner!==trust.recipientId)
    return deny('RECIPIENT_KEY_REASSIGNED');
   recipientKeys.set(trust.recipientId,fp);
   historicOwners.set(fp,trust.recipientId);
  }
  let digest;
  try{digest=escalationReceiptSuccessionEntryHash(b,t);}
  catch{return deny('INVALID_RECEIPT_COMMITMENT');}
  if(digest!==entry.hash)return deny('TAMPERED_RECEIPT_SUCCESSION_ENTRY');
  head=entry.hash;namespace=t.bundle.namespace;transferIds.add(b.transferId);
  previousCheckpoint=candidate.checkpointPosition;
  priorRecords=t.bundle.manifest.items.map(x=>({
   seal:{hash:x.checkpointHash},evidenceDigest:x.evidenceDigest
  }));
  receipts.push(Object.freeze({sequence:i+1,transferId:b.transferId,
   transferDigest:b.transferDigest,recipientIds:Object.freeze([...candidate.recipientIds]),
   checkpointPosition:candidate.checkpointPosition,status:'RECEIPT_EVIDENCE_HOLD'}));
 }
 const anchored=trustedFloor.count===0?genesis.head:
  records[trustedFloor.count-1].hash;
 if(anchored!==trustedFloor.head)return deny('TRUSTED_RECEIPT_HISTORY_FORK');
 return Object.freeze({ok:true,phase:'RECEIPT_SUCCESSION_VERIFIED_HOLD',
  reason:'SIGNED_RECEIPT_LINEAGE_NO_PHYSICAL_CUSTODY',authorized:false,
  candidate:Object.freeze({position:Object.freeze({count:records.length,head}),
   receipts:Object.freeze(receipts)})});
}
/** Complete separate NEO-051 verifications, same transfer ID + same signing
 * key, differing transfer digests => contradictory signed archive assertions.
 */
export function inspectArchiveRecipientContradiction(left,right,recipientId){
 if(!exact(left,inputFields)||!exact(right,inputFields)||!id(recipientId))
  return deny('INVALID_ARCHIVE_CONFLICT_INPUT');
 const a=verifyEscalationEvidenceTransfer(left.bundle,left.receipts,
  left.trusts,left.expectedRecipientIds,left.pinnedTransferDigest);
 const b=verifyEscalationEvidenceTransfer(right.bundle,right.receipts,
  right.trusts,right.expectedRecipientIds,right.pinnedTransferDigest);
 if(!a.ok||!b.ok)return deny('UNVERIFIED_ARCHIVE_TRANSFER');
 if(left.bundle.namespace!==right.bundle.namespace||
    a.candidate.transferId!==b.candidate.transferId)
  return deny('UNRELATED_TRANSFER_STATEMENTS');
 const la=left.trusts.find(x=>x.recipientId===recipientId);
 const rb=right.trusts.find(x=>x.recipientId===recipientId);
 const fp=la?fingerprint(la.publicKeyPem):null;
 if(!fp||!rb||fingerprint(rb.publicKeyPem)!==fp||
    !a.candidate.recipientIds.includes(recipientId)||
    !b.candidate.recipientIds.includes(recipientId))
  return deny('UNRELATED_ARCHIVE_SIGNER');
 if(a.candidate.transferDigest===b.candidate.transferDigest)
  return Object.freeze({ok:true,phase:'NO_PROVEN_CONFLICT',
   reason:'IDENTICAL_SIGNED_TRANSFER',authorized:false,candidate:null});
 const digests=[a.candidate.transferDigest,b.candidate.transferDigest].sort();
 return Object.freeze({ok:true,phase:'ARCHIVE_RECIPIENT_CONTRADICTION_HOLD',
  reason:'TWO_SIGNED_INCOMPATIBLE_TRANSFER_DIGESTS',authorized:false,
  candidate:Object.freeze({transferId:a.candidate.transferId,recipientId,
   digests:Object.freeze(digests),
   evidenceDigest:hash(['PALACO-NEO-ARCHIVE-RECEIPT-CONTRADICTION-v1',
    left.bundle.namespace,a.candidate.transferId,recipientId,fp,digests])})});
}
export const INITIAL_RECEIPT_SUCCESSION_POSITION=genesis;
