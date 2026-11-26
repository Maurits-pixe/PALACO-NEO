import {createHash,createPublicKey,verify as edVerify} from 'node:crypto';
import {verifyCaseHandoff} from './cas-case-custody.mjs';

/**
 * NEO-035: offline, bounded transfer lineage + byte inventory verification.
 * Signatures attest possession of keys; no physical persistence or authority.
 */
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 (Object.getPrototypeOf(x)===Object.prototype||Object.getPrototypeOf(x)===null);
const exact=(x,fields)=>plain(x)&&Object.keys(x).sort().join(',')===[...fields].sort().join(',');
const id=x=>typeof x==='string'&&/^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const hex=x=>typeof x==='string'&&/^[0-9a-f]{64}$/.test(x);
const position=x=>exact(x,['count','head'])&&Number.isSafeInteger(x.count)&&
 x.count>=0&&x.count<=64&&hex(x.head);
const deny=reason=>Object.freeze({ok:false,phase:'HOLD',reason,authorized:false,candidate:null});
const HEAD='0'.repeat(64);
const manifestShape=x=>exact(x,['schema','caseId','artifacts'])&&
 x.schema==='NEO-035-INVENTORY-v1'&&id(x.caseId)&&
 Array.isArray(x.artifacts)&&x.artifacts.length>0&&x.artifacts.length<=64;
const itemShape=x=>exact(x,['artifactId','sha256','byteLength'])&&
 id(x.artifactId)&&hex(x.sha256)&&Number.isSafeInteger(x.byteLength)&&
 x.byteLength>=0&&x.byteLength<=1048576;
const receiptShape=x=>exact(x,['custodianId','outcome','signature'])&&
 id(x.custodianId)&&['OBSERVED','REJECTED'].includes(x.outcome);
const stepShape=x=>exact(x,['handoff','destinationTrust','manifest','artifacts','storageReceipt']);
const hash=x=>createHash('sha256').update(x).digest('hex');
const canonical=items=>[...items].sort((a,b)=>a.artifactId<b.artifactId?-1:a.artifactId>b.artifactId?1:0);
function inventory(manifest,artifacts){
 if(!manifestShape(manifest)||!Array.isArray(artifacts)||
    artifacts.length!==manifest.artifacts.length)return null;
 const ids=new Set(),received=new Map();
 for(const item of manifest.artifacts){
  if(!itemShape(item)||ids.has(item.artifactId))return null;
  ids.add(item.artifactId);
 }
 for(const item of artifacts){
  if(!exact(item,['artifactId','base64'])||!id(item.artifactId)||
     !ids.has(item.artifactId)||received.has(item.artifactId)||
     typeof item.base64!=='string'||item.base64.length>1398112||
     !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(item.base64))
    return null;
  received.set(item.artifactId,item.base64);
 }
 for(const item of manifest.artifacts){
  const encoded=received.get(item.artifactId);
  if(encoded===undefined)return null;
  const bytes=Buffer.from(encoded,'base64');
  if(bytes.toString('base64')!==encoded||bytes.length!==item.byteLength||
     hash(bytes)!==item.sha256)return null;
 }
 return canonical(manifest.artifacts).map(i=>[i.artifactId,i.sha256,i.byteLength]);
}
export function transferInventoryDigest(manifest){
 if(!manifestShape(manifest))throw new TypeError('INVALID_INVENTORY');
 const seen=new Set();
 for(const item of manifest.artifacts){
  if(!itemShape(item)||seen.has(item.artifactId))
    throw new TypeError('INVALID_INVENTORY');
  seen.add(item.artifactId);
 }
 return hash(JSON.stringify(['PALACO-NEO-TRANSFER-INVENTORY-v1',
  manifest.caseId,canonical(manifest.artifacts).map(i=>[
   i.artifactId,i.sha256,i.byteLength])]));
}
export function transferStoragePayload(body,custodianId,outcome){
 if(!exact(body,['namespace','caseId','transferId','handoffDigest',
    'inventoryDigest','previousHash'])||!id(body.namespace)||!id(body.caseId)||
    !id(body.transferId)||!hex(body.handoffDigest)||!hex(body.inventoryDigest)||
    !hex(body.previousHash)||!id(custodianId)||
    !['OBSERVED','REJECTED'].includes(outcome))
   throw new TypeError('INVALID_TRANSFER_STORAGE_PAYLOAD');
 return Buffer.from(JSON.stringify(['PALACO-NEO-TRANSFER-STORAGE-v1',
  body.namespace,body.caseId,body.transferId,body.handoffDigest,
  body.inventoryDigest,body.previousHash,custodianId,outcome]),'utf8');
}
function verifyStorage(receipt,trust,body){
 if(!receiptShape(receipt)||receipt.outcome!=='OBSERVED'||
    !plain(trust)||trust.custodianId!==receipt.custodianId||
    trust.status!=='ACTIVE'||typeof trust.publicKeyPem!=='string'||
    typeof receipt.signature!=='string'||
    !/^[A-Za-z0-9+/]{86}==$/.test(receipt.signature))return false;
 try{
  const key=createPublicKey(trust.publicKeyPem);
  const bytes=Buffer.from(receipt.signature,'base64');
  return key.asymmetricKeyType==='ed25519'&&bytes.length===64&&
   bytes.toString('base64')===receipt.signature&&
   edVerify(null,transferStoragePayload(body,receipt.custodianId,'OBSERVED'),key,bytes);
 }catch{return false;}
}
function entryDigest(sequence,body,receipt){
 return hash(JSON.stringify(['PALACO-NEO-CUSTODY-LINEAGE-v1',sequence,
  body.namespace,body.caseId,body.transferId,body.handoffDigest,
  body.inventoryDigest,body.previousHash,receipt.custodianId,
  receipt.outcome,receipt.signature]));
}
/**
 * A full signed NEO-034 handoff must be checked afresh for EVERY transfer.
 * Each transfer includes all artifact bytes, plus destination's independently
 * pinned signed observation binding those bytes to the handoff and prior tip.
 */
export function verifyCustodyLineage(entries,caseEvidence,policy,policyPin,
 trustedJournalFloor,steps,initialCustodian,trustedLineageFloor){
 if(!Array.isArray(steps)||steps.length>64||!id(initialCustodian)||
    !position(trustedLineageFloor))return deny('INVALID_LINEAGE_INPUT');
 let head=HEAD,source=initialCustodian,caseId=null,inventoryDigest=null;
 const usedIds=new Set();
 const resultEntries=[];
 for(let i=0;i<steps.length;i++){
  const step=steps[i];
  if(!stepShape(step)||!plain(step.handoff)||!plain(step.handoff.body))
   return deny('INVALID_TRANSFER_RECORD');
  const b=step.handoff.body;
  if(b.fromCustodian!==source)return deny('NONCONTIGUOUS_CUSTODIAN_LINEAGE');
  if(caseId!==null&&b.caseId!==caseId)return deny('CROSS_CASE_TRANSFER');
  if(usedIds.has(b.transferId))return deny('TRANSFER_ID_REPLAY');
  const verified=verifyCaseHandoff(entries,caseEvidence,policy,policyPin,
    trustedJournalFloor,step.handoff,step.destinationTrust);
  if(!verified.ok)return deny('HANDOFF_'+verified.reason);
  if(!manifestShape(step.manifest)||step.manifest.caseId!==b.caseId)
   return deny('INVALID_MANIFEST_CASE');
  const checked=inventory(step.manifest,step.artifacts);
  if(checked===null)return deny('MISSING_OR_TAMPERED_ARTIFACTS');
  const digest=transferInventoryDigest(step.manifest);
  if(inventoryDigest!==null&&digest!==inventoryDigest)
   return deny('INVENTORY_CHANGED_WITHOUT_AUTHORIZED_PROCEDURE');
  const body={namespace:b.namespace,caseId:b.caseId,transferId:b.transferId,
   handoffDigest:verified.candidate.evidenceDigest,
   inventoryDigest:digest,previousHash:head};
  if(step.storageReceipt===null)return deny('DESTINATION_STORAGE_NOT_CONFIRMED');
  if(!verifyStorage(step.storageReceipt,step.destinationTrust,body))
   return deny('INVALID_DESTINATION_STORAGE_ATTESTATION');
  head=entryDigest(i+1,body,step.storageReceipt);
  resultEntries.push(Object.freeze({sequence:i+1,transferId:b.transferId,
   custodianId:b.toCustodian,inventoryDigest:digest,hash:head}));
  source=b.toCustodian;caseId=b.caseId;inventoryDigest=digest;
  usedIds.add(b.transferId);
 }
 if(steps.length<trustedLineageFloor.count)return deny('LINEAGE_ROLLBACK');
 const floorHash=trustedLineageFloor.count===0?HEAD:
   resultEntries[trustedLineageFloor.count-1].hash;
 if(floorHash!==trustedLineageFloor.head)return deny('LINEAGE_FORK');
 return Object.freeze({ok:true,phase:'VERIFIED_ASSERTIONS_ONLY',
  reason:'SIGNED_CUSTODY_LINEAGE_NO_DURABILITY_PROOF',authorized:false,
  candidate:Object.freeze({position:Object.freeze({count:steps.length,head}),
   caseId,custodianId:source,inventoryDigest,entries:Object.freeze(resultEntries)})});
}
export const INITIAL_CUSTODY_LINEAGE_POSITION=Object.freeze({count:0,head:HEAD});
