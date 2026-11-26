import {createHash} from 'node:crypto';
import {verifyCASProofLedger,proposeCASProofAppend,INITIAL_CAS_PROOF_POSITION} from './cas-proof-ledger.mjs';

/**
 * NEO-024: verification-only full-receipt archive with externally pinned key snapshot.
 * NO persistence, key custody, trusted clock, authorization, or historical revocation oracle.
 */
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 (Object.getPrototypeOf(x)===Object.prototype||Object.getPrototypeOf(x)===null);
const exact=(x,fields)=>plain(x)&&Object.keys(x).sort().join(',')===[...fields].sort().join(',');
const id=x=>typeof x==='string'&&/^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const hex=x=>typeof x==='string'&&/^[0-9a-f]{64}$/.test(x);
const invalid=reason=>Object.freeze({ok:false,reason,authorized:false,position:null});
const position=x=>exact(x,['count','head'])&&Number.isSafeInteger(x.count)&&
 x.count>=0&&x.count<=10000&&hex(x.head);
const entryShape=x=>exact(x,['id','publicKeyPem','status'])&&id(x.id)&&
 typeof x.publicKeyPem==='string'&&x.publicKeyPem.length>0&&
 x.publicKeyPem.length<=8192&&['ACTIVE','REVOKED'].includes(x.status);
export function custodianKeySnapshotDigest(snapshot) {
 if(!exact(snapshot,['schema','namespace','version','custodians'])||
    snapshot.schema!=='NEO-024-KEYS-v1'||!id(snapshot.namespace)||
    !Number.isSafeInteger(snapshot.version)||snapshot.version<1||
    !Array.isArray(snapshot.custodians)||snapshot.custodians.length<1||
    snapshot.custodians.length>32)throw new TypeError('INVALID_KEY_SNAPSHOT');
 const seen=new Set();
 for(const item of snapshot.custodians) {
  if(!entryShape(item)||seen.has(item.id))throw new TypeError('INVALID_KEY_SNAPSHOT');
  seen.add(item.id);
 }
 const sorted=[...snapshot.custodians].sort((a,b)=>
  a.id<b.id?-1:a.id>b.id?1:0).map(x=>[x.id,x.status,x.publicKeyPem]);
 return createHash('sha256').update(JSON.stringify([
  'PALACO-NEO-CAS-KEY-SNAPSHOT-v1',snapshot.namespace,snapshot.version,sorted
 ])).digest('hex');
}
/** Verify full original signed receipts against externally pinned key history
 * AND the independently authenticated proof chain count/head floor.
 * Each archive item contains exactly {plan,receipt}; no mutable trust payload.
 */
export function verifyCASProofArchive(entries,archive,trustedFloor,keySnapshot,keyPin) {
 if(!Array.isArray(entries)||!Array.isArray(archive)||archive.length!==entries.length||
    archive.length>10000||!position(trustedFloor)||
    !exact(keyPin,['version','digest'])||
    !Number.isSafeInteger(keyPin.version)||keyPin.version<1||!hex(keyPin.digest))
  return invalid('INVALID_ARCHIVE_INPUT');
 let actualPin;
 try{actualPin=custodianKeySnapshotDigest(keySnapshot);}catch{return invalid('INVALID_KEY_SNAPSHOT');}
 if(actualPin!==keyPin.digest||keySnapshot.version!==keyPin.version)
  return invalid('UNTRUSTED_KEY_SNAPSHOT');
 const structural=verifyCASProofLedger(entries,trustedFloor);
 if(!structural.ok)return invalid('LEDGER_'+structural.reason);
 let prefix=[],head=INITIAL_CAS_PROOF_POSITION;
 for(let i=0;i<archive.length;i++){
  const item=archive[i],entry=entries[i];
  if(!exact(item,['plan','receipt'])||!plain(item.receipt)||
     !plain(item.receipt.cas)||!id(item.receipt.custodianId))
    return invalid('INVALID_ARCHIVE_RECORD');
  const signer=keySnapshot.custodians.find(x=>x.id===item.receipt.custodianId);
  if(!signer)return invalid('UNKNOWN_HISTORICAL_CUSTODIAN');
  if(signer.status!=='ACTIVE')return invalid('REVOKED_CUSTODIAN');
  const cas=item.receipt.cas;
  // Verification key snapshot is externally pinned; never accept keys within receipts.
  const trust={namespace:keySnapshot.namespace,custodianId:signer.id,
    status:signer.status,publicKeyPem:signer.publicKeyPem,
    expectedOperationId:cas.operationId,trustedBefore:cas.before};
  const proposal=proposeCASProofAppend(prefix,head,item.plan,item.receipt,trust);
  if(!proposal.ok)return invalid('RECEIPT_'+proposal.reason);
  if(JSON.stringify(proposal.candidate.entry)!==JSON.stringify(entry))
    return invalid('ARCHIVE_PROOF_MISMATCH');
  prefix=[...prefix,entry];head=proposal.candidate.position;
 }
 if(head.count!==structural.position.count||head.head!==structural.position.head)
  return invalid('FINAL_PROOF_MISMATCH');
 return Object.freeze({ok:true,reason:'REVERIFIED_SIGNED_RECEIPTS_NOT_INDEPENDENTLY_AUTHENTICATED',
   authorized:false,position:structural.position});
}
