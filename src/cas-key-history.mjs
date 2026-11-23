import {createHash,createPublicKey} from 'node:crypto';
import {verifyCASProofLedger,proposeCASProofAppend,INITIAL_CAS_PROOF_POSITION} from './cas-proof-ledger.mjs';

/**
 * NEO-025: revision-scoped custodian key epochs and historical CAS verification.
 * Revision is an authenticated external anchor sequence, NOT wall-clock time.
 * No key issuance, custody, clocks, signing or authorization.
 */
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
  (Object.getPrototypeOf(x)===Object.prototype||Object.getPrototypeOf(x)===null);
const exact=(x,fields)=>plain(x)&&Object.keys(x).sort().join(',')===[...fields].sort().join(',');
const hex=x=>typeof x==='string'&&/^[0-9a-f]{64}$/.test(x);
const id=x=>typeof x==='string'&&/^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const revision=x=>Number.isSafeInteger(x)&&x>=1;
const position=x=>exact(x,['count','head'])&&Number.isSafeInteger(x.count)&&
  x.count>=0&&x.count<=10000&&hex(x.head);
const reject=reason=>Object.freeze({ok:false,reason,authorized:false,candidate:null});
const good=(reason,position)=>Object.freeze({ok:true,reason,authorized:false,
  position:Object.freeze({...position})});
const epochShape=e=>exact(e,['custodianId','publicKeyPem','fromRevision','untilRevision','status'])&&
  id(e.custodianId)&&typeof e.publicKeyPem==='string'&&e.publicKeyPem.length<=8192&&
  e.publicKeyPem.length>0&&revision(e.fromRevision)&&
  (e.untilRevision===null||(revision(e.untilRevision)&&e.untilRevision>e.fromRevision))&&
  ['TRUSTED','COMPROMISED'].includes(e.status);
function validPublicKey(pem) {
  try {return createPublicKey(pem).asymmetricKeyType==='ed25519';}
  catch{return false;}
}
function validateHistory(history) {
  if(!exact(history,['schema','namespace','version','epochs'])||
    history.schema!=='NEO-025-KEY-HISTORY-v1'||!id(history.namespace)||
    !revision(history.version)||!Array.isArray(history.epochs)||
    history.epochs.length<1||history.epochs.length>256)
    throw new TypeError('INVALID_KEY_HISTORY');
  const groups=new Map();
  for(const epoch of history.epochs) {
    if(!epochShape(epoch)||!validPublicKey(epoch.publicKeyPem))
      throw new TypeError('INVALID_KEY_EPOCH');
    const group=groups.get(epoch.custodianId)||[];
    group.push(epoch);groups.set(epoch.custodianId,group);
  }
  for(const records of groups.values()) {
    records.sort((a,b)=>a.fromRevision-b.fromRevision);
    for(let i=1;i<records.length;i++){
      const a=records[i-1],b=records[i];
      if(a.untilRevision===null||a.untilRevision>b.fromRevision)
        throw new TypeError('OVERLAPPING_KEY_EPOCHS');
    }
  }
  return history.epochs.map(e=>[
    e.custodianId,e.fromRevision,e.untilRevision,e.status,e.publicKeyPem
  ]).sort((a,b)=>a[0]<b[0]?-1:a[0]>b[0]?1:a[1]-b[1]);
}
export function custodianKeyHistoryDigest(history) {
  const canonical=validateHistory(history);
  return createHash('sha256').update(JSON.stringify([
    'PALACO-NEO-CUSTODIAN-KEY-HISTORY-v1',history.namespace,history.version,canonical
  ])).digest('hex');
}
/** Proposed rotation with exclusive cutover revision. No keys are generated.
 * Source key must be open-ended, trusted and its start precedes cutover.
 * Older receipts continue to use the older key under the pinned epochs.
 */
export function proposeCustodianKeyRotation(history,pin,request) {
  let digest;
  try{digest=custodianKeyHistoryDigest(history);}catch{return reject('INVALID_HISTORY');}
  if(!exact(pin,['version','digest'])||!revision(pin.version)||!hex(pin.digest)||
    pin.version!==history.version||pin.digest!==digest)return reject('UNTRUSTED_HISTORY_PIN');
  if(!exact(request,['custodianId','cutoverRevision','successorPublicKeyPem'])||
    !id(request.custodianId)||!revision(request.cutoverRevision)||
    !validPublicKey(request.successorPublicKeyPem)||
    request.successorPublicKeyPem.length>8192)return reject('INVALID_ROTATION');
  const open=history.epochs.filter(e=>e.custodianId===request.custodianId&&e.untilRevision===null);
  if(open.length!==1||open[0].status!=='TRUSTED'||
    request.cutoverRevision<=open[0].fromRevision||
    request.successorPublicKeyPem===open[0].publicKeyPem)
    return reject('INVALID_CUTOVER');
  if(history.version===Number.MAX_SAFE_INTEGER||history.epochs.length>=256)
    return reject('HISTORY_CAPACITY');
  const epochs=history.epochs.map(e=>e===open[0]?
    {...e,untilRevision:request.cutoverRevision}:{...e});
  epochs.push({custodianId:request.custodianId,
    publicKeyPem:request.successorPublicKeyPem,fromRevision:request.cutoverRevision,
    untilRevision:null,status:'TRUSTED'});
  const candidate=Object.freeze({schema:'NEO-025-KEY-HISTORY-v1',
    namespace:history.namespace,version:history.version+1,
    epochs:Object.freeze(epochs.map(e=>Object.freeze(e)))});
  return Object.freeze({ok:true,reason:'KEY_ROTATION_PROPOSAL_ONLY',authorized:false,
    candidate:Object.freeze({history:candidate,digest:custodianKeyHistoryDigest(candidate)})});
}
/** Reverify each signed original receipt with the unique trusted epoch selected
 * by CAS BEFORE revision. A compromised epoch is denied even for past records.
 */
export function verifyHistoricalCASArchive(entries,archive,trustedFloor,history,pin) {
  if(!Array.isArray(entries)||!Array.isArray(archive)||archive.length!==entries.length||
    archive.length>10000||!position(trustedFloor)||
    !exact(pin,['version','digest'])||!revision(pin.version)||!hex(pin.digest))
    return reject('INVALID_ARCHIVE_INPUT');
  let digest;
  try{digest=custodianKeyHistoryDigest(history);}catch{return reject('INVALID_HISTORY');}
  if(pin.version!==history.version||pin.digest!==digest)
    return reject('UNTRUSTED_HISTORY_PIN');
  const chain=verifyCASProofLedger(entries,trustedFloor);
  if(!chain.ok)return reject('LEDGER_'+chain.reason);
  let prefix=[],head=INITIAL_CAS_PROOF_POSITION;
  for(let i=0;i<archive.length;i++) {
    const item=archive[i],entry=entries[i];
    if(!exact(item,['plan','receipt'])||!plain(item.receipt)||
      !plain(item.receipt.cas)||!id(item.receipt.custodianId))
      return reject('INVALID_ARCHIVE_RECORD');
    const cas=item.receipt.cas;
    if(!revision(cas.before?.revision)||cas.namespace!==history.namespace)
      return reject('INVALID_RECEIPT_REVISION');
    const matches=history.epochs.filter(e=>e.custodianId===item.receipt.custodianId&&
      e.fromRevision<=cas.before.revision&&
      (e.untilRevision===null||cas.before.revision<e.untilRevision));
    if(matches.length!==1)return reject('NO_UNIQUE_TRUSTED_KEY_EPOCH');
    const epoch=matches[0];
    if(epoch.status!=='TRUSTED')return reject('COMPROMISED_KEY_EPOCH');
    const trust={namespace:history.namespace,custodianId:epoch.custodianId,
      publicKeyPem:epoch.publicKeyPem,status:'ACTIVE',
      expectedOperationId:cas.operationId,trustedBefore:cas.before};
    const result=proposeCASProofAppend(prefix,head,item.plan,item.receipt,trust);
    if(!result.ok)return reject('RECEIPT_'+result.reason);
    if(JSON.stringify(result.candidate.entry)!==JSON.stringify(entry))
      return reject('ARCHIVE_ENTRY_MISMATCH');
    prefix.push(entry);head=result.candidate.position;
  }
  if(head.count!==chain.position.count||head.head!==chain.position.head)
    return reject('FINAL_PROOF_MISMATCH');
  return good('REVISION_SCOPED_SIGNATURES_VERIFIED_NO_AUTHORITY',chain.position);
}
