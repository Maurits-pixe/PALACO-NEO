import {createHash,createPublicKey} from 'node:crypto';
import {verifyCustodianRotation} from './cas-custodian-rotation.mjs';
import {verifyAuditCheckpoint,auditCheckpointHash,INITIAL_AUDIT_CHECKPOINT_POSITION}
 from './cas-audit-checkpoint.mjs';

/** NEO-042 — bounded, verification-only audit-checkpoint succession. */
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 (Object.getPrototypeOf(x)===Object.prototype||Object.getPrototypeOf(x)===null);
const exact=(x,fields)=>plain(x)&&Object.keys(x).sort().join(',')===[...fields].sort().join(',');
const id=x=>typeof x==='string'&&/^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const hex=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const pos=x=>exact(x,['count','head'])&&Number.isSafeInteger(x.count)&&x.count>=0&&x.count<=64&&hex(x.head);
const fail=reason=>Object.freeze({ok:false,phase:'HOLD',reason,authorized:false,candidate:null});
const ok=(phase,reason,candidate)=>Object.freeze({ok:true,phase,reason,authorized:false,candidate});
const itemKeys=['entries','evidence','policy','policyPin','seal','trusts','expectedCustodianIds'];
const hash=x=>createHash('sha256').update(JSON.stringify(x)).digest('hex');
const compare=(a,b)=>a<b?-1:a>b?1:0;
const pub=pem=>{
 try{
  if(typeof pem!=='string'||pem.length===0||pem.length>8192)return null;
  const k=createPublicKey(pem);
  return k.asymmetricKeyType==='ed25519'?
   k.export({type:'spki',format:'der'}).toString('base64'):null;
 }catch{return null;}
};
/** Domain-separated chain link commits the prior history tip and full signed seal. */
export function auditHistoryEntryHash(sequence,previousHash,seal){
 if(!Number.isSafeInteger(sequence)||sequence<1||sequence>64||!hex(previousHash))
  throw new TypeError('INVALID_HISTORY_LINK');
 const sealDigest=auditCheckpointHash(seal);
 return hash(['PALACO-NEO-AUDIT-HISTORY-LINK-v1',sequence,previousHash,sealDigest]);
}
/**
 * Every full NEO-040 journal is reverified by NEO-041 for every checkpoint.
 * This verifier does not retain an external floor; that must be supplied from
 * separately authenticated, monotonic storage on every invocation.
 */
export function verifyAuditCheckpointSuccession(history,trustedHistoryFloor,rotations=[]){
 if(!Array.isArray(history)||history.length>64||!pos(trustedHistoryFloor)||
    !Array.isArray(rotations)||rotations.length>64)
  return fail('INVALID_AUDIT_HISTORY_INPUT');
 if(history.length<trustedHistoryFloor.count)return fail('AUDIT_HISTORY_ROLLBACK');
 let head=INITIAL_AUDIT_CHECKPOINT_POSITION.head;
 let previousJournal=INITIAL_AUDIT_CHECKPOINT_POSITION;
 let namespace=null;
 const checkpointIds=new Set(),custodianKeys=new Map(),keyOwners=new Map();
 const previousPems=new Map(),rotationIds=new Set(),usedRotations=new Set();
 const rotationBySequence=new Map();
 for(const item of rotations){
  if(!exact(item,['atSequence','proof'])||!Number.isSafeInteger(item.atSequence)||
      item.atSequence<2||item.atSequence>history.length||
      !plain(item.proof)||!plain(item.proof.body)||
      !id(item.proof.body.rotationId)||
      rotationIds.has(item.proof.body.rotationId))
   return fail('INVALID_OR_REPLAYED_ROTATION_INPUT');
  const list=rotationBySequence.get(item.atSequence)??[];
  list.push(item.proof);rotationBySequence.set(item.atSequence,list);
  rotationIds.add(item.proof.body.rotationId);
 }
 const snapshots=[];
 for(let i=0;i<history.length;i++){
  const e=history[i];
  if(!exact(e,itemKeys)||!plain(e.seal)||!plain(e.seal.body)||
    !Array.isArray(e.entries)||!Array.isArray(e.evidence)||
    !Array.isArray(e.trusts)||!Array.isArray(e.expectedCustodianIds))
   return fail('INVALID_AUDIT_HISTORY_ENTRY');
  const body=e.seal.body;
  if(!id(body.checkpointId)||checkpointIds.has(body.checkpointId))
   return fail('AUDIT_CHECKPOINT_ID_REPLAY');
  if(namespace!==null&&body.namespace!==namespace)
   return fail('AUDIT_NAMESPACE_CHANGED');
  if(body.anchoredFloor?.count!==previousJournal.count||
     body.anchoredFloor?.head!==previousJournal.head)
   return fail('AUDIT_JOURNAL_ANCESTOR_CONFLICT');
  const verified=verifyAuditCheckpoint(e.entries,e.evidence,e.policy,e.policyPin,
    previousJournal,e.seal,e.trusts,e.expectedCustodianIds);
  if(!verified.ok)return fail('AUDIT_CHECKPOINT_'+verified.reason);
  // Monotonic extension: even if a valid signature refers to the same tip,
  // a later checkpoint cannot pretend a journal changed or shrank.
  if(verified.candidate.position.count<previousJournal.count)
   return fail('AUDIT_JOURNAL_ROLLBACK');
  const pending=rotationBySequence.get(i+1)??[];
  const usedAtSequence=new Set();
  for(const trust of e.trusts){
   const fingerprint=pub(trust.publicKeyPem);
   if(!fingerprint)return fail('INVALID_HISTORICAL_CUSTODIAN_KEY');
   const previous=custodianKeys.get(trust.custodianId);
   if(previous!==undefined&&previous!==fingerprint){
    const matching=pending.filter(p=>p.body?.custodianId===trust.custodianId);
    if(matching.length!==1)return fail('CUSTODIAN_KEY_CHANGED_WITHOUT_ROTATION_PROOF');
    const proof=matching[0],expected={
     namespace:body.namespace,custodianId:trust.custodianId,
     oldKeyPem:previousPems.get(trust.custodianId),
     newKeyPem:trust.publicKeyPem,atSequence:i+1,
     previousHistoryHead:head,checkpointId:body.checkpointId
    };
    if(keyOwners.has(fingerprint))
     return fail('HISTORICAL_CUSTODIAN_KEY_REUSE');
    const checked=verifyCustodianRotation(proof,e.policy,e.policyPin,expected);
    if(!checked.ok)return fail('ROTATION_'+checked.reason);
    usedAtSequence.add(proof.body.rotationId);
    usedRotations.add(proof.body.rotationId);
   }
   const other=keyOwners.get(fingerprint);
   if(other!==undefined&&other!==trust.custodianId)
    return fail('REUSED_KEY_ACROSS_CUSTODIAN_IDENTITIES');
   custodianKeys.set(trust.custodianId,fingerprint);
   previousPems.set(trust.custodianId,trust.publicKeyPem);
   keyOwners.set(fingerprint,trust.custodianId);
  }
  if(usedAtSequence.size!==pending.length)
   return fail('UNCONSUMED_ROTATION_PROOF');
  namespace=body.namespace;
  checkpointIds.add(body.checkpointId);
  previousJournal=verified.candidate.position;
  head=auditHistoryEntryHash(i+1,head,e.seal);
  snapshots.push(Object.freeze({sequence:i+1,head,checkpointId:body.checkpointId,
   journalPosition:Object.freeze({...previousJournal})}));
 }
 if(usedRotations.size!==rotations.length)return fail('UNUSED_ROTATION_EVIDENCE');
 const floorHead=trustedHistoryFloor.count===0?INITIAL_AUDIT_CHECKPOINT_POSITION.head:
  snapshots[trustedHistoryFloor.count-1].head;
 if(floorHead!==trustedHistoryFloor.head)return fail('TRUSTED_AUDIT_HISTORY_FORK');
 return ok('AUDIT_HISTORY_VERIFIED_HOLD','COMPLETE_SIGNED_AUDIT_SUCCESSION_NO_AUTHORITY',
  Object.freeze({position:Object.freeze({count:history.length,head}),
   journalPosition:previousJournal,checkpoints:Object.freeze(snapshots)}));
}
/** A prefix extension is not a fork; divergent valid histories are evidence-only. */
export function inspectAuditHistoryFork(left,right,trustedHistoryFloor){
 const a=verifyAuditCheckpointSuccession(left,trustedHistoryFloor);
 const b=verifyAuditCheckpointSuccession(right,trustedHistoryFloor);
 if(!a.ok||!b.ok)return fail('UNVERIFIED_AUDIT_BRANCH');
 const count=Math.min(left.length,right.length);
 let i=0;
 while(i<count&&a.candidate.checkpoints[i].head===b.candidate.checkpoints[i].head)i++;
 if(i===count)return ok('NO_PROVEN_FORK','COMPATIBLE_AUDIT_PREFIX',null);
 const predecessor=i===0?INITIAL_AUDIT_CHECKPOINT_POSITION.head:
  a.candidate.checkpoints[i-1].head;
 const first=a.candidate.checkpoints[i],second=b.candidate.checkpoints[i];
 return ok('AUDIT_HISTORY_FORK_HOLD','TWO_VALID_CONFLICTING_AUDIT_CHAINS',
  Object.freeze({sequence:i+1,previousHead:predecessor,
   heads:Object.freeze([first.head,second.head].sort(compare)),
   checkpointIds:Object.freeze([first.checkpointId,second.checkpointId].sort(compare))}));
}
export const INITIAL_AUDIT_HISTORY_POSITION=Object.freeze({count:0,head:'0'.repeat(64)});
