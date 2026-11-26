import {createHash,createPublicKey,verify as edVerify} from 'node:crypto';
import {verifyEmergencyResponsibilityHandoffs} from './cas-responsibility-handoff.mjs';
import {keyQuorumPolicyDigest} from './cas-key-quorum.mjs';

/** NEO-048: signed checkpoint succession over fully reverified handoff evidence. */
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 (Object.getPrototypeOf(x)===Object.prototype||Object.getPrototypeOf(x)===null);
const exact=(x,keys)=>plain(x)&&Object.keys(x).sort().join(',')===[...keys].sort().join(',');
const id=x=>typeof x==='string'&&/^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const hex=x=>typeof x==='string'&&/^[0-9a-f]{64}$/.test(x);
const sig=x=>typeof x==='string'&&/^[A-Za-z0-9+/]{86}==$/.test(x)&&
 Buffer.from(x,'base64').toString('base64')===x;
const pos=x=>exact(x,['count','head'])&&Number.isSafeInteger(x.count)&&
 x.count>=0&&x.count<=64&&hex(x.head);
const deny=reason=>Object.freeze({ok:false,phase:'HOLD',reason,authorized:false,candidate:null});
const accepted=(phase,reason,candidate)=>Object.freeze({ok:true,phase,reason,authorized:false,candidate});
const SHA=x=>createHash('sha256').update(JSON.stringify(x)).digest('hex');
const INITIAL=Object.freeze({count:0,head:'0'.repeat(64)});
const bodyFields=['schema','namespace','checkpointId','sequence','previousHash',
 'handoffPosition','quarantinePosition','policyDigest'];
const recordFields=['source','seal','witnessTrust','expectedWitnessIds'];
const sealFields=['body','witnesses','hash'];
const witnessFields=['witnessId','signature'];
const trustFields=['namespace','witnessId','publicKeyPem','status','expectedCheckpointId'];
const sourceFields=['history','rotations','historyFloor','lifecyclePin',
 'quarantines','policy','policyPin','trustedQuarantineFloor',
 'handoffs','trustedHandoffFloor'];
const validBody=b=>exact(b,bodyFields)&&b.schema==='NEO-048-HANDOFF-CHECKPOINT-v1'&&
 id(b.namespace)&&id(b.checkpointId)&&
 Number.isSafeInteger(b.sequence)&&b.sequence>=1&&b.sequence<=64&&
 hex(b.previousHash)&&pos(b.handoffPosition)&&pos(b.quarantinePosition)&&
 hex(b.policyDigest);
function publicKey(pem){
 try{
  if(typeof pem!=='string'||!pem.length||pem.length>8192)return null;
  const k=createPublicKey(pem);
  return k.asymmetricKeyType==='ed25519'?k:null;
 }catch{return null;}
}
const fingerprint=k=>k.export({type:'spki',format:'der'}).toString('base64');
export function handoffCheckpointPayload(body,witnessId){
 if(!validBody(body)||!id(witnessId))throw new TypeError('INVALID_HANDOFF_CHECKPOINT');
 return Buffer.from(JSON.stringify([
  'PALACO-NEO-HANDOFF-CHECKPOINT-v1',body.namespace,body.checkpointId,
  body.sequence,body.previousHash,body.handoffPosition.count,
  body.handoffPosition.head,body.quarantinePosition.count,
  body.quarantinePosition.head,body.policyDigest,witnessId]),'utf8');
}
export function handoffCheckpointHash(body,witnesses){
 handoffCheckpointPayload(body,'entry-hash');
 if(!Array.isArray(witnesses)||witnesses.length<2||witnesses.length>16||
    witnesses.some(w=>!exact(w,witnessFields)||!id(w.witnessId)||!sig(w.signature))||
    new Set(witnesses.map(w=>w.witnessId)).size!==witnesses.length)
  throw new TypeError('INVALID_HANDOFF_CHECKPOINT_WITNESSES');
 return SHA(['PALACO-NEO-HANDOFF-CHECKPOINT-ENTRY-v1',
  handoffCheckpointPayload(body,'entry-hash').toString('base64'),
  [...witnesses].sort((a,b)=>a.witnessId<b.witnessId?-1:1)
   .map(w=>[w.witnessId,w.signature])]);
}
/** Each checkpoint replays NEO-047/046/044 and underlying original archive
 * bytes. External pins, witness keys and full evidence MUST be independently
 * authenticated by the caller. No physical transfer of access occurs.
 */
export function verifyHandoffCheckpointHistory(records,trustedFloor){
 if(!Array.isArray(records)||records.length>64||!pos(trustedFloor))
  return deny('INVALID_CHECKPOINT_HISTORY_INPUT');
 if(records.length<trustedFloor.count)return deny('CHECKPOINT_ROLLBACK');
 let head=INITIAL.head,namespace=null,previousHandoff=0,previousQuarantine=0;
 const seenIds=new Set(),keyOwners=new Map(),idKeys=new Map(),history=[];
 for(let i=0;i<records.length;i++){
  const record=records[i];
  if(!exact(record,recordFields)||!exact(record?.source,sourceFields)||
     !exact(record?.seal,sealFields)||!validBody(record.seal.body)||
     !Array.isArray(record.seal.witnesses)||!hex(record.seal.hash)||
     !Array.isArray(record.witnessTrust)||!Array.isArray(record.expectedWitnessIds))
   return deny('INVALID_CHECKPOINT_ENTRY');
  const body=record.seal.body,src=record.source;
  if(body.sequence!==i+1||body.previousHash!==head)
   return deny('BROKEN_CHECKPOINT_CHAIN');
  if(seenIds.has(body.checkpointId))return deny('CHECKPOINT_ID_REPLAY');
  if(namespace!==null&&namespace!==body.namespace)return deny('NAMESPACE_CHANGED');
  const verified=verifyEmergencyResponsibilityHandoffs(
   src.history,src.rotations,src.historyFloor,src.lifecyclePin,src.quarantines,
   src.policy,src.policyPin,src.trustedQuarantineFloor,
   src.handoffs,src.trustedHandoffFloor);
  if(!verified.ok)return deny('HANDOFF_'+verified.reason);
  let policyDigest;
  try{policyDigest=keyQuorumPolicyDigest(src.policy);}
  catch{return deny('INVALID_REVIEW_POLICY');}
  if(body.namespace!==src.policy.namespace||body.policyDigest!==policyDigest||
     body.handoffPosition.count!==verified.candidate.position.count||
     body.handoffPosition.head!==verified.candidate.position.head||
     body.quarantinePosition.count!==verified.candidate.quarantinePosition.count||
     body.quarantinePosition.head!==verified.candidate.quarantinePosition.head)
   return deny('CHECKPOINT_EVIDENCE_CONTEXT_CONFLICT');
  if(body.handoffPosition.count<previousHandoff||
     body.quarantinePosition.count<previousQuarantine)
   return deny('CHECKPOINT_STATE_ROLLBACK');
  const expected=record.expectedWitnessIds;
  if(expected.length<2||expected.length>16||expected.length!==record.witnessTrust.length||
     expected.length!==record.seal.witnesses.length||
     expected.some(x=>!id(x))||new Set(expected).size!==expected.length)
   return deny('INVALID_WITNESS_ROSTER');
  const reviewerKeys=new Set();
  for(const reviewer of src.policy.reviewers){
   const k=publicKey(reviewer.publicKeyPem);
   if(!k)return deny('INVALID_REVIEWER_KEY');
   reviewerKeys.add(fingerprint(k));
  }
  for(const q of src.quarantines){
   const k=publicKey(q.body.successorPublicKeyPem);
   if(!k)return deny('INVALID_SUCCESSOR_KEY');
   reviewerKeys.add(fingerprint(k));
  }
  const trustMap=new Map(),witnessKeys=new Set();
  for(const t of record.witnessTrust){
   if(!exact(t,trustFields)||!expected.includes(t.witnessId)||
      trustMap.has(t.witnessId)||t.namespace!==body.namespace||
      t.expectedCheckpointId!==body.checkpointId||t.status!=='ACTIVE')
    return deny('INVALID_OR_REVOKED_WITNESS');
   const k=publicKey(t.publicKeyPem);
   if(!k)return deny('INVALID_WITNESS_KEY');
   const fp=fingerprint(k);
   if(witnessKeys.has(fp)||reviewerKeys.has(fp))
    return deny('NONINDEPENDENT_WITNESS_KEY');
   const owner=keyOwners.get(fp),oldKey=idKeys.get(t.witnessId);
   if(owner!==undefined&&owner!==t.witnessId||
      oldKey!==undefined&&oldKey!==fp)
    return deny('WITNESS_IDENTITY_OR_KEY_CHANGED');
   witnessKeys.add(fp);trustMap.set(t.witnessId,k);
  }
  const signed=new Set();
  for(const w of record.seal.witnesses){
   if(!exact(w,witnessFields)||!expected.includes(w.witnessId)||
      signed.has(w.witnessId)||!sig(w.signature))
    return deny('DUPLICATE_OR_INVALID_WITNESS');
   const k=trustMap.get(w.witnessId);
   if(!k||!edVerify(null,handoffCheckpointPayload(body,w.witnessId),
      k,Buffer.from(w.signature,'base64')))
    return deny('INVALID_WITNESS_SIGNATURE');
   signed.add(w.witnessId);
  }
  if(signed.size!==expected.length)return deny('MISSING_WITNESS');
  if(handoffCheckpointHash(body,record.seal.witnesses)!==record.seal.hash)
   return deny('TAMPERED_CHECKPOINT_HASH');
  for(const t of record.witnessTrust){
   const fp=fingerprint(trustMap.get(t.witnessId));
   keyOwners.set(fp,t.witnessId);idKeys.set(t.witnessId,fp);
  }
  seenIds.add(body.checkpointId);namespace=body.namespace;head=record.seal.hash;
  previousHandoff=body.handoffPosition.count;
  previousQuarantine=body.quarantinePosition.count;
  history.push(Object.freeze({sequence:i+1,checkpointId:body.checkpointId,
   head,handoffPosition:body.handoffPosition}));
 }
 const floorHead=trustedFloor.count===0?INITIAL.head:
  history[trustedFloor.count-1].head;
 if(floorHead!==trustedFloor.head)return deny('TRUSTED_CHECKPOINT_FORK');
 return accepted('HANDOFF_CHECKPOINT_HISTORY_VERIFIED_HOLD',
  'INDEPENDENTLY_SIGNED_HANDOFF_HISTORY_NO_AUTHORITY',
  Object.freeze({position:Object.freeze({count:records.length,head}),
   checkpoints:Object.freeze(history)}));
}
/** Two contradictory, individually verified signatures of the SAME pinned
 * witness key at an identical checkpoint scope are cryptographic statements,
 * not proof that either account or remote storage was actually activated.
 */
export function inspectHandoffWitnessConflict(a,b,trust,trustedPredecessor){
 if(!pos(trustedPredecessor)||!exact(a,['body','witness'])||
    !exact(b,['body','witness'])||!validBody(a.body)||!validBody(b.body)||
    !exact(trust,trustFields))return deny('INVALID_CONFLICT_INPUT');
 const x=a.body,y=b.body;
 if(x.namespace!==y.namespace||x.checkpointId!==y.checkpointId||
    x.sequence!==y.sequence||x.previousHash!==y.previousHash||
    x.policyDigest!==y.policyDigest||
    x.previousHash!==trustedPredecessor.head||
    x.sequence!==trustedPredecessor.count+1||
    trust.namespace!==x.namespace||
    trust.expectedCheckpointId!==x.checkpointId||trust.status!=='ACTIVE')
  return deny('UNRELATED_OR_UNTRUSTED_STATEMENTS');
 const k=publicKey(trust.publicKeyPem);
 if(!k)return deny('INVALID_WITNESS_KEY');
 for(const claim of [a,b]){
  if(!exact(claim.witness,witnessFields)||
     claim.witness.witnessId!==trust.witnessId||
     !sig(claim.witness.signature)||!edVerify(null,
       handoffCheckpointPayload(claim.body,trust.witnessId),k,
       Buffer.from(claim.witness.signature,'base64')))
   return deny('UNVERIFIED_WITNESS_CLAIM');
 }
 if(x.handoffPosition.head===y.handoffPosition.head&&
    x.handoffPosition.count===y.handoffPosition.count&&
    x.quarantinePosition.head===y.quarantinePosition.head&&
    x.quarantinePosition.count===y.quarantinePosition.count)
  return accepted('NO_PROVEN_CONFLICT','IDENTICAL_SIGNED_HANDOFF_STATE',null);
 const states=[x,y].map(z=>[
  z.handoffPosition.count,z.handoffPosition.head,
  z.quarantinePosition.count,z.quarantinePosition.head
 ]).sort((l,r)=>JSON.stringify(l).localeCompare(JSON.stringify(r)));
 return accepted('HANDOFF_WITNESS_CONFLICT_HOLD',
  'TWO_VALID_CONFLICTING_WITNESS_STATEMENTS',
  Object.freeze({witnessId:trust.witnessId,checkpointId:x.checkpointId,
   sequence:x.sequence,states:Object.freeze(states),
   evidenceDigest:SHA(['PALACO-NEO-HANDOFF-WITNESS-CONFLICT-v1',
    x.namespace,x.checkpointId,x.sequence,x.previousHash,x.policyDigest,states])}));
}
export const INITIAL_HANDOFF_CHECKPOINT_POSITION=INITIAL;
