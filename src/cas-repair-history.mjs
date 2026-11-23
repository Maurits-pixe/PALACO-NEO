import {verifyRepairCheckpoint,INITIAL_REPAIR_CHECKPOINT_POSITION} from './cas-repair-checkpoint.mjs';

/** NEO-039: read-only full-history checkpoint verification and fork detection.
 * Every checkpoint must replay its original NEO-037 bytes, policy and signatures.
 * Neither verification nor fork evidence grants execution authority.
 */
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 (Object.getPrototypeOf(x)===Object.prototype||Object.getPrototypeOf(x)===null);
const exact=(x,fields)=>obj(x)&&Object.keys(x).sort().join(',')===[...fields].sort().join(',');
const id=x=>typeof x==='string'&&/^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const hex=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const position=x=>exact(x,['count','head'])&&Number.isSafeInteger(x.count)&&
 x.count>=0&&x.count<=256&&hex(x.head);
const fail=reason=>Object.freeze({ok:false,phase:'HOLD',reason,authorized:false,candidate:null});
const success=(phase,reason,candidate)=>Object.freeze({ok:true,phase,reason,
 authorized:false,candidate});
const keys=['manifest','inventoryPin','lineagePosition','pre','post','policy',
 'policyPin','approval','expectedNamespace','seal','witnessTrust','expectedWitnessIds'];
function verifyOne(e,before){
 if(!exact(e,keys))return fail('INVALID_CHECKPOINT_EVIDENCE');
 return verifyRepairCheckpoint(e.manifest,e.inventoryPin,e.lineagePosition,
  e.pre,e.post,e.policy,e.policyPin,e.approval,e.expectedNamespace,
  e.seal,e.witnessTrust,e.expectedWitnessIds,before);
}
function chainFloor(history,floor){
 if(history.length<floor.count)return 'CHECKPOINT_ROLLBACK';
 const actual=floor.count===0?INITIAL_REPAIR_CHECKPOINT_POSITION.head:
  history[floor.count-1].seal.hash;
 return actual===floor.head?null:'TRUSTED_CHECKPOINT_FORK';
}
/** No skipped proofs: recheck each checkpoint, not just its hash or cached verdict.
 * The floor and every trust record must come from separately authenticated custody.
 */
export function verifyRepairCheckpointHistory(history,trustedFloor){
 if(!Array.isArray(history)||history.length>256||!position(trustedFloor))
  return fail('INVALID_HISTORY_INPUT');
 if(history.length<trustedFloor.count)return fail('CHECKPOINT_ROLLBACK');
 let previous=INITIAL_REPAIR_CHECKPOINT_POSITION;
 const usedRecoveries=new Set(),usedCheckpoints=new Set(),
  usedObservations=new Set(),verified=[];
 for(let i=0;i<history.length;i++){
  const e=history[i];
  if(!exact(e,keys)||!obj(e.seal)||!obj(e.seal.body))
   return fail('INVALID_CHECKPOINT_EVIDENCE');
  const body=e.seal.body;
  if(!id(body.recoveryId)||!id(body.checkpointId)||
    usedRecoveries.has(body.recoveryId)||usedCheckpoints.has(body.checkpointId))
   return fail('DUPLICATE_RECOVERY_OR_CHECKPOINT_ID');
  // Cross-history replay resistance (local to the supplied full chain).
  if(!obj(e.post)||!Array.isArray(e.post.replicas))
   return fail('MISSING_POST_EVIDENCE');
  for(const replica of e.post.replicas){
   const observation=replica?.body?.observationId;
   if(!id(observation)||usedObservations.has(observation))
    return fail('REPLAYED_POST_OBSERVATION');
  }
  const checked=verifyOne(e,previous);
  if(!checked.ok)return fail('CHECKPOINT_'+checked.reason);
  for(const replica of e.post.replicas)usedObservations.add(replica.body.observationId);
  usedRecoveries.add(body.recoveryId);usedCheckpoints.add(body.checkpointId);
  previous=checked.candidate.position;
  verified.push(Object.freeze({count:previous.count,head:previous.head,
   recoveryId:body.recoveryId,checkpointId:body.checkpointId}));
 }
 const floorProblem=chainFloor(history,trustedFloor);
 if(floorProblem)return fail(floorProblem);
 return success('VERIFIED_HISTORY_ONLY','FULL_REPAIR_HISTORY_SIGNED_NOT_AUTHORITY',
  Object.freeze({position:previous,checkpoints:Object.freeze(verified)}));
}
/** Forensic comparison of two independently authenticated full-chain versions.
 * Two different valid signed checkpoint entries branching from the same pinned
 * predecessor constitute conflicting witness-backed statements; not proof that
 * the same witness signed both unless witness IDs AND keys overlap.
 */
export function inspectRepairCheckpointFork(left,right,trustedFloor){
 const a=verifyRepairCheckpointHistory(left,trustedFloor);
 const b=verifyRepairCheckpointHistory(right,trustedFloor);
 if(!a.ok||!b.ok)return fail('UNVERIFIED_HISTORY_BRANCH');
 const prefix=Math.min(left.length,right.length);
 let conflict=-1;
 for(let i=0;i<prefix;i++){
  if(left[i].seal.hash!==right[i].seal.hash){conflict=i;break;}
 }
 if(conflict===-1)return success('NO_PROVEN_FORK',
   'IDENTICAL_OR_PREFIX_COMPATIBLE_HISTORY',null);
 const la=left[conflict].seal,rb=right[conflict].seal;
 if(la.body.priorCheckpoint.count!==rb.body.priorCheckpoint.count||
    la.body.priorCheckpoint.head!==rb.body.priorCheckpoint.head)
  return fail('UNRELATED_BRANCH_POINT');
 const lhs=new Map(la.witnesses.map(w=>[w.witnessId,w.signature]));
 const rhs=new Map(rb.witnesses.map(w=>[w.witnessId,w.signature]));
 const witnessed=[];
 const leftKeys=new Map(left[conflict].witnessTrust.map(t=>[t.witnessId,t.publicKeyPem]));
 for(const t of right[conflict].witnessTrust){
  if(lhs.has(t.witnessId)&&rhs.has(t.witnessId)&&leftKeys.get(t.witnessId)===t.publicKeyPem)
   witnessed.push(t.witnessId);
 }
 return success('FORK_EVIDENCE_HOLD','TWO_VALID_CONFLICTING_CHECKPOINT_BRANCHES',
  Object.freeze({position:Object.freeze({count:conflict+1,
   previousHead:la.body.priorCheckpoint.head}),
   leftHash:la.hash,rightHash:rb.hash,
   sharedSigningWitnesses:Object.freeze(witnessed.sort())}));
}
