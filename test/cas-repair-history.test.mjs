import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {transferInventoryDigest} from '../src/cas-custody-lineage.mjs';
import {assessReplicaArchive,replicaObservationPayload} from '../src/cas-replica-recovery.mjs';
import {keyQuorumPolicyDigest} from '../src/cas-key-quorum.mjs';
import {recoveryProposalDigest,recoveryReviewPayload} from '../src/cas-repair-review.mjs';
import {repairCheckpointPayload,repairCheckpointHash,recoveryPostEvidenceDigest,
 INITIAL_REPAIR_CHECKPOINT_POSITION as genesis} from '../src/cas-repair-checkpoint.mjs';
import {verifyRepairCheckpointHistory,inspectRepairCheckpointFork}
 from '../src/cas-repair-history.mjs';

const namespace='PALACO-NEO-TEST',caseId='case-039',lineage={count:1,head:'a'.repeat(64)};
const sha=b=>createHash('sha256').update(b).digest('hex');
const pem=k=>k.publicKey.export({type:'spki',format:'pem'});
const replicaKeys=Array.from({length:3},()=>generateKeyPairSync('ed25519'));
const owner=generateKeyPairSync('ed25519'),security=generateKeyPairSync('ed25519');
const w1=generateKeyPairSync('ed25519'),w2=generateKeyPairSync('ed25519');
const attacker=generateKeyPairSync('ed25519');
const bytes=Buffer.from('original case archive');
const manifest=()=>({schema:'NEO-035-INVENTORY-v1',caseId,artifacts:[
 {artifactId:'file-001',sha256:sha(bytes),byteLength:bytes.length}]});
const pin=transferInventoryDigest(manifest());
const policy=()=>({schema:'NEO-027-POLICY-v1',namespace,version:1,reviewers:[
 {reviewerId:'review-owner',role:'OWNER',status:'ACTIVE',publicKeyPem:pem(owner)},
 {reviewerId:'review-security',role:'SECURITY',status:'ACTIVE',publicKeyPem:pem(security)}]});
const ids=['replica-001','replica-002','replica-003'];
function snapshot(prefix,missing=false){
 return {replicas:ids.map((replicaId,i)=>{
  const observationId=prefix+'-obs-'+i;
  const body={schema:'NEO-036-REPLICA-v1',namespace,caseId,replicaId,
   inventoryDigest:pin,lineagePosition:lineage,observationId};
  const state=missing&&i===2?'INCOMPLETE':'PRESENT';
  return {body,status:state,signature:sign(null,replicaObservationPayload(body,state),
   replicaKeys[i].privateKey).toString('base64'),
   artifacts:state==='PRESENT'?[{artifactId:'file-001',base64:bytes.toString('base64')}]:[]};
 }),trusts:ids.map((replicaId,i)=>({namespace,replicaId,
   publicKeyPem:pem(replicaKeys[i]),status:'ACTIVE',
   expectedObservationId:prefix+'-obs-'+i})),expectedReplicaIds:[...ids]};
}
function build(index=1,previous=genesis,suffix=''){
 const label=index+'-'+suffix,pre=snapshot('pre-'+label,true),
  post=snapshot('post-'+label),p=policy();
 const assessed=assessReplicaArchive(manifest(),pin,lineage,
  pre.replicas,pre.trusts,pre.expectedReplicaIds,namespace);
 assert.equal(assessed.phase,'REPAIR_PROPOSAL_ONLY');
 const body={schema:'NEO-037-RECOVERY-v1',namespace,recoveryId:'recovery-'+index+suffix,
  policyDigest:keyQuorumPolicyDigest(p),proposalDigest:
   recoveryProposalDigest(assessed.candidate.repairProposal),
  inventoryDigest:pin,lineagePosition:lineage};
 const reviews=[['review-owner','OWNER',owner],['review-security','SECURITY',security]]
  .map(([reviewerId,role,key])=>({reviewerId,
   signature:sign(null,recoveryReviewPayload(body,reviewerId,role),
    key.privateKey).toString('base64')}));
 const approval={body,reviews};
 const cb={schema:'NEO-038-REPAIR-CHECKPOINT-v1',namespace,
  checkpointId:'checkpoint-'+index+suffix,recoveryId:body.recoveryId,
  proposalDigest:body.proposalDigest,inventoryDigest:pin,lineagePosition:lineage,
  priorCheckpoint:previous,postEvidenceDigest:recoveryPostEvidenceDigest(approval,post)};
 const witnesses=[['witness-001',w1],['witness-002',w2]].map(([witnessId,key])=>
  ({witnessId,signature:sign(null,repairCheckpointPayload(cb,witnessId),
   key.privateKey).toString('base64')}));
 const seal={body:cb,witnesses,hash:repairCheckpointHash(cb,witnesses)};
 const witnessTrust=[['witness-001',w1],['witness-002',w2]].map(([witnessId,key])=>
  ({namespace,witnessId,publicKeyPem:pem(key),status:'ACTIVE',
   expectedCheckpointId:cb.checkpointId}));
 return {manifest:manifest(),inventoryPin:pin,lineagePosition:lineage,
  pre,post,policy:p,policyPin:{version:p.version,digest:keyQuorumPolicyDigest(p)},
  approval,expectedNamespace:namespace,seal,witnessTrust,
  expectedWitnessIds:['witness-001','witness-002']};
}
const pos=e=>({count:e.seal.body.priorCheckpoint.count+1,head:e.seal.hash});
const two=()=>{
 const one=build();return [one,build(2,pos(one))];
};
test('empty history verifies but never authorizes',()=>{
 const r=verifyRepairCheckpointHistory([],genesis);
 assert.equal(r.ok,true);assert.equal(r.authorized,false);
 assert.equal(r.candidate.position.count,0);
});
test('one full signed repair checkpoint verifies',()=>{
 const r=verifyRepairCheckpointHistory([build()],genesis);
 assert.equal(r.ok,true);assert.equal(r.candidate.position.count,1);
});
test('two successive checkpoints verify entire original bytes and signatures',()=>{
 const r=verifyRepairCheckpointHistory(two(),genesis);
 assert.equal(r.ok,true);assert.equal(r.candidate.position.count,2);
});
test('externally pinned history floor detects truncation',()=>{
 const h=two();
 assert.equal(verifyRepairCheckpointHistory([h[0]],pos(h[1])).reason,
 'CHECKPOINT_ROLLBACK');
});
test('externally pinned floor detects alternative history',()=>{
 const h=two();
 assert.equal(verifyRepairCheckpointHistory(h,{count:1,head:'f'.repeat(64)}).reason,
 'TRUSTED_CHECKPOINT_FORK');
});
test('duplicate recovery ID is rejected before any bypass of history',()=>{
 const h=two();h[1].seal.body.recoveryId=h[0].seal.body.recoveryId;
 assert.equal(verifyRepairCheckpointHistory(h,genesis).reason,
  'DUPLICATE_RECOVERY_OR_CHECKPOINT_ID');
});
test('duplicate checkpoint ID rejected',()=>{
 const h=two();h[1].seal.body.checkpointId=h[0].seal.body.checkpointId;
 assert.equal(verifyRepairCheckpointHistory(h,genesis).reason,
  'DUPLICATE_RECOVERY_OR_CHECKPOINT_ID');
});
test('replayed post-repair observation ID rejected across checkpoints',()=>{
 const h=two();
 h[1].post.replicas[0].body.observationId=h[0].post.replicas[0].body.observationId;
 assert.equal(verifyRepairCheckpointHistory(h,genesis).reason,
  'REPLAYED_POST_OBSERVATION');
});
test('broken predecessor link fails even if new checkpoint is signed',()=>{
 const h=two(),bad=build(2,genesis);
 assert.match(verifyRepairCheckpointHistory([h[0],bad],genesis).reason,
 /^CHECKPOINT_/);
});
test('forged checkpoint witness signature fails full replay',()=>{
 const e=build();e.seal.witnesses[0].signature=sign(null,
  repairCheckpointPayload(e.seal.body,'witness-001'),
  attacker.privateKey).toString('base64');
 assert.match(verifyRepairCheckpointHistory([e],genesis).reason,/^CHECKPOINT_/);
});
test('damaged original post-repair byte cannot be covered by signed checkpoint',()=>{
 const e=build();e.post.replicas[0].artifacts[0].base64=Buffer.from('bad').toString('base64');
 assert.match(verifyRepairCheckpointHistory([e],genesis).reason,/^CHECKPOINT_/);
});
test('two identical valid complete histories are not a fork',()=>{
 const h=two();const r=inspectRepairCheckpointFork(h,structuredClone(h),genesis);
 assert.equal(r.phase,'NO_PROVEN_FORK');
});
test('valid prefix and extension are not equivocation',()=>{
 const h=two();const r=inspectRepairCheckpointFork([h[0]],h,genesis);
 assert.equal(r.phase,'NO_PROVEN_FORK');
});
test('two fully verified branches from same predecessor surface conflicting witnesses',()=>{
 const left=[build(1,genesis,'-left')],right=[build(1,genesis,'-right')];
 const r=inspectRepairCheckpointFork(left,right,genesis);
 assert.equal(r.phase,'FORK_EVIDENCE_HOLD');assert.equal(r.authorized,false);
 assert.deepEqual(r.candidate.sharedSigningWitnesses,['witness-001','witness-002']);
 assert.notEqual(r.candidate.leftHash,r.candidate.rightHash);
});
test('a forged competing branch cannot create valid fork evidence',()=>{
 const a=build(1,genesis,'-left'),b=build(1,genesis,'-right');
 b.seal.witnesses[0].signature='a'.repeat(88);
 assert.equal(inspectRepairCheckpointFork([a],[b],genesis).reason,
 'UNVERIFIED_HISTORY_BRANCH');
});
test('fork proof is bounded by independent floor',()=>{
 const a=build(1,genesis,'-left'),b=build(1,genesis,'-right');
 assert.equal(inspectRepairCheckpointFork([a],[b],pos(a)).ok,false);
});
test('unexpected missing witness evidence is denied',()=>{
 const e=build();e.seal.witnesses.pop();
 assert.equal(verifyRepairCheckpointHistory([e],genesis).ok,false);
});
test('invalid input fails closed',()=>{
 assert.equal(verifyRepairCheckpointHistory(null,genesis).ok,false);
 assert.equal(inspectRepairCheckpointFork(null,[],genesis).ok,false);
});
