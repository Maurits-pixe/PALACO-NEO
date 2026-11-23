import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {transferInventoryDigest} from '../src/cas-custody-lineage.mjs';
import {assessReplicaArchive,replicaObservationPayload} from '../src/cas-replica-recovery.mjs';
import {keyQuorumPolicyDigest} from '../src/cas-key-quorum.mjs';
import {recoveryProposalDigest,recoveryReviewPayload} from '../src/cas-repair-review.mjs';
import {INITIAL_REPAIR_CHECKPOINT_POSITION as genesis,
 repairCheckpointPayload,repairCheckpointHash,recoveryPostEvidenceDigest,
 verifyRepairCheckpoint} from '../src/cas-repair-checkpoint.mjs';

const ns='PALACO-NEO-TEST',caseId='case-038';
const lineage={count:1,head:'a'.repeat(64)};
const sha=b=>createHash('sha256').update(b).digest('hex');
const pem=k=>k.publicKey.export({type:'spki',format:'pem'});
const replicas=Array.from({length:3},()=>generateKeyPairSync('ed25519'));
const owner=generateKeyPairSync('ed25519'),security=generateKeyPairSync('ed25519');
const w1=generateKeyPairSync('ed25519'),w2=generateKeyPairSync('ed25519');
const impostor=generateKeyPairSync('ed25519');
const bytes=Buffer.from('original PALACO case bytes');
const manifest=()=>({schema:'NEO-035-INVENTORY-v1',caseId,artifacts:[
 {artifactId:'file-001',sha256:sha(bytes),byteLength:bytes.length}]});
const inventoryPin=transferInventoryDigest(manifest());
const policy=()=>({schema:'NEO-027-POLICY-v1',namespace:ns,version:1,reviewers:[
 {reviewerId:'review-owner',role:'OWNER',status:'ACTIVE',publicKeyPem:pem(owner)},
 {reviewerId:'review-security',role:'SECURITY',status:'ACTIVE',publicKeyPem:pem(security)}]});
const replicaIds=['replica-001','replica-002','replica-003'];
function replica(i,phase,missing=false){
 const replicaId=replicaIds[i],observationId=phase+'-obs-'+i;
 const body={schema:'NEO-036-REPLICA-v1',namespace:ns,caseId,replicaId,
  inventoryDigest:inventoryPin,lineagePosition:lineage,observationId};
 const status=missing?'INCOMPLETE':'PRESENT';
 return {body,status,signature:sign(null,replicaObservationPayload(body,status),
  replicas[i].privateKey).toString('base64'),
  artifacts:missing?[]:[{artifactId:'file-001',base64:bytes.toString('base64')}]};
}
function snapshot(phase,missing=-1){
 return {replicas:replicaIds.map((_,i)=>replica(i,phase,i===missing)),
 trusts:replicaIds.map((replicaId,i)=>({namespace:ns,replicaId,
  publicKeyPem:pem(replicas[i]),status:'ACTIVE',
  expectedObservationId:phase+'-obs-'+i})),
 expectedReplicaIds:[...replicaIds]};
}
function fixture(){
 const pre=snapshot('before',2),post=snapshot('after'),p=policy();
 const assessed=assessReplicaArchive(manifest(),inventoryPin,lineage,
  pre.replicas,pre.trusts,pre.expectedReplicaIds,ns);
 assert.equal(assessed.phase,'REPAIR_PROPOSAL_ONLY');
 const body={schema:'NEO-037-RECOVERY-v1',namespace:ns,
  recoveryId:'recovery-038',policyDigest:keyQuorumPolicyDigest(p),
  proposalDigest:recoveryProposalDigest(assessed.candidate.repairProposal),
  inventoryDigest:inventoryPin,lineagePosition:lineage};
 const reviews=[['review-owner','OWNER',owner],['review-security','SECURITY',security]]
  .map(([reviewerId,role,key])=>({reviewerId,signature:sign(null,
   recoveryReviewPayload(body,reviewerId,role),
   key.privateKey).toString('base64')}));
 const approval={body,reviews};
 const cb={schema:'NEO-038-REPAIR-CHECKPOINT-v1',namespace:ns,
  checkpointId:'checkpoint-038',recoveryId:body.recoveryId,
  proposalDigest:body.proposalDigest,inventoryDigest:inventoryPin,
  lineagePosition:lineage,priorCheckpoint:genesis,
  postEvidenceDigest:recoveryPostEvidenceDigest(approval,post)};
 const witnesses=[['witness-001',w1],['witness-002',w2]].map(([witnessId,key])=>
  ({witnessId,signature:sign(null,repairCheckpointPayload(cb,witnessId),
   key.privateKey).toString('base64')}));
 const seal={body:cb,witnesses,hash:repairCheckpointHash(cb,witnesses)};
 const trusts=[['witness-001',w1],['witness-002',w2]].map(([witnessId,key])=>({
  namespace:ns,witnessId,publicKeyPem:pem(key),status:'ACTIVE',
  expectedCheckpointId:'checkpoint-038'
 }));
 return {pre,post,policy:p,policyPin:{version:1,digest:keyQuorumPolicyDigest(p)},
  approval,seal,trusts};
}
const check=(f,opts={})=>verifyRepairCheckpoint(
 opts.manifest??manifest(),opts.inventoryPin??inventoryPin,
 opts.lineage??lineage,f.pre,f.post,f.policy,f.policyPin,f.approval,
 opts.namespace??ns,f.seal,f.trusts,
 opts.ids??['witness-001','witness-002'],
 opts.before??genesis,opts.after??null);
test('two independent signed witnesses attest to reverified post-repair bytes',()=>{
 const result=check(fixture());
 assert.equal(result.ok,true);
 assert.equal(result.authorized,false);
 assert.equal(result.phase,'SIGNED_REPAIR_CHECKPOINT_NO_AUTHORITY');
 assert.equal(result.candidate.position.count,1);
});
test('exact externally pinned next checkpoint is accepted',()=>{
 const f=fixture();
 assert.equal(check(f,{after:{count:1,head:f.seal.hash}}).ok,true);
});
test('stale or forked externally pinned next checkpoint is refused',()=>{
 const f=fixture();
 assert.equal(check(f,{after:{count:1,head:'f'.repeat(64)}}).reason,'CHECKPOINT_ROLLBACK_OR_FORK');
 assert.equal(check(f,{after:{count:0,head:genesis.head}}).ok,false);
});
test('independently pinned previous checkpoint must match signed predecessor',()=>{
 const f=fixture();
 assert.equal(check(f,{before:{count:1,head:'b'.repeat(64)}}).reason,
 'UNTRUSTED_CHECKPOINT_CONTEXT');
});
test('single missing witness is insufficient',()=>{
 const f=fixture();f.seal.witnesses.pop();
 assert.equal(check(f).ok,false);
});
test('duplicated witness signing identity fails closed',()=>{
 const f=fixture();f.seal.witnesses[1]={...f.seal.witnesses[0]};
 assert.equal(check(f).reason,'DUPLICATE_OR_MISSING_WITNESS');
});
test('forged witness signature is refused',()=>{
 const f=fixture();
 f.seal.witnesses[1].signature=sign(null,
  repairCheckpointPayload(f.seal.body,'witness-002'),
  impostor.privateKey).toString('base64');
 assert.equal(check(f).reason,'INVALID_WITNESS_SIGNATURE');
});
test('reused signing key across two witness IDs is refused',()=>{
 const f=fixture();f.trusts[1].publicKeyPem=pem(w1);
 assert.equal(check(f).reason,'SHARED_CHECKPOINT_WITNESS_KEY');
});
test('witness key may not alias a reviewer key',()=>{
 const f=fixture();f.trusts[0].publicKeyPem=pem(owner);
 assert.equal(check(f).reason,'SHARED_CHECKPOINT_WITNESS_KEY');
});
test('witness key may not alias a replica key',()=>{
 const f=fixture();f.trusts[0].publicKeyPem=pem(replicas[0]);
 assert.equal(check(f).reason,'SHARED_CHECKPOINT_WITNESS_KEY');
});
test('revoked witness denied',()=>{
 const f=fixture();f.trusts[1].status='REVOKED';
 assert.equal(check(f).reason,'UNTRUSTED_CHECKPOINT_WITNESS');
});
test('checkpoint replay against different expected checkpoint ID denied',()=>{
 const f=fixture();f.trusts[1].expectedCheckpointId='checkpoint-new';
 assert.equal(check(f).reason,'UNTRUSTED_CHECKPOINT_WITNESS');
});
test('changing checkpoint hash without signatures fails',()=>{
 const f=fixture();f.seal.hash='f'.repeat(64);
 assert.equal(check(f).reason,'TAMPERED_CHECKPOINT_HASH');
});
test('modified post-repair artifact is rejected before witness evaluation',()=>{
 const f=fixture();f.post.replicas[2].artifacts[0].base64=
  Buffer.from('tamper').toString('base64');
 assert.match(check(f).reason,/^RECOVERY_/);
});
test('missing post-repair replica is rejected before witness evaluation',()=>{
 const f=fixture();f.post.replicas[2].artifacts=[];
 assert.match(check(f).reason,/^RECOVERY_/);
});
test('modified signed reviewer approval is rejected',()=>{
 const f=fixture();f.approval.reviews[0].signature=sign(null,
  recoveryReviewPayload(f.approval.body,'review-owner','OWNER'),
  impostor.privateKey).toString('base64');
 assert.match(check(f).reason,/^RECOVERY_/);
});
test('incorrect post-evidence digest and incorrect inventory pin fail closed',()=>{
 const f=fixture();f.seal.body.postEvidenceDigest='f'.repeat(64);
 assert.equal(check(f).reason,'UNTRUSTED_CHECKPOINT_CONTEXT');
 assert.equal(check(fixture(),{inventoryPin:'f'.repeat(64)}).ok,false);
});
test('signed witness inputs without original repair evidence are never accepted',()=>{
 const f=fixture();f.pre.replicas[2]=replica(2,'before',false);
 assert.match(check(f).reason,/^RECOVERY_/);
});
test('malformed checkpoint, trust or roster are refused',()=>{
 const f=fixture();
 assert.equal(check(f,{ids:['witness-001','witness-001']}).ok,false);
 assert.equal(check({...f,seal:null}).ok,false);
 assert.throws(()=>repairCheckpointPayload({},'witness-001'),/INVALID_REPAIR_CHECKPOINT/);
});
