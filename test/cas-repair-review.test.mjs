import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {transferInventoryDigest} from '../src/cas-custody-lineage.mjs';
import {assessReplicaArchive,replicaObservationPayload} from '../src/cas-replica-recovery.mjs';
import {keyQuorumPolicyDigest} from '../src/cas-key-quorum.mjs';
import {recoveryProposalDigest,recoveryReviewPayload,verifyRecoveryEvidence}
 from '../src/cas-repair-review.mjs';

const namespace='PALACO-NEO-TEST',caseId='case-037';
const position={count:1,head:'a'.repeat(64)};
const sha=b=>createHash('sha256').update(b).digest('hex');
const pem=k=>k.publicKey.export({type:'spki',format:'pem'});
const replicaKeys=[0,1,2].map(()=>generateKeyPairSync('ed25519'));
const owner=generateKeyPairSync('ed25519'),security=generateKeyPairSync('ed25519');
const imposter=generateKeyPairSync('ed25519');
const bytes=Buffer.from('intact case source bytes');
const manifest=()=>({schema:'NEO-035-INVENTORY-v1',caseId,artifacts:[
 {artifactId:'file-001',sha256:sha(bytes),byteLength:bytes.length}]});
const inventoryPin=transferInventoryDigest(manifest());
const policy=()=>({schema:'NEO-027-POLICY-v1',namespace,version:1,reviewers:[
 {reviewerId:'review-owner',role:'OWNER',status:'ACTIVE',publicKeyPem:pem(owner)},
 {reviewerId:'review-security',role:'SECURITY',status:'ACTIVE',publicKeyPem:pem(security)}]});
const ids=['replica-001','replica-002','replica-003'];
function replica(i,phase,missing=false){
 const replicaId=ids[i],observationId=phase+'-observation-'+i;
 const body={schema:'NEO-036-REPLICA-v1',namespace,caseId,replicaId,
 inventoryDigest:inventoryPin,lineagePosition:position,observationId};
 const status=missing?'INCOMPLETE':'PRESENT';
 return {body,status,signature:sign(null,replicaObservationPayload(body,status),
  replicaKeys[i].privateKey).toString('base64'),
  artifacts:missing?[]:[{artifactId:'file-001',base64:bytes.toString('base64')}]};
}
function snapshots(phase,missingIndex=-1){
 return {replicas:ids.map((_,i)=>replica(i,phase,i===missingIndex)),
 trusts:ids.map((replicaId,i)=>({namespace,replicaId,
 publicKeyPem:pem(replicaKeys[i]),status:'ACTIVE',
 expectedObservationId:phase+'-observation-'+i})),
 expectedReplicaIds:[...ids]};
}
function fixture(){
 const pre=snapshots('before',2),post=snapshots('after');
 const assessment=assessReplicaArchive(manifest(),inventoryPin,position,
  pre.replicas,pre.trusts,pre.expectedReplicaIds,namespace);
 assert.equal(assessment.phase,'REPAIR_PROPOSAL_ONLY');
 const p=policy();
 const body={schema:'NEO-037-RECOVERY-v1',namespace,recoveryId:'recovery-037',
  policyDigest:keyQuorumPolicyDigest(p),
  proposalDigest:recoveryProposalDigest(assessment.candidate.repairProposal),
  inventoryDigest:inventoryPin,lineagePosition:position};
 const reviews=[['review-owner','OWNER',owner],['review-security','SECURITY',security]]
  .map(([reviewerId,role,k])=>({reviewerId,signature:sign(null,
   recoveryReviewPayload(body,reviewerId,role),k.privateKey).toString('base64')}));
 return {pre,post,policy:p,policyPin:{version:1,digest:keyQuorumPolicyDigest(p)},
  approval:{body,reviews}};
}
function check(f,options={}){
 return verifyRecoveryEvidence(options.manifest??manifest(),
  options.inventoryPin??inventoryPin,options.position??position,f.pre,f.post,
  f.policy,f.policyPin,f.approval,options.namespace??namespace);
}
test('dual-reviewed post-recovery inventory verification never grants authority',()=>{
 const r=check(fixture());
 assert.equal(r.ok,true);assert.equal(r.authorized,false);
 assert.equal(r.phase,'POST_REPAIR_EVIDENCE_VERIFIED_NO_AUTHORITY');
 assert.equal(r.candidate.verifiedReplicas.length,3);
});
test('missing post-repair bytes cannot be accepted',()=>{
 const f=fixture();f.post=snapshots('after',2);
 assert.equal(check(f).reason,'POST_REPAIR_INVENTORY_NOT_VERIFIED');
});
test('forged security signature is denied',()=>{
 const f=fixture();f.approval.reviews[1].signature=sign(null,
  recoveryReviewPayload(f.approval.body,'review-security','SECURITY'),
  imposter.privateKey).toString('base64');
 assert.equal(check(f).reason,'INVALID_RECOVERY_SIGNATURE');
});
test('duplicate owner review cannot substitute for security',()=>{
 const f=fixture();f.approval.reviews[1]={...f.approval.reviews[0]};
 assert.equal(check(f).reason,'INVALID_RECOVERY_REVIEW');
});
test('missing one review is never sufficient',()=>{
 const f=fixture();f.approval.reviews.pop();
 assert.equal(check(f).reason,'INVALID_RECOVERY_INPUT');
});
test('modified proposal digest is rejected',()=>{
 const f=fixture();f.approval.body.proposalDigest='f'.repeat(64);
 assert.equal(check(f).reason,'RECOVERY_CONTEXT_CONFLICT');
});
test('modified inventory digest pin is rejected',()=>{
 assert.equal(check(fixture(),{inventoryPin:'f'.repeat(64)}).reason,
 'NO_VERIFIED_REPAIR_PROPOSAL');
});
test('wrong review policy pin fails closed',()=>{
 const f=fixture();f.policyPin.digest='f'.repeat(64);
 assert.equal(check(f).reason,'UNTRUSTED_RECOVERY_POLICY');
});
test('reviewer revoked under independently pinned policy fails',()=>{
 const f=fixture();f.policy.reviewers[0].status='REVOKED';
 f.policyPin.digest=keyQuorumPolicyDigest(f.policy);
 assert.equal(check(f).reason,'RECOVERY_CONTEXT_CONFLICT');
});
test('reused pre-repair observation IDs are rejected',()=>{
 const f=fixture();f.post=structuredClone(f.pre);
 f.post.replicas[2]=replica(2,'before',false);
 assert.equal(check(f).reason,'REPLICA_TRUST_OR_OBSERVATION_CONFLICT');
});
test('changed replica key in successor snapshot is denied',()=>{
 const f=fixture();f.post.trusts[2].publicKeyPem=pem(imposter);
 assert.equal(check(f).reason,'REPLICA_TRUST_OR_OBSERVATION_CONFLICT');
});
test('changed replica roster is denied',()=>{
 const f=fixture();f.post.expectedReplicaIds.reverse();
 assert.equal(check(f).reason,'REPLICA_ROSTER_CHANGED');
});
test('tampered replica post-repair bytes are denied',()=>{
 const f=fixture();f.post.replicas[2].artifacts[0].base64=
  Buffer.from('corrupted').toString('base64');
 assert.equal(check(f).reason,'POST_REPAIR_INVENTORY_NOT_VERIFIED');
});
test('no verified preliminary repair proposal means no review',()=>{
 const f=fixture();f.pre=snapshots('before');
 assert.equal(check(f).reason,'NO_VERIFIED_REPAIR_PROPOSAL');
});
test('different namespace cannot reuse signed review',()=>{
 assert.equal(check(fixture(),{namespace:'OTHER-REGION'}).ok,false);
});
test('proposal hash is deterministic and refuses malformed evidence',()=>{
 const f=fixture();const before=assessReplicaArchive(manifest(),inventoryPin,position,
  f.pre.replicas,f.pre.trusts,f.pre.expectedReplicaIds,namespace);
 const p=before.candidate.repairProposal;
 assert.equal(recoveryProposalDigest(p),recoveryProposalDigest(structuredClone(p)));
 assert.throws(()=>recoveryProposalDigest({}),/INVALID_RECOVERY_PROPOSAL/);
});
test('invalid input fails closed',()=>{
 const f=fixture();f.approval=null;
 assert.equal(check(f).ok,false);
});
