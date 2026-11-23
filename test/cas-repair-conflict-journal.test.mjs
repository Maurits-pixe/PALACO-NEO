import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {transferInventoryDigest} from '../src/cas-custody-lineage.mjs';
import {assessReplicaArchive,replicaObservationPayload} from '../src/cas-replica-recovery.mjs';
import {keyQuorumPolicyDigest} from '../src/cas-key-quorum.mjs';
import {recoveryProposalDigest,recoveryReviewPayload} from '../src/cas-repair-review.mjs';
import {repairCheckpointPayload,repairCheckpointHash,recoveryPostEvidenceDigest,
 INITIAL_REPAIR_CHECKPOINT_POSITION as genesis} from '../src/cas-repair-checkpoint.mjs';
import {inspectRepairCheckpointFork} from '../src/cas-repair-history.mjs';
import {repairForkEvidenceDigest,repairConflictReviewPayload,repairConflictEntryHash,verifyRepairConflictJournal,INITIAL_REPAIR_CONFLICT_POSITION as auditGenesis} from '../src/cas-repair-conflict-journal.mjs';

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

function record(suffix='-left',rival='-right',caseName='audit-case-001',sequence=1,previousHead=auditGenesis.head){
 const left=[build(1,genesis,suffix)],right=[build(1,genesis,rival)];
 const fork=inspectRepairCheckpointFork(left,right,genesis);
 assert.equal(fork.phase,'FORK_EVIDENCE_HOLD');
 const body={sequence,previousHash:previousHead,caseId:caseName,
  action:'ESCALATE_HOLD',forkDigest:repairForkEvidenceDigest(fork.candidate)};
 const digest=keyQuorumPolicyDigest(policy());
 const reviews=[['review-owner','OWNER',owner],['review-security','SECURITY',security]]
  .map(([reviewerId,role,key])=>({reviewerId,signature:sign(null,
  repairConflictReviewPayload(body,digest,reviewerId,role),key.privateKey).toString('base64')}));
 return {entry:{...body,reviews,hash:repairConflictEntryHash(body,reviews)},
  evidence:{left,right,forkFloor:genesis}};
}
const verify=(rows,floor=auditGenesis,p=policy(),pinOverride=null)=>verifyRepairConflictJournal(
 rows.map(x=>x.entry),rows.map(x=>x.evidence),p,
 pinOverride??{version:p.version,digest:keyQuorumPolicyDigest(p)},floor);
test('valid full original conflicting histories are audited with dual roles but no release',()=>{
 const r=verify([record()]);
 assert.equal(r.ok,true);assert.equal(r.authorized,false);
 assert.equal(r.phase,'ESCALATION_EVIDENCE_VERIFIED_HOLD');
 assert.equal(r.candidate.cases[0].status,'ESCALATED_HOLD');
});
test('two distinct conflict cases form a signed append-only journal',()=>{
 const a=record(),b=record('-third','-fourth','audit-case-002',2,a.entry.hash);
 const r=verify([a,b]);assert.equal(r.ok,true);
 assert.equal(r.candidate.position.count,2);
});
test('reordered opposing histories yield the same forensic digest',()=>{
 const a=record();
 const fork=inspectRepairCheckpointFork(a.evidence.right,a.evidence.left,genesis);
 assert.equal(repairForkEvidenceDigest(fork.candidate),a.entry.forkDigest);
});
test('modified original witness signature is detected',()=>{
 const a=record();a.evidence.right[0].seal.witnesses[0].signature='a'.repeat(88);
 assert.equal(verify([a]).reason,'UNVERIFIED_RECOVERY_FORK');
});
test('tampered original artifact bytes are rejected',()=>{
 const a=record();a.evidence.left[0].post.replicas[0].artifacts[0].base64='YmFk';
 assert.equal(verify([a]).reason,'UNVERIFIED_RECOVERY_FORK');
});
test('substituted forensic evidence cannot reuse review signatures',()=>{
 const a=record(),b=record('-third','-fourth');
 a.evidence=b.evidence;
 assert.equal(verify([a]).reason,'FORK_EVIDENCE_SUBSTITUTED');
});
test('OWNER signature forgery fails closed',()=>{
 const a=record();
 a.entry.reviews[0].signature=sign(null,repairConflictReviewPayload({
  sequence:a.entry.sequence,previousHash:a.entry.previousHash,caseId:a.entry.caseId,
  action:a.entry.action,forkDigest:a.entry.forkDigest},keyQuorumPolicyDigest(policy()),
  'review-owner','OWNER'),attacker.privateKey).toString('base64');
 assert.equal(verify([a]).reason,'INVALID_REVIEW_SIGNATURE');
});
test('duplicate reviewer or missing role fails closed',()=>{
 const a=record();a.entry.reviews[1]={...a.entry.reviews[0]};
 assert.equal(verify([a]).reason,'INVALID_OR_DUPLICATE_REVIEW');
});
test('revoked reviewer never satisfies quorum',()=>{
 const a=record(),p=policy();p.reviewers[0].status='REVOKED';
 assert.equal(verify([a],auditGenesis,p).reason,'REVOKED_OR_DUPLICATE_REVIEW_ROLE');
});
test('wrong externally pinned quorum policy refuses all entries',()=>{
 const a=record();
 assert.equal(verify([a],auditGenesis,policy(),{version:1,digest:'f'.repeat(64)}).reason,
  'REVIEW_POLICY_PIN_CONFLICT');
});
test('duplicate case ID is forbidden',()=>{
 const a=record(),b=record('-third','-fourth','audit-case-001',2,a.entry.hash);
 assert.equal(verify([a,b]).reason,'DUPLICATE_CONFLICT_CASE_OR_FORK');
});
test('duplicate fork digest under a second case ID is forbidden',()=>{
 const a=record(),b=record('-left','-right','audit-case-002',2,a.entry.hash);
 assert.equal(verify([a,b]).reason,'DUPLICATE_CONFLICT_CASE_OR_FORK');
});
test('truncated history below trusted floor is rejected',()=>{
 const a=record();
 assert.equal(verify([],{count:1,head:a.entry.hash}).reason,'CONFLICT_JOURNAL_ROLLBACK');
});
test('forked journal head against trusted floor is rejected',()=>{
 const a=record();
 assert.equal(verify([a],{count:1,head:'f'.repeat(64)}).reason,'CONFLICT_JOURNAL_FORK');
});
test('journal entry tampering is detected',()=>{
 const a=record();a.entry.hash='f'.repeat(64);
 assert.equal(verify([a]).reason,'TAMPERED_CONFLICT_ENTRY');
});
test('invalid action cannot silently close an audit case',()=>{
 const a=record();a.entry.action='CLOSED';
 assert.equal(verify([a]).reason,'BROKEN_CONFLICT_JOURNAL_CHAIN');
});
test('valid non-conflicting prefix is not fabricated into fork evidence',()=>{
 const a=record();a.evidence.right=a.evidence.left;
 assert.equal(verify([a]).reason,'UNVERIFIED_RECOVERY_FORK');
});
test('malformed evidence and inputs are denied; empty journal grants no authority',()=>{
 assert.equal(verifyRepairConflictJournal(null,[],policy(),{version:1,digest:'f'.repeat(64)},auditGenesis).ok,false);
 assert.equal(verify([],auditGenesis).authorized,false);
 assert.throws(()=>repairForkEvidenceDigest({}),/INVALID_FORK_EVIDENCE/);
});
