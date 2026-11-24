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
import {repairForkEvidenceDigest,repairConflictReviewPayload,repairConflictEntryHash,INITIAL_REPAIR_CONFLICT_POSITION as auditGenesis} from '../src/cas-repair-conflict-journal.mjs';
import {auditCheckpointPayload} from '../src/cas-audit-checkpoint.mjs';
import {auditHistoryEntryHash,verifyAuditCheckpointSuccession,INITIAL_AUDIT_HISTORY_POSITION as historyGenesis} from '../src/cas-audit-history.mjs';
import {custodianRotationPayload,verifyCustodianRotation} from '../src/cas-custodian-rotation.mjs';

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

const custodianA=generateKeyPairSync('ed25519');
const custodianB=generateKeyPairSync('ed25519');
const custodianC=generateKeyPairSync('ed25519');
const custodianIds=['custodian-a','custodian-b'];
function assertion(body,custodianId,key){
 return {custodianId,signature:sign(null,auditCheckpointPayload(body,custodianId),
  key.privateKey).toString('base64')};
}
function fixture(){
 const rows=[record()];
 const p=policy(),policyPin={version:p.version,digest:keyQuorumPolicyDigest(p)};
 const body={schema:'NEO-041-AUDIT-CHECKPOINT-v1',namespace,
  checkpointId:'checkpoint-041',position:{count:1,head:rows[0].entry.hash},
  anchoredFloor:auditGenesis,policyDigest:policyPin.digest};
 const seal={body,attestations:[assertion(body,custodianIds[0],custodianA),
  assertion(body,custodianIds[1],custodianB)]};
 const trusts=[[custodianIds[0],custodianA],[custodianIds[1],custodianB]]
  .map(([custodianId,k])=>({namespace,custodianId,publicKeyPem:pem(k),
   status:'ACTIVE',expectedCheckpointId:body.checkpointId}));
 return {rows,p,policyPin,seal,trusts};
}
const check=(f,floor=auditGenesis,ids=custodianIds)=>
 verifyAuditCheckpoint(f.rows.map(x=>x.entry),f.rows.map(x=>x.evidence),
 f.p,f.policyPin,floor,f.seal,f.trusts,ids);

function item(f=fixture()){
 return {entries:f.rows.map(x=>x.entry),evidence:f.rows.map(x=>x.evidence),
 policy:f.p,policyPin:f.policyPin,seal:f.seal,trusts:f.trusts,
 expectedCustodianIds:[...custodianIds]};
}
function next(previous,suffix='-next',checkpointId='checkpoint-042'){
 const a=previous.entries.at(-1),p=policy();
 const extra=record('-later'+suffix,'-rival'+suffix,
   'audit-case-'+suffix.replace(/[^A-Za-z0-9]/g,''),2,a.hash);
 const entries=[...previous.entries,extra.entry];
 const evidence=[...previous.evidence,extra.evidence];
 const floor={count:previous.entries.length,head:a.hash};
 const body={schema:'NEO-041-AUDIT-CHECKPOINT-v1',namespace,
  checkpointId,position:{count:entries.length,head:extra.entry.hash},
  anchoredFloor:floor,policyDigest:keyQuorumPolicyDigest(p)};
 const seal={body,attestations:[assertion(body,'custodian-a',custodianA),
  assertion(body,'custodian-b',custodianB)]};
 const trusts=[['custodian-a',custodianA],['custodian-b',custodianB]]
  .map(([custodianId,key])=>({namespace,custodianId,
   publicKeyPem:pem(key),status:'ACTIVE',expectedCheckpointId:checkpointId}));
 return {entries,evidence,policy:p,policyPin:{version:p.version,digest:keyQuorumPolicyDigest(p)},
  seal,trusts,expectedCustodianIds:[...custodianIds]};
}
const chain=()=>{const a=item();return [a,next(a)];};

const forged=generateKeyPairSync('ed25519');
function rotationFixture(){
 const h=chain(),oldKey=custodianA,newKey=custodianC;
 const first=auditHistoryEntryHash(1,historyGenesis.head,h[0].seal);
 h[1].trusts[0].publicKeyPem=pem(newKey);
 h[1].seal.attestations[0]=assertion(h[1].seal.body,'custodian-a',newKey);
 const p=h[1].policy;
 const rb={schema:'NEO-043-CUSTODIAN-ROTATION-v1',namespace,
  rotationId:'rotation-043',custodianId:'custodian-a',
  oldKeyPem:pem(oldKey),newKeyPem:pem(newKey),
  atSequence:2,previousHistoryHead:first,
  checkpointId:h[1].seal.body.checkpointId,
  policyDigest:keyQuorumPolicyDigest(p)};
 const oldSignature=sign(null,custodianRotationPayload(rb,'custodian-a','OLD_CUSTODIAN'),
  oldKey.privateKey).toString('base64');
 const newSignature=sign(null,custodianRotationPayload(rb,'custodian-a','NEW_CUSTODIAN'),
  newKey.privateKey).toString('base64');
 const reviews=[['review-owner','OWNER',owner],['review-security','SECURITY',security]]
 .map(([reviewerId,role,key])=>({reviewerId,
  signature:sign(null,custodianRotationPayload(rb,reviewerId,role),
   key.privateKey).toString('base64')}));
 const proof={body:rb,oldSignature,newSignature,reviews};
 return {history:h,rotations:[{atSequence:2,proof}]};
}
const checkRotation=f=>verifyAuditCheckpointSuccession(f.history,
 historyGenesis,f.rotations);
test('signed old/new custodian continuity and OWNER+SECURITY reviews retain HOLD',()=>{
 const f=rotationFixture(),r=checkRotation(f);
 assert.equal(r.ok,true);assert.equal(r.authorized,false);
 assert.equal(r.candidate.position.count,2);
});
test('rotated audit history refuses key change when proof is missing',()=>{
 const f=rotationFixture();
 assert.equal(verifyAuditCheckpointSuccession(f.history,historyGenesis).reason,
  'CUSTODIAN_KEY_CHANGED_WITHOUT_ROTATION_PROOF');
});
test('old key signature forgery fails closed',()=>{
 const f=rotationFixture(),p=f.rotations[0].proof;
 p.oldSignature=sign(null,custodianRotationPayload(p.body,'custodian-a','OLD_CUSTODIAN'),
  forged.privateKey).toString('base64');
 assert.equal(checkRotation(f).reason,'ROTATION_INVALID_CUSTODIAN_CONTINUITY_SIGNATURE');
});
test('new key signature forgery fails closed',()=>{
 const f=rotationFixture(),p=f.rotations[0].proof;
 p.newSignature=sign(null,custodianRotationPayload(p.body,'custodian-a','NEW_CUSTODIAN'),
  forged.privateKey).toString('base64');
 assert.equal(checkRotation(f).reason,'ROTATION_INVALID_CUSTODIAN_CONTINUITY_SIGNATURE');
});
test('forged security review rejected',()=>{
 const f=rotationFixture(),p=f.rotations[0].proof;
 p.reviews[1].signature=sign(null,
 custodianRotationPayload(p.body,'review-security','SECURITY'),
 forged.privateKey).toString('base64');
 assert.equal(checkRotation(f).reason,'ROTATION_INVALID_ROTATION_REVIEW_SIGNATURE');
});
test('duplicate reviewer identity cannot satisfy dual role review',()=>{
 const f=rotationFixture(),p=f.rotations[0].proof;
 p.reviews[1]={...p.reviews[0]};
 assert.equal(checkRotation(f).reason,'ROTATION_INVALID_DUPLICATE_REVIEWER');
});
test('revoked reviewer refused with pinned policy',()=>{
 const f=rotationFixture(),p=f.history[1].policy;
 p.reviewers[1].status='REVOKED';
 f.history[1].policyPin.digest=keyQuorumPolicyDigest(p);
 assert.equal(checkRotation(f).ok,false);
});
test('wrong rotation checkpoint is rejected',()=>{
 const f=rotationFixture();
 f.rotations[0].proof.body.checkpointId='checkpoint-other';
 assert.equal(checkRotation(f).reason,'ROTATION_ROTATION_CONTEXT_CONFLICT');
});
test('previous history head cannot be substituted',()=>{
 const f=rotationFixture();
 f.rotations[0].proof.body.previousHistoryHead='f'.repeat(64);
 assert.equal(checkRotation(f).reason,'ROTATION_ROTATION_CONTEXT_CONFLICT');
});
test('rotation replay identifier is rejected',()=>{
 const f=rotationFixture();
 f.rotations.push(structuredClone(f.rotations[0]));
 assert.equal(checkRotation(f).reason,'INVALID_OR_REPLAYED_ROTATION_INPUT');
});
test('extraneous unused rotation proof rejected',()=>{
 const f=rotationFixture();
 const extra=structuredClone(f.rotations[0]);
 extra.proof.body.rotationId='unrelated-rotation';
 f.rotations.push(extra);
 assert.equal(checkRotation(f).reason,'UNCONSUMED_ROTATION_PROOF');
});
test('reviewer key cannot be used as new custodian key',()=>{
 const f=rotationFixture(),p=f.rotations[0].proof;
 p.body.newKeyPem=pem(owner);
 assert.equal(checkRotation(f).ok,false);
});
test('rotation proof cannot relabel custodian identity',()=>{
 const f=rotationFixture();
 f.rotations[0].proof.body.custodianId='custodian-b';
 assert.equal(checkRotation(f).reason,'ROTATION_ROTATION_CONTEXT_CONFLICT');
});
test('old/new same key is invalid rotation',()=>{
 const f=rotationFixture(),p=f.rotations[0].proof;
 p.body.newKeyPem=p.body.oldKeyPem;
 assert.equal(checkRotation(f).reason,'ROTATION_INVALID_ROTATION_INPUT');
});
test('rotation cannot be declared at the first checkpoint',()=>{
 const f=rotationFixture();
 f.rotations[0].atSequence=1;
 assert.equal(checkRotation(f).ok,false);
});
test('independently pinned floor still detects rollback after rotation',()=>{
 const f=rotationFixture(),r=checkRotation(f);
 assert.equal(verifyAuditCheckpointSuccession([f.history[0]],
  r.candidate.position,[]).reason,'AUDIT_HISTORY_ROLLBACK');
});
test('valid rotation proof never authorizes execution',()=>{
 const f=rotationFixture(),p=f.rotations[0].proof;
 const expected={namespace,custodianId:'custodian-a',oldKeyPem:pem(custodianA),
  newKeyPem:pem(custodianC),atSequence:2,
  previousHistoryHead:p.body.previousHistoryHead,checkpointId:p.body.checkpointId};
 const r=verifyCustodianRotation(p,f.history[1].policy,f.history[1].policyPin,expected);
 assert.equal(r.ok,true);assert.equal(r.authorized,false);
});
test('malformed input is rejected without signing anything',()=>{
 assert.throws(()=>custodianRotationPayload({},'custodian-a','OLD_CUSTODIAN'),
  /INVALID_CUSTODIAN_ROTATION_PAYLOAD/);
 const f=rotationFixture();f.rotations=null;
 assert.equal(checkRotation(f).ok,false);
});
