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
import {custodianRotationPayload} from '../src/cas-custodian-rotation.mjs';
import {verifyCustodianKeyLifecycle} from '../src/cas-custodian-lifecycle.mjs';
import {INITIAL_CUSTODIAN_REVOCATION_POSITION as revGenesis} from '../src/cas-custodian-revocation.mjs';
import {emergencyQuarantinePayload,emergencyQuarantineEntryHash,verifyEmergencyQuarantineJournal,INITIAL_EMERGENCY_QUARANTINE_POSITION as emergencyGenesis} from '../src/cas-emergency-quarantine.mjs';
import {responsibilityHandoffPayload,responsibilityHandoffEntryHash,verifyEmergencyResponsibilityHandoffs,INITIAL_RESPONSIBILITY_HANDOFF_POSITION as handoffGenesis} from '../src/cas-responsibility-handoff.mjs';
import {handoffCheckpointPayload,handoffCheckpointHash,verifyHandoffCheckpointHistory,inspectHandoffWitnessConflict,INITIAL_HANDOFF_CHECKPOINT_POSITION as cpGenesis} from '../src/cas-handoff-checkpoints.mjs';

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

function setup(){
 const f=rotationFixture(),lifecycle=verifyCustodianKeyLifecycle(
  f.history,f.rotations,historyGenesis);
 assert.equal(lifecycle.ok,true);
 const retired=lifecycle.candidate.transitions.find(t=>t.action==='RETIRED_ROTATED');
 assert.ok(retired);
 const p=policy(),policyPin={version:p.version,digest:keyQuorumPolicyDigest(p)};
 const body={schema:'NEO-045-CUSTODIAN-REVOCATION-v1',namespace,
  sequence:1,previousHash:revGenesis.head,revocationId:'revoke-045',
  custodianId:retired.custodianId,keyFingerprint:retired.fingerprint,
  retiredAtSequence:retired.sequence,
  lifecycleDigest:lifecycle.candidate.lifecycleDigest,
  historyPosition:lifecycle.candidate.position,
  policyDigest:policyPin.digest,action:'REVOKE_RETIRED_HOLD'};
 const reviews=[['review-owner','OWNER',owner],['review-security','SECURITY',security]]
  .map(([reviewerId,role,k])=>({reviewerId,signature:sign(null,
  custodianRevocationPayload(body,reviewerId,role),k.privateKey).toString('base64')}));
 const entry={body,reviews,hash:custodianRevocationEntryHash(body,reviews)};
 return {...f,p,policyPin,entries:[entry],lifecycle};
}
const checkRevocation=(f,floor=revGenesis,overridePin=null)=>verifyCustodianRevocationJournal(
 f.history,f.rotations,historyGenesis,overridePin,f.entries,f.p,f.policyPin,floor);

const successor=generateKeyPairSync('ed25519');
const successor2=generateKeyPairSync('ed25519');
function incident(){
 const f=rotationFixture();
 const verified=verifyCustodianKeyLifecycle(f.history,f.rotations,historyGenesis);
 assert.equal(verified.ok,true);
 const snapshot=verified.candidate,p=policy(),policyPin={
  version:p.version,digest:keyQuorumPolicyDigest(p)};
 const selected=snapshot.active.find(x=>x.custodianId==='custodian-a');
 const body={schema:'NEO-046-EMERGENCY-QUARANTINE-v1',namespace,
  sequence:1,previousHash:emergencyGenesis.head,incidentId:'incident-046',
  custodianId:'custodian-a',activeKeyFingerprint:selected.fingerprint,
  successorCustodianId:'custodian-successor',
  successorPublicKeyPem:pem(successor),
  lifecycleDigest:snapshot.lifecycleDigest,
  historyPosition:snapshot.position,policyDigest:policyPin.digest,
  action:'QUARANTINE_ACTIVE_KEY_HOLD'};
 const signReview=(r,role,k,b=body)=>({
  reviewerId:r,signature:sign(null,emergencyQuarantinePayload(b,r,role),
   k.privateKey).toString('base64')});
 const reviews=[signReview('review-owner','OWNER',owner),
  signReview('review-security','SECURITY',security)];
 const successorSignature=sign(null,emergencyQuarantinePayload(
  body,'custodian-successor','SUCCESSOR'),successor.privateKey).toString('base64');
 const entry={body,reviews,successorSignature,
  hash:emergencyQuarantineEntryHash(body,reviews,successorSignature)};
 return {...f,snapshot,p,policyPin,entries:[entry]};
}
const checkEmergency=(f,floor=emergencyGenesis,lifecyclePin=null)=>
 verifyEmergencyQuarantineJournal(f.history,f.rotations,historyGenesis,
 lifecyclePin,f.entries,f.p,f.policyPin,floor);

function handoffFixture(){
 const f=incident(),q=f.entries[0],bq=q.body;
 const body={schema:'NEO-047-RESPONSIBILITY-HANDOFF-v1',namespace,
  sequence:1,previousHash:handoffGenesis.head,handoffId:'handoff-047',
  incidentId:bq.incidentId,quarantineEntryHash:q.hash,
  quarantinePosition:{count:1,head:q.hash},
  originalCustodianId:bq.custodianId,
  originalKeyFingerprint:bq.activeKeyFingerprint,
  successorCustodianId:bq.successorCustodianId,
  successorKeyFingerprint:sha(Buffer.from(
   successor.publicKey.export({type:'spki',format:'der'}))),
  lifecycleDigest:bq.lifecycleDigest,policyDigest:bq.policyDigest,
  action:'REVIEWED_RESPONSIBILITY_HANDOFF_HOLD'};
 const reviewers=[['review-owner','OWNER',owner],['review-security','SECURITY',security]]
  .map(([reviewerId,role,k])=>({reviewerId,signature:sign(null,
   responsibilityHandoffPayload(body,reviewerId,role),
   k.privateKey).toString('base64')}));
 const successorAcceptance=sign(null,responsibilityHandoffPayload(
  body,'custodian-successor','SUCCESSOR'),successor.privateKey).toString('base64');
 const entry={body,reviews:reviewers,successorAcceptance,
  hash:responsibilityHandoffEntryHash(body,reviewers,successorAcceptance)};
 return {...f,handoffs:[entry]};
}
const verifyHandoff=(f,emergencyFloor=emergencyGenesis,handoffFloor=handoffGenesis,
 lifecyclePin=null)=>verifyEmergencyResponsibilityHandoffs(
 f.history,f.rotations,historyGenesis,lifecyclePin,f.entries,f.p,f.policyPin,
 emergencyFloor,f.handoffs,handoffFloor);

const witnessA=generateKeyPairSync('ed25519'),witnessB=generateKeyPairSync('ed25519');
function checkpointFixture(){
 const f=handoffFixture();
 const evidence=verifyHandoff(f);
 assert.equal(evidence.ok,true);
 const source={history:f.history,rotations:f.rotations,historyFloor:historyGenesis,
  lifecyclePin:null,quarantines:f.entries,policy:f.p,policyPin:f.policyPin,
  trustedQuarantineFloor:emergencyGenesis,handoffs:f.handoffs,
  trustedHandoffFloor:handoffGenesis};
 const body={schema:'NEO-048-HANDOFF-CHECKPOINT-v1',namespace,
  checkpointId:'checkpoint-048',sequence:1,previousHash:cpGenesis.head,
  handoffPosition:evidence.candidate.position,
  quarantinePosition:evidence.candidate.quarantinePosition,
  policyDigest:keyQuorumPolicyDigest(f.p)};
 const witnesses=[['witness-a',witnessA],['witness-b',witnessB]]
  .map(([witnessId,k])=>({witnessId,signature:sign(null,
   handoffCheckpointPayload(body,witnessId),k.privateKey).toString('base64')}));
 const seal={body,witnesses,hash:handoffCheckpointHash(body,witnesses)};
 const witnessTrust=[['witness-a',witnessA],['witness-b',witnessB]]
  .map(([witnessId,k])=>({namespace,witnessId,publicKeyPem:pem(k),
    status:'ACTIVE',expectedCheckpointId:body.checkpointId}));
 return {source,seal,witnessTrust,expectedWitnessIds:['witness-a','witness-b']};
}
function successorCheckpoint(first,id='checkpoint-049'){
 const body={...first.seal.body,checkpointId:id,sequence:2,
  previousHash:first.seal.hash};
 const witnesses=[['witness-a',witnessA],['witness-b',witnessB]]
 .map(([witnessId,k])=>({witnessId,signature:sign(null,
  handoffCheckpointPayload(body,witnessId),k.privateKey).toString('base64')}));
 return {source:first.source,seal:{body,witnesses,hash:handoffCheckpointHash(body,witnesses)},
  witnessTrust:first.witnessTrust.map(t=>({...t,expectedCheckpointId:id})),
  expectedWitnessIds:[...first.expectedWitnessIds]};
}
const verifyCheckpoints=(rows,pin=cpGenesis)=>verifyHandoffCheckpointHistory(rows,pin);
test('two independent witnesses sign a fully reverified handoff checkpoint',()=>{
 const f=checkpointFixture(),r=verifyCheckpoints([f]);
 assert.equal(r.ok,true);assert.equal(r.authorized,false);
 assert.equal(r.phase,'HANDOFF_CHECKPOINT_HISTORY_VERIFIED_HOLD');
 assert.equal(r.candidate.position.count,1);
});
test('two consecutive signed checkpoints verify against full original evidence',()=>{
 const a=checkpointFixture(),b=successorCheckpoint(a);
 const r=verifyCheckpoints([a,b]);assert.equal(r.ok,true);
 assert.equal(r.candidate.position.count,2);
});
test('an externally pinned checkpoint head validates the same history',()=>{
 const a=checkpointFixture();
 assert.equal(verifyCheckpoints([a],{count:1,head:a.seal.hash}).ok,true);
});
test('truncation below externally trusted position fails',()=>{
 const a=checkpointFixture();
 assert.equal(verifyCheckpoints([],{count:1,head:a.seal.hash}).reason,
  'CHECKPOINT_ROLLBACK');
});
test('externally pinned alternate checkpoint hash fails',()=>{
 const a=checkpointFixture();
 assert.equal(verifyCheckpoints([a],{count:1,head:'f'.repeat(64)}).reason,
  'TRUSTED_CHECKPOINT_FORK');
});
test('duplicate checkpoint id across history is rejected',()=>{
 const a=checkpointFixture(),b=successorCheckpoint(a,a.seal.body.checkpointId);
 assert.equal(verifyCheckpoints([a,b]).reason,'CHECKPOINT_ID_REPLAY');
});
test('broken predecessor chain fails',()=>{
 const a=checkpointFixture(),b=successorCheckpoint(a);
 b.seal.body.previousHash=cpGenesis.head;
 assert.equal(verifyCheckpoints([a,b]).reason,'BROKEN_CHECKPOINT_CHAIN');
});
test('missing mandatory witness is rejected',()=>{
 const a=checkpointFixture();a.seal.witnesses.pop();
 assert.equal(verifyCheckpoints([a]).reason,'INVALID_WITNESS_ROSTER');
});
test('duplicate witness signature does not satisfy two independent witnesses',()=>{
 const a=checkpointFixture();a.seal.witnesses[1]={...a.seal.witnesses[0]};
 assert.equal(verifyCheckpoints([a]).reason,'DUPLICATE_OR_INVALID_WITNESS');
});
test('shared witness signing key cannot stand for two identities',()=>{
 const a=checkpointFixture();a.witnessTrust[1].publicKeyPem=pem(witnessA);
 assert.equal(verifyCheckpoints([a]).reason,'NONINDEPENDENT_WITNESS_KEY');
});
test('reviewer key cannot also be a checkpoint witness key',()=>{
 const a=checkpointFixture();a.witnessTrust[0].publicKeyPem=pem(owner);
 assert.equal(verifyCheckpoints([a]).reason,'NONINDEPENDENT_WITNESS_KEY');
});
test('successor key cannot also be a checkpoint witness key',()=>{
 const a=checkpointFixture();a.witnessTrust[0].publicKeyPem=pem(successor);
 assert.equal(verifyCheckpoints([a]).reason,'NONINDEPENDENT_WITNESS_KEY');
});
test('forged witness signature fails',()=>{
 const a=checkpointFixture(),body=a.seal.body;
 a.seal.witnesses[0].signature=sign(null,
  handoffCheckpointPayload(body,'witness-a'),forged.privateKey).toString('base64');
 assert.equal(verifyCheckpoints([a]).reason,'INVALID_WITNESS_SIGNATURE');
});
test('revoked witness is not trusted',()=>{
 const a=checkpointFixture();a.witnessTrust[0].status='REVOKED';
 assert.equal(verifyCheckpoints([a]).reason,'INVALID_OR_REVOKED_WITNESS');
});
test('original successor acceptance forgery is independently refused',()=>{
 const a=checkpointFixture();a.source.handoffs[0].successorAcceptance='a'.repeat(88);
 assert.match(verifyCheckpoints([a]).reason,/^HANDOFF_/);
});
test('original archive bytes tampered invalidates signed checkpoint',()=>{
 const a=checkpointFixture();
 a.source.history[0].evidence[0].left[0].post.replicas[0].artifacts[0].base64='YmFk';
 assert.match(verifyCheckpoints([a]).reason,/^HANDOFF_/);
});
test('tampered checkpoint digest is refused',()=>{
 const a=checkpointFixture();a.seal.hash='f'.repeat(64);
 assert.equal(verifyCheckpoints([a]).reason,'TAMPERED_CHECKPOINT_HASH');
});
test('witness identity changing key across checkpoints is refused',()=>{
 const a=checkpointFixture(),b=successorCheckpoint(a),other=generateKeyPairSync('ed25519');
 b.witnessTrust[0].publicKeyPem=pem(other);
 b.seal.witnesses[0].signature=sign(null,
  handoffCheckpointPayload(b.seal.body,'witness-a'),other.privateKey).toString('base64');
 b.seal.hash=handoffCheckpointHash(b.seal.body,b.seal.witnesses);
 assert.equal(verifyCheckpoints([a,b]).reason,'WITNESS_IDENTITY_OR_KEY_CHANGED');
});
test('same key can sign two contradictory claims yielding conflict evidence only',()=>{
 const a=checkpointFixture(),body=a.seal.body;
 const other={...body,handoffPosition:{count:1,head:'f'.repeat(64)}};
 const x={body,witness:a.seal.witnesses[0]};
 const y={body:other,witness:{witnessId:'witness-a',signature:sign(null,
  handoffCheckpointPayload(other,'witness-a'),witnessA.privateKey).toString('base64')}};
 const r=inspectHandoffWitnessConflict(x,y,a.witnessTrust[0],cpGenesis);
 assert.equal(r.phase,'HANDOFF_WITNESS_CONFLICT_HOLD');
 assert.equal(r.authorized,false);assert.equal(r.candidate.states.length,2);
});
test('identical signed statements do not create false conflict',()=>{
 const a=checkpointFixture(),claim={body:a.seal.body,witness:a.seal.witnesses[0]};
 assert.equal(inspectHandoffWitnessConflict(claim,claim,a.witnessTrust[0],cpGenesis).phase,
  'NO_PROVEN_CONFLICT');
});
test('forged conflicting statement is not credible conflict proof',()=>{
 const a=checkpointFixture(),other={...a.seal.body,
  handoffPosition:{count:1,head:'f'.repeat(64)}};
 const r=inspectHandoffWitnessConflict(
  {body:a.seal.body,witness:a.seal.witnesses[0]},
  {body:other,witness:{witnessId:'witness-a',signature:sign(null,
    handoffCheckpointPayload(other,'witness-a'),forged.privateKey).toString('base64')}},
  a.witnessTrust[0],cpGenesis);
 assert.equal(r.reason,'UNVERIFIED_WITNESS_CLAIM');
});
test('different trusted predecessor blocks conflict classification',()=>{
 const a=checkpointFixture(),claim={body:a.seal.body,witness:a.seal.witnesses[0]};
 assert.equal(inspectHandoffWitnessConflict(claim,claim,a.witnessTrust[0],
  {count:0,head:'f'.repeat(64)}).reason,'UNRELATED_OR_UNTRUSTED_STATEMENTS');
});
test('invalid malformed inputs are rejected',()=>{
 assert.equal(verifyCheckpoints(null).ok,false);
 assert.throws(()=>handoffCheckpointPayload({},'witness-a'),/INVALID_HANDOFF_CHECKPOINT/);
});
