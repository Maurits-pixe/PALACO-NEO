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
test('complete emergency succession proof is nonauthorizing',()=>{
 const f=handoffFixture(),r=verifyHandoff(f);
 assert.equal(r.ok,true);assert.equal(r.authorized,false);
 assert.equal(r.phase,'RESPONSIBILITY_HANDOFF_EVIDENCE_HOLD');
 assert.equal(r.candidate.handoffs[0].status,'RESPONSIBILITY_CLAIM_REVIEWED_HOLD');
});
test('independent lifecycle pin accepted only when exact',()=>{
 const f=handoffFixture(),v=f.snapshot;
 assert.equal(verifyHandoff(f,emergencyGenesis,handoffGenesis,
  {count:v.position.count,head:v.position.head,digest:v.lifecycleDigest}).ok,true);
 assert.equal(verifyHandoff(f,emergencyGenesis,handoffGenesis,
  {count:v.position.count,head:v.position.head,digest:'f'.repeat(64)}).ok,false);
});
test('unsigned successor responsibility cannot transfer custody',()=>{
 const f=handoffFixture();f.handoffs[0].successorAcceptance='';
 assert.equal(verifyHandoff(f).reason,'INVALID_RESPONSIBILITY_ACCEPTANCE');
});
test('forged successor responsibility signature is refused',()=>{
 const f=handoffFixture(),b=f.handoffs[0].body;
 f.handoffs[0].successorAcceptance=sign(null,
  responsibilityHandoffPayload(b,'custodian-successor','SUCCESSOR'),
  forged.privateKey).toString('base64');
 assert.equal(verifyHandoff(f).reason,'INVALID_RESPONSIBILITY_ACCEPTANCE');
});
test('OWNER review forgery is rejected',()=>{
 const f=handoffFixture(),b=f.handoffs[0].body;
 f.handoffs[0].reviews[0].signature=sign(null,
  responsibilityHandoffPayload(b,'review-owner','OWNER'),
  forged.privateKey).toString('base64');
 assert.equal(verifyHandoff(f).reason,'INVALID_HANDOFF_REVIEW_SIGNATURE');
});
test('duplicated OWNER reviewer cannot impersonate SECURITY',()=>{
 const f=handoffFixture();f.handoffs[0].reviews[1]={...f.handoffs[0].reviews[0]};
 assert.equal(verifyHandoff(f).reason,'INVALID_OR_DUPLICATE_HANDOFF_REVIEWER');
});
test('missing SECURITY signature prevents handoff',()=>{
 const f=handoffFixture();f.handoffs[0].reviews.pop();
 assert.equal(verifyHandoff(f).reason,'BROKEN_HANDOFF_CHAIN');
});
test('handoff must bind exact quarantine entry hash',()=>{
 const f=handoffFixture();f.handoffs[0].body.quarantineEntryHash='f'.repeat(64);
 assert.equal(verifyHandoff(f).reason,'HANDOFF_CONTEXT_OR_QUARANTINE_CONFLICT');
});
test('handoff must bind exact quarantine position',()=>{
 const f=handoffFixture();f.handoffs[0].body.quarantinePosition.head='f'.repeat(64);
 assert.equal(verifyHandoff(f).reason,'HANDOFF_CONTEXT_OR_QUARANTINE_CONFLICT');
});
test('handoff must bind original active custodian and key',()=>{
 const f=handoffFixture();f.handoffs[0].body.originalCustodianId='another-custodian';
 assert.equal(verifyHandoff(f).reason,'HANDOFF_CONTEXT_OR_QUARANTINE_CONFLICT');
});
test('handoff cannot nominate different successor key',()=>{
 const f=handoffFixture();f.handoffs[0].body.successorKeyFingerprint='f'.repeat(64);
 assert.equal(verifyHandoff(f).reason,'HANDOFF_CONTEXT_OR_QUARANTINE_CONFLICT');
});
test('handoff does not permit successor activation action',()=>{
 const f=handoffFixture();f.handoffs[0].body.action='ACTIVATE_SUCCESSOR';
 assert.equal(verifyHandoff(f).reason,'BROKEN_HANDOFF_CHAIN');
});
test('tampered handoff hash fails closed',()=>{
 const f=handoffFixture();f.handoffs[0].hash='f'.repeat(64);
 assert.equal(verifyHandoff(f).reason,'TAMPERED_HANDOFF_ENTRY');
});
test('modified NEO-046 quarantine evidence is independently rejected',()=>{
 const f=handoffFixture();f.entries[0].reviews[0].signature='a'.repeat(88);
 assert.match(verifyHandoff(f).reason,/^QUARANTINE_/);
});
test('modified original NEO-036 bytes invalidate responsibility proofs',()=>{
 const f=handoffFixture();
 f.history[0].evidence[0].left[0].post.replicas[0].artifacts[0].base64='YmFk';
 assert.match(verifyHandoff(f).reason,/^QUARANTINE_/);
});
test('truncated handoff evidence is not silently accepted',()=>{
 const f=handoffFixture();f.handoffs=[];
 assert.equal(verifyHandoff(f).reason,'INCOMPLETE_OR_INVALID_HANDOFF_INPUT');
});
test('trusted handoff floor rejects conflicting history',()=>{
 const f=handoffFixture();
 assert.equal(verifyHandoff(f,emergencyGenesis,{count:1,head:'f'.repeat(64)}).reason,
  'HANDOFF_FORK');
});
test('trusted quarantine floor detects altered externally pinned root',()=>{
 const f=handoffFixture();
 assert.equal(verifyHandoff(f,{count:1,head:'f'.repeat(64)}).reason,
  'QUARANTINE_EMERGENCY_FORK');
});
test('empty validated sequence grants no authority',()=>{
 const f=handoffFixture();f.entries=[];f.handoffs=[];
 const r=verifyHandoff(f);
 assert.equal(r.ok,true);assert.equal(r.authorized,false);
 assert.equal(r.candidate.handoffs.length,0);
});
test('malformed handoff inputs and missing body are denied',()=>{
 const f=handoffFixture();f.handoffs=null;
 assert.equal(verifyHandoff(f).ok,false);
 assert.throws(()=>responsibilityHandoffPayload({},'review-owner','OWNER'),
 /INVALID_RESPONSIBILITY_HANDOFF_PAYLOAD/);
});
