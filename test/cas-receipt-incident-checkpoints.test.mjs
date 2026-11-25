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
import {handoffConflictReviewPayload,handoffConflictEntryHash,verifyHandoffConflictJournal,INITIAL_HANDOFF_CONFLICT_POSITION as conflictGenesis} from '../src/cas-handoff-conflict-journal.mjs';
import {escalationCheckpointPayload,escalationCheckpointHash,verifyEscalationCheckpointHistory,inspectEscalationCustodianConflict,INITIAL_ESCALATION_CHECKPOINT_POSITION as escGenesis} from '../src/cas-escalation-checkpoints.mjs';
import {escalationEvidenceManifest,escalationEvidenceTransferDigest,escalationEvidenceReceiptPayload,verifyEscalationEvidenceTransfer} from '../src/cas-escalation-evidence-transfer.mjs';
import {escalationReceiptSuccessionEntryHash,verifyEscalationReceiptSuccession,inspectArchiveRecipientContradiction,INITIAL_RECEIPT_SUCCESSION_POSITION as receiptGenesis} from '../src/cas-escalation-receipt-succession.mjs';
import {receiptCheckpointPayload,receiptCheckpointHash,verifyReceiptCheckpointHistory,inspectReceiptCheckpointEquivocation,INITIAL_RECEIPT_CHECKPOINT_POSITION as checkpointGenesis053} from '../src/cas-receipt-checkpoints.mjs';
import {receiptIncidentReviewPayload,receiptIncidentEntryHash,verifyReceiptIncidentJournal,INITIAL_RECEIPT_INCIDENT_POSITION as incidentGenesis054} from '../src/cas-receipt-incident-journal.mjs';
import {incidentCheckpointPayload,incidentCheckpointHash,verifyIncidentCheckpointHistory,inspectIncidentCheckpointConflict,INITIAL_INCIDENT_CHECKPOINT_POSITION as cpGenesis055} from '../src/cas-incident-checkpoints.mjs';
import {incidentEvidenceManifest,incidentEvidenceTransferDigest,incidentEvidenceReceiptPayload,verifyIncidentEvidenceTransfer} from '../src/cas-incident-evidence-transfer.mjs';
import {incidentTransferReceiptEntryHash,verifyIncidentTransferReceiptHistory,inspectIncidentArchiveContradiction,INITIAL_INCIDENT_TRANSFER_RECEIPT_POSITION as register057Genesis} from '../src/cas-incident-transfer-receipts.mjs';
import {incidentReceiptCheckpointPayload,incidentReceiptCheckpointHash,verifyIncidentReceiptCheckpointHistory,inspectIncidentReceiptCheckpointConflict,INITIAL_INCIDENT_RECEIPT_CHECKPOINT_POSITION as register058Genesis} from '../src/cas-incident-receipt-checkpoints.mjs';
import {incidentReceiptConflictReviewPayload,incidentReceiptConflictEntryHash,verifyIncidentReceiptConflictJournal,INITIAL_INCIDENT_RECEIPT_CONFLICT_POSITION as register059Genesis} from '../src/cas-incident-receipt-conflicts.mjs';
import {receiptIncidentCheckpointPayload,receiptIncidentCheckpointHash,verifyReceiptIncidentCheckpointHistory,inspectReceiptIncidentCheckpointConflict,INITIAL_RECEIPT_INCIDENT_CHECKPOINT_POSITION as register060Genesis} from '../src/cas-receipt-incident-checkpoints.mjs';

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

function conflictFixture(suffix=''){
 const canonical=checkpointFixture();
 const body=canonical.seal.body;
 const rightBody={...body,handoffPosition:{count:body.handoffPosition.count,
   head:'f'.repeat(64)}};
 const source={left:{body,witness:canonical.seal.witnesses[0]},
  right:{body:rightBody,witness:{witnessId:'witness-a',
   signature:sign(null,handoffCheckpointPayload(rightBody,'witness-a'),
    witnessA.privateKey).toString('base64')}},
  trust:canonical.witnessTrust[0],trustedPredecessor:cpGenesis,
  canonicalHistory:[canonical],canonicalFloor:cpGenesis};
 const verdict=inspectHandoffWitnessConflict(source.left,source.right,
  source.trust,source.trustedPredecessor);
 assert.equal(verdict.phase,'HANDOFF_WITNESS_CONFLICT_HOLD');
 const p=policy(),pin={version:p.version,digest:keyQuorumPolicyDigest(p)};
 const b={schema:'NEO-049-HANDOFF-CONFLICT-ESCALATION-v1',
  namespace,sequence:1,previousHash:conflictGenesis.head,
  caseId:'case-049'+suffix,checkpointId:body.checkpointId,
  checkpointSequence:1,witnessId:'witness-a',
  conflictDigest:verdict.candidate.evidenceDigest,
  canonicalCheckpointHead:canonical.seal.hash,
  policyDigest:pin.digest,action:'ESCALATE_SIGNED_CONFLICT_HOLD'};
 const reviews=[['review-owner','OWNER',owner],['review-security','SECURITY',security]]
  .map(([reviewerId,role,k])=>({reviewerId,signature:sign(null,
   handoffConflictReviewPayload(b,reviewerId,role),
   k.privateKey).toString('base64')}));
 const entry={body:b,reviews,hash:handoffConflictEntryHash(b,reviews)};
 return {entries:[entry],evidence:[source],p,pin};
}
const checkConflict=(f,floor=conflictGenesis)=>verifyHandoffConflictJournal(
 f.entries,f.evidence,f.p,f.pin,floor);

const auditA=generateKeyPairSync('ed25519'),auditB=generateKeyPairSync('ed25519');
function checkpoint050(){
 const f=conflictFixture();
 const result=checkConflict(f);
 assert.equal(result.ok,true);
 const source={entries:f.entries,evidence:f.evidence,policy:f.p,
  policyPin:f.pin,trustedConflictFloor:conflictGenesis};
 const body={schema:'NEO-050-ESCALATION-CHECKPOINT-v1',
  namespace,checkpointId:'checkpoint-050',sequence:1,
  previousHash:escGenesis.head,escalationPosition:result.candidate.position,
  policyDigest:f.pin.digest};
 const witnesses=[['audit-a',auditA],['audit-b',auditB]]
  .map(([custodianId,k])=>({custodianId,signature:sign(null,
  escalationCheckpointPayload(body,custodianId),k.privateKey).toString('base64')}));
 const custodianTrust=[['audit-a',auditA],['audit-b',auditB]]
  .map(([custodianId,k])=>({namespace,custodianId,publicKeyPem:pem(k),
   status:'ACTIVE',expectedCheckpointId:body.checkpointId}));
 const seal={body,witnesses,hash:escalationCheckpointHash(body,witnesses)};
 return {source,seal,custodianTrust,expectedCustodianIds:['audit-a','audit-b']};
}
function next050(a,id='checkpoint-051'){
 const body={...a.seal.body,checkpointId:id,sequence:2,previousHash:a.seal.hash};
 const witnesses=[['audit-a',auditA],['audit-b',auditB]]
  .map(([custodianId,k])=>({custodianId,signature:sign(null,
    escalationCheckpointPayload(body,custodianId),k.privateKey).toString('base64')}));
 return {source:a.source,
  seal:{body,witnesses,hash:escalationCheckpointHash(body,witnesses)},
  custodianTrust:a.custodianTrust.map(x=>({...x,expectedCheckpointId:id})),
  expectedCustodianIds:[...a.expectedCustodianIds]};
}
const check050=(rows,floor=escGenesis)=>verifyEscalationCheckpointHistory(rows,floor);

const archiveA=generateKeyPairSync('ed25519'),archiveB=generateKeyPairSync('ed25519');
function package051(two=false){
 const first=checkpoint050();
 const records=two?[first,next050(first)]:[first];
 const bundle={schema:'NEO-051-ESCALATION-EVIDENCE-BUNDLE-v1',
 namespace,transferId:'transfer-051',trustedCheckpointFloor:escGenesis,
 records,manifest:escalationEvidenceManifest(records)};
 const receipts=[['archive-a',archiveA],['archive-b',archiveB]]
  .map(([recipientId,k])=>({recipientId,signature:sign(null,
   escalationEvidenceReceiptPayload(bundle,recipientId),
   k.privateKey).toString('base64')}));
 const trusts=[['archive-a',archiveA],['archive-b',archiveB]]
  .map(([recipientId,k])=>({namespace,recipientId,publicKeyPem:pem(k),
   status:'ACTIVE',expectedTransferId:bundle.transferId}));
 return {bundle,receipts,trusts,ids:['archive-a','archive-b']};
}
const check051=(f,pin=null)=>verifyEscalationEvidenceTransfer(
 f.bundle,f.receipts,f.trusts,f.ids,pin);

function transfer052(first,transferId='transfer-052',addCheckpoint=false){
 const records=addCheckpoint?
  [...first.bundle.records,next050(first.bundle.records.at(-1))]:
  [...first.bundle.records];
 const bundle={...first.bundle,transferId,records,
  manifest:escalationEvidenceManifest(records)};
 const receipts=[['archive-a',archiveA],['archive-b',archiveB]]
  .map(([recipientId,k])=>({recipientId,signature:sign(null,
   escalationEvidenceReceiptPayload(bundle,recipientId),
   k.privateKey).toString('base64')}));
 const trusts=first.trusts.map(t=>({...t,expectedTransferId:transferId}));
 return {bundle,receipts,trusts,expectedRecipientIds:[...first.ids],
  pinnedTransferDigest:null};
}
function entry052(transfer,sequence=1,previousHash=receiptGenesis.head){
 const r=verifyEscalationEvidenceTransfer(transfer.bundle,transfer.receipts,
  transfer.trusts,transfer.expectedRecipientIds,transfer.pinnedTransferDigest);
 assert.equal(r.ok,true);
 const body={schema:'NEO-052-RECEIPT-SUCCESSION-v1',
  sequence,previousHash,transferId:r.candidate.transferId,
  transferDigest:r.candidate.transferDigest,
  checkpointPosition:r.candidate.checkpointPosition};
 return {body,transfer,hash:escalationReceiptSuccessionEntryHash(body,transfer)};
}
function receiptHistory052(){
 const a=package051(),first=entry052(transfer052(a,'transfer-first'));
 const second=entry052(transfer052(a,'transfer-second'),2,first.hash);
 return [first,second];
}
const check052=(entries,floor=receiptGenesis)=>
 verifyEscalationReceiptSuccession(entries,floor);

const guardianA053=generateKeyPairSync('ed25519');
const guardianB053=generateKeyPairSync('ed25519');
function checkpoint053(){
 const receipts=receiptHistory052();
 const verified=verifyEscalationReceiptSuccession(receipts,receiptGenesis);
 assert.equal(verified.ok,true);
 const source={entries:receipts,trustedReceiptFloor:receiptGenesis};
 const body={schema:'NEO-053-RECEIPT-CHECKPOINT-v1',
  namespace,checkpointId:'receipt-checkpoint-053',sequence:1,
  previousHash:checkpointGenesis053.head,receiptPosition:verified.candidate.position};
 const attestations=[['guardian-a',guardianA053],['guardian-b',guardianB053]]
  .map(([custodianId,k])=>({custodianId,signature:sign(null,
   receiptCheckpointPayload(body,custodianId),k.privateKey).toString('base64')}));
 const seal={body,attestations,hash:receiptCheckpointHash(body,attestations)};
 const custodianTrust=[['guardian-a',guardianA053],['guardian-b',guardianB053]]
  .map(([custodianId,k])=>({namespace,custodianId,publicKeyPem:pem(k),
   status:'ACTIVE',expectedCheckpointId:body.checkpointId}));
 return {source,seal,custodianTrust,expectedCustodianIds:['guardian-a','guardian-b']};
}
function next053(a,id='receipt-checkpoint-054'){
 const body={...a.seal.body,checkpointId:id,sequence:2,previousHash:a.seal.hash};
 const attestations=[['guardian-a',guardianA053],['guardian-b',guardianB053]]
  .map(([custodianId,k])=>({custodianId,signature:sign(null,
   receiptCheckpointPayload(body,custodianId),k.privateKey).toString('base64')}));
 return {source:a.source,seal:{body,attestations,
  hash:receiptCheckpointHash(body,attestations)},
  custodianTrust:a.custodianTrust.map(t=>({...t,expectedCheckpointId:id})),
  expectedCustodianIds:[...a.expectedCustodianIds]};
}
const check053=(history,floor=checkpointGenesis053)=>
 verifyReceiptCheckpointHistory(history,floor);

function incident054(){
 const canonical=checkpoint053(),original=canonical.seal.body;
 const alternative={...original,receiptPosition:{count:2,head:'f'.repeat(64)}};
 const source={canonicalHistory:[canonical],canonicalFloor:checkpointGenesis053,
  trustedPredecessor:checkpointGenesis053,
  left:{body:original,attestation:canonical.seal.attestations[0]},
  right:{body:alternative,attestation:{custodianId:'guardian-a',
   signature:sign(null,receiptCheckpointPayload(alternative,'guardian-a'),
    guardianA053.privateKey).toString('base64')}},
  trust:canonical.custodianTrust[0]};
 const verdict=inspectReceiptCheckpointEquivocation(source.left,source.right,
   source.trust,source.trustedPredecessor);
 assert.equal(verdict.phase,'RECEIPT_CHECKPOINT_EQUIVOCATION_HOLD');
 const p=policy(),policyPin={version:p.version,digest:keyQuorumPolicyDigest(p)};
 const body={schema:'NEO-054-RECEIPT-INCIDENT-v1',namespace,sequence:1,
  previousHash:incidentGenesis054.head,incidentId:'incident-054',
  checkpointId:original.checkpointId,checkpointSequence:1,
  canonicalCheckpointHash:canonical.seal.hash,custodianId:'guardian-a',
  equivocationDigest:verdict.candidate.evidenceDigest,
  policyDigest:policyPin.digest,action:'ESCALATE_RECEIPT_EQUIVOCATION_HOLD'};
 const reviews=[['review-owner','OWNER',owner],['review-security','SECURITY',security]]
  .map(([reviewerId,role,k])=>({reviewerId,signature:sign(null,
   receiptIncidentReviewPayload(body,reviewerId,role),
   k.privateKey).toString('base64')}));
 const entry={body,reviews,hash:receiptIncidentEntryHash(body,reviews)};
 return {entries:[entry],evidence:[source],p,policyPin};
}
const check054=(f,floor=incidentGenesis054)=>verifyReceiptIncidentJournal(
 f.entries,f.evidence,f.p,f.policyPin,floor);

const audit055a=generateKeyPairSync('ed25519');
const audit055b=generateKeyPairSync('ed25519');
function checkpoint055(){
 const f=incident054(),verified=check054(f);
 assert.equal(verified.ok,true);
 const source={entries:f.entries,evidence:f.evidence,policy:f.p,
  policyPin:f.policyPin,trustedIncidentFloor:incidentGenesis054};
 const body={schema:'NEO-055-INCIDENT-CHECKPOINT-v1',
  namespace,checkpointId:'incident-checkpoint-055',sequence:1,
  previousHash:cpGenesis055.head,incidentPosition:verified.candidate.position};
 const attestations=[['incident-a',audit055a],['incident-b',audit055b]]
  .map(([custodianId,k])=>({custodianId,signature:sign(null,
   incidentCheckpointPayload(body,custodianId),k.privateKey).toString('base64')}));
 const seal={body,attestations,hash:incidentCheckpointHash(body,attestations)};
 const custodianTrust=[['incident-a',audit055a],['incident-b',audit055b]]
  .map(([custodianId,k])=>({namespace,custodianId,publicKeyPem:pem(k),
   status:'ACTIVE',expectedCheckpointId:body.checkpointId}));
 return {source,seal,custodianTrust,expectedCustodianIds:['incident-a','incident-b']};
}
function next055(first,id='incident-checkpoint-056'){
 const body={...first.seal.body,checkpointId:id,
  sequence:2,previousHash:first.seal.hash};
 const attestations=[['incident-a',audit055a],['incident-b',audit055b]]
  .map(([custodianId,k])=>({custodianId,signature:sign(null,
   incidentCheckpointPayload(body,custodianId),k.privateKey).toString('base64')}));
 return {source:first.source,seal:{body,attestations,
  hash:incidentCheckpointHash(body,attestations)},
  custodianTrust:first.custodianTrust.map(t=>({...t,expectedCheckpointId:id})),
  expectedCustodianIds:[...first.expectedCustodianIds]};
}
const check055=(records,pin=cpGenesis055)=>verifyIncidentCheckpointHistory(records,pin);

const vault056a=generateKeyPairSync('ed25519'),vault056b=generateKeyPairSync('ed25519');
function transfer056(two=false){
 const first=checkpoint055();
 const records=two?[first,next055(first)]:[first];
 const bundle={schema:'NEO-056-INCIDENT-EVIDENCE-TRANSFER-v1',
  namespace,transferId:'incident-transfer-056',
  trustedCheckpointFloor:cpGenesis055,records,
  manifest:incidentEvidenceManifest(records)};
 const receipts=[['vault-a',vault056a],['vault-b',vault056b]]
  .map(([recipientId,k])=>({recipientId,signature:sign(null,
   incidentEvidenceReceiptPayload(bundle,recipientId),
   k.privateKey).toString('base64')}));
 const trusts=[['vault-a',vault056a],['vault-b',vault056b]]
  .map(([recipientId,k])=>({namespace,recipientId,publicKeyPem:pem(k),
   status:'ACTIVE',expectedTransferId:bundle.transferId}));
 return {bundle,receipts,trusts,expectedRecipientIds:['vault-a','vault-b']};
}
const check056=(f,pin=null)=>verifyIncidentEvidenceTransfer(
 f.bundle,f.receipts,f.trusts,f.expectedRecipientIds,pin);

function scopedTransfer057(base,transferId='transfer-057',extend=false){
 const records=extend?[...base.bundle.records,
  next055(base.bundle.records.at(-1))]:[...base.bundle.records];
 const bundle={...base.bundle,transferId,records,
  manifest:incidentEvidenceManifest(records)};
 const receipts=[['vault-a',vault056a],['vault-b',vault056b]]
  .map(([recipientId,k])=>({recipientId,signature:sign(null,
   incidentEvidenceReceiptPayload(bundle,recipientId),
   k.privateKey).toString('base64')}));
 return {bundle,receipts,
  trusts:base.trusts.map(t=>({...t,expectedTransferId:transferId})),
  expectedRecipientIds:[...base.expectedRecipientIds],
  trustedTransferDigest:null};
}
function entry057(t,sequence=1,previousHash=register057Genesis.head){
 const v=verifyIncidentEvidenceTransfer(t.bundle,t.receipts,t.trusts,
  t.expectedRecipientIds,t.trustedTransferDigest);
 assert.equal(v.ok,true);
 const body={schema:'NEO-057-INCIDENT-TRANSFER-RECEIPT-v1',
  sequence,previousHash,transferId:v.candidate.transferId,
  transferDigest:v.candidate.transferDigest,
  checkpointPosition:v.candidate.checkpointPosition};
 return {body,transfer:t,hash:incidentTransferReceiptEntryHash(body,t)};
}
function history057(){
 const f=transfer056(),first=entry057(scopedTransfer057(f,'transfer-057a'));
 return [first,entry057(scopedTransfer057(f,'transfer-057b'),2,first.hash)];
}
const check057=(history,floor=register057Genesis)=>
 verifyIncidentTransferReceiptHistory(history,floor);

const witness058a=generateKeyPairSync('ed25519'),witness058b=generateKeyPairSync('ed25519');
function checkpoint058(){
 const entries=history057(),v=check057(entries);
 assert.equal(v.ok,true);
 const source={entries,trustedReceiptFloor:register057Genesis};
 const body={schema:'NEO-058-INCIDENT-RECEIPT-CHECKPOINT-v1',
  namespace,checkpointId:'receipt-058',sequence:1,
  previousHash:register058Genesis.head,receiptPosition:v.candidate.position};
 const attestations=[['witness-058-a',witness058a],['witness-058-b',witness058b]]
  .map(([custodianId,k])=>({custodianId,signature:sign(null,
   incidentReceiptCheckpointPayload(body,custodianId),k.privateKey).toString('base64')}));
 const seal={body,attestations,hash:incidentReceiptCheckpointHash(body,attestations)};
 const custodianTrust=[['witness-058-a',witness058a],['witness-058-b',witness058b]]
  .map(([custodianId,k])=>({namespace,custodianId,publicKeyPem:pem(k),
   status:'ACTIVE',expectedCheckpointId:body.checkpointId}));
 return {source,seal,custodianTrust,
  expectedCustodianIds:['witness-058-a','witness-058-b']};
}
function next058(first,id='receipt-059'){
 const body={...first.seal.body,checkpointId:id,
  sequence:2,previousHash:first.seal.hash};
 const attestations=[['witness-058-a',witness058a],['witness-058-b',witness058b]]
  .map(([custodianId,k])=>({custodianId,signature:sign(null,
   incidentReceiptCheckpointPayload(body,custodianId),k.privateKey).toString('base64')}));
 return {source:first.source,seal:{body,attestations,
  hash:incidentReceiptCheckpointHash(body,attestations)},
  custodianTrust:first.custodianTrust.map(t=>({...t,expectedCheckpointId:id})),
  expectedCustodianIds:[...first.expectedCustodianIds]};
}
const check058=(rows,floor=register058Genesis)=>
 verifyIncidentReceiptCheckpointHistory(rows,floor);

function incident059(){
 const original=checkpoint058(),canonical=original.seal.body;
 const other={...canonical,receiptPosition:{count:2,head:'f'.repeat(64)}};
 const source={canonicalHistory:[original],canonicalFloor:register058Genesis,
  trustedPredecessor:register058Genesis,
  left:{body:canonical,attestation:original.seal.attestations[0]},
  right:{body:other,attestation:{custodianId:'witness-058-a',
   signature:sign(null,incidentReceiptCheckpointPayload(other,'witness-058-a'),
    witness058a.privateKey).toString('base64')}},
  trust:original.custodianTrust[0]};
 const verdict=inspectIncidentReceiptCheckpointConflict(source.left,source.right,
  source.trust,source.trustedPredecessor);
 assert.equal(verdict.phase,'INCIDENT_RECEIPT_CHECKPOINT_CONFLICT_HOLD');
 const p=policy(),policyPin={version:p.version,digest:keyQuorumPolicyDigest(p)};
 const body={schema:'NEO-059-INCIDENT-RECEIPT-EQUIVOCATION-v1',
  namespace,sequence:1,previousHash:register059Genesis.head,
  incidentId:'incident-059',checkpointId:canonical.checkpointId,
  checkpointSequence:1,canonicalCheckpointHash:original.seal.hash,
  custodianId:'witness-058-a',conflictDigest:verdict.candidate.evidenceDigest,
  policyDigest:policyPin.digest,
  action:'ESCALATE_RECEIPT_CHECKPOINT_CONFLICT_HOLD'};
 const reviews=[['review-owner','OWNER',owner],['review-security','SECURITY',security]]
  .map(([reviewerId,role,k])=>({reviewerId,signature:sign(null,
   incidentReceiptConflictReviewPayload(body,reviewerId,role),
   k.privateKey).toString('base64')}));
 return {entries:[{body,reviews,hash:incidentReceiptConflictEntryHash(body,reviews)}],
  evidence:[source],p,policyPin};
}
const check059=(f,floor=register059Genesis)=>verifyIncidentReceiptConflictJournal(
 f.entries,f.evidence,f.p,f.policyPin,floor);

const audit060a=generateKeyPairSync('ed25519'),audit060b=generateKeyPairSync('ed25519');
function checkpoint060(){
 const f=incident059(),verified=check059(f);assert.equal(verified.ok,true);
 const source={entries:f.entries,evidence:f.evidence,policy:f.p,
  policyPin:f.policyPin,trustedIncidentFloor:register059Genesis};
 const body={schema:'NEO-060-RECEIPT-INCIDENT-CHECKPOINT-v1',
  namespace,checkpointId:'incident-checkpoint-060',sequence:1,
  previousHash:register060Genesis.head,incidentPosition:verified.candidate.position};
 const attestations=[['audit-060-a',audit060a],['audit-060-b',audit060b]]
  .map(([custodianId,k])=>({custodianId,signature:sign(null,
   receiptIncidentCheckpointPayload(body,custodianId),k.privateKey).toString('base64')}));
 const seal={body,attestations,hash:receiptIncidentCheckpointHash(body,attestations)};
 const custodianTrust=[['audit-060-a',audit060a],['audit-060-b',audit060b]]
  .map(([custodianId,k])=>({namespace,custodianId,publicKeyPem:pem(k),
   status:'ACTIVE',expectedCheckpointId:body.checkpointId}));
 return {source,seal,custodianTrust,expectedCustodianIds:['audit-060-a','audit-060-b']};
}
function next060(first,id='incident-checkpoint-061'){
 const body={...first.seal.body,checkpointId:id,sequence:2,
  previousHash:first.seal.hash};
 const attestations=[['audit-060-a',audit060a],['audit-060-b',audit060b]]
  .map(([custodianId,k])=>({custodianId,signature:sign(null,
   receiptIncidentCheckpointPayload(body,custodianId),k.privateKey).toString('base64')}));
 return {source:first.source,seal:{body,attestations,
  hash:receiptIncidentCheckpointHash(body,attestations)},
  custodianTrust:first.custodianTrust.map(t=>({...t,expectedCheckpointId:id})),
  expectedCustodianIds:[...first.expectedCustodianIds]};
}
const check060=(rows,floor=register060Genesis)=>
 verifyReceiptIncidentCheckpointHistory(rows,floor);
test('fully verified signed NEO-060 checkpoint remains nonauthorizing HOLD',()=>{
 const r=check060([checkpoint060()]);
 assert.equal(r.ok,true);assert.equal(r.authorized,false);
 assert.equal(r.phase,'RECEIPT_INCIDENT_CHECKPOINT_HISTORY_VERIFIED_HOLD');
});
test('two consecutive checkpoints can bind identical verified historic incident head',()=>{
 const a=checkpoint060(),b=next060(a);
 assert.equal(check060([a,b]).candidate.position.count,2);
});
test('witness array order cannot change checkpoint hash',()=>{
 const a=checkpoint060(),original=a.seal.hash;
 a.seal.attestations.reverse();
 assert.equal(receiptIncidentCheckpointHash(a.seal.body,a.seal.attestations),original);
 assert.equal(check060([a]).ok,true);
});
test('externally pinned exact checkpoint history verifies',()=>{
 const a=checkpoint060();
 assert.equal(check060([a],{count:1,head:a.seal.hash}).ok,true);
});
test('externally trusted floor refuses truncation',()=>{
 const a=checkpoint060();
 assert.equal(check060([],{count:1,head:a.seal.hash}).reason,
  'RECEIPT_INCIDENT_CHECKPOINT_ROLLBACK');
});
test('externally trusted floor refuses competing history',()=>{
 const a=checkpoint060();
 assert.equal(check060([a],{count:1,head:'f'.repeat(64)}).reason,
  'TRUSTED_RECEIPT_INCIDENT_CHECKPOINT_FORK');
});
test('replayed checkpoint ID is refused',()=>{
 const a=checkpoint060(),b=next060(a,a.seal.body.checkpointId);
 assert.equal(check060([a,b]).reason,'REPLAYED_RECEIPT_INCIDENT_CHECKPOINT_ID');
});
test('invalid previous checkpoint hash refused',()=>{
 const a=checkpoint060(),b=next060(a);
 b.seal.body.previousHash='f'.repeat(64);
 assert.equal(check060([a,b]).reason,'BROKEN_RECEIPT_INCIDENT_CHECKPOINT_CHAIN');
});
test('missing audit signature denies checkpoint',()=>{
 const a=checkpoint060();a.seal.attestations.pop();
 assert.equal(check060([a]).reason,'INVALID_CHECKPOINT_CUSTODIAN_ROSTER');
});
test('duplicate audit custodian cannot satisfy quorum',()=>{
 const a=checkpoint060();a.seal.attestations[1]={...a.seal.attestations[0]};
 assert.equal(check060([a]).reason,'INVALID_OR_DUPLICATE_CUSTODIAN_ATTESTATION');
});
test('two custodian identities with one public key are rejected',()=>{
 const a=checkpoint060();a.custodianTrust[1].publicKeyPem=pem(audit060a);
 assert.equal(check060([a]).reason,'NONINDEPENDENT_CHECKPOINT_CUSTODIAN');
});
test('OWNER reviewer key cannot double as independent custodian',()=>{
 const a=checkpoint060();a.custodianTrust[0].publicKeyPem=pem(owner);
 assert.equal(check060([a]).reason,'NONINDEPENDENT_CHECKPOINT_CUSTODIAN');
});
test('disputed witness key cannot double as independent audit custodian',()=>{
 const a=checkpoint060();a.custodianTrust[0].publicKeyPem=pem(witness058a);
 assert.equal(check060([a]).reason,'NONINDEPENDENT_CHECKPOINT_CUSTODIAN');
});
test('revoked audit key is denied',()=>{
 const a=checkpoint060();a.custodianTrust[0].status='REVOKED';
 assert.equal(check060([a]).reason,'INVALID_OR_REVOKED_CHECKPOINT_CUSTODIAN');
});
test('forged audit attestation denied',()=>{
 const a=checkpoint060();a.seal.attestations[0].signature=sign(null,
  receiptIncidentCheckpointPayload(a.seal.body,'audit-060-a'),
  forged.privateKey).toString('base64');
 assert.equal(check060([a]).reason,'FORGED_CHECKPOINT_ATTESTATION');
});
test('original OWNER review forgery invalidates NEO-060 checkpoint',()=>{
 const a=checkpoint060();a.source.entries[0].reviews[0].signature='a'.repeat(88);
 assert.match(check060([a]).reason,/^INCIDENT_/);
});
test('original archived evidence substitution invalidates NEO-060 checkpoint',()=>{
 const a=checkpoint060();
 a.source.evidence[0].canonicalHistory[0].source.entries[0]
 .transfer.bundle.records[0].source.evidence[0].canonicalHistory[0]
 .source.entries[0].transfer.bundle.records[0].source.evidence[0]
 .canonicalHistory[0].source.history[0].evidence[0].left[0]
 .post.replicas[0].artifacts[0].base64='YmFk';
 assert.match(check060([a]).reason,/^INCIDENT_/);
});
test('tampered checkpoint hash denied',()=>{
 const a=checkpoint060();a.seal.hash='f'.repeat(64);
 assert.equal(check060([a]).reason,'TAMPERED_RECEIPT_INCIDENT_CHECKPOINT_HASH');
});
test('audit identity cannot silently rotate to another public key',()=>{
 const a=checkpoint060(),b=next060(a),replacement=generateKeyPairSync('ed25519');
 b.custodianTrust[0].publicKeyPem=pem(replacement);
 b.seal.attestations[0].signature=sign(null,
  receiptIncidentCheckpointPayload(b.seal.body,'audit-060-a'),
  replacement.privateKey).toString('base64');
 b.seal.hash=receiptIncidentCheckpointHash(b.seal.body,b.seal.attestations);
 assert.equal(check060([a,b]).reason,'CHECKPOINT_CUSTODIAN_KEY_CHANGED');
});
test('same audit signer conflicting incident heads yields HOLD evidence only',()=>{
 const a=checkpoint060(),other={...a.seal.body,
  incidentPosition:{count:1,head:'f'.repeat(64)}};
 const left={body:a.seal.body,attestation:a.seal.attestations[0]};
 const right={body:other,attestation:{custodianId:'audit-060-a',
  signature:sign(null,receiptIncidentCheckpointPayload(other,'audit-060-a'),
   audit060a.privateKey).toString('base64')}};
 const r=inspectReceiptIncidentCheckpointConflict(left,right,
  a.custodianTrust[0],register060Genesis);
 assert.equal(r.phase,'RECEIPT_INCIDENT_CHECKPOINT_CONFLICT_HOLD');
 assert.equal(r.authorized,false);
});
test('matching signed incident statements do not establish conflict',()=>{
 const a=checkpoint060(),claim={body:a.seal.body,
  attestation:a.seal.attestations[0]};
 assert.equal(inspectReceiptIncidentCheckpointConflict(claim,claim,
  a.custodianTrust[0],register060Genesis).phase,'NO_PROVEN_CONFLICT');
});
test('forged contradictory statement is not credible conflict evidence',()=>{
 const a=checkpoint060(),other={...a.seal.body,
  incidentPosition:{count:1,head:'f'.repeat(64)}};
 const left={body:a.seal.body,attestation:a.seal.attestations[0]};
 const right={body:other,attestation:{custodianId:'audit-060-a',
  signature:sign(null,receiptIncidentCheckpointPayload(other,'audit-060-a'),
   forged.privateKey).toString('base64')}};
 assert.equal(inspectReceiptIncidentCheckpointConflict(left,right,
  a.custodianTrust[0],register060Genesis).reason,
  'UNVERIFIED_CHECKPOINT_CONFLICT_CLAIM');
});
test('wrong independently trusted predecessor makes claim unrelated',()=>{
 const a=checkpoint060(),claim={body:a.seal.body,
  attestation:a.seal.attestations[0]};
 assert.equal(inspectReceiptIncidentCheckpointConflict(claim,claim,
  a.custodianTrust[0],{count:0,head:'f'.repeat(64)}).reason,
  'UNRELATED_CHECKPOINT_CLAIMS');
});
test('malformed structures are denied',()=>{
 assert.equal(check060(null).ok,false);
 assert.throws(()=>receiptIncidentCheckpointPayload({},'audit-060-a'),
  /INVALID_RECEIPT_INCIDENT_CHECKPOINT/);
});
