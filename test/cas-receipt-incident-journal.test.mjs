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
test('real signed NEO-053 contradiction is escalated with HOLD only',()=>{
 const f=incident054(),r=check054(f);
 assert.equal(r.ok,true);assert.equal(r.authorized,false);
 assert.equal(r.phase,'RECEIPT_INCIDENT_ESCALATION_VERIFIED_HOLD');
 assert.equal(r.candidate.cases[0].status,'ESCALATED_HOLD');
});
test('exact independently pinned incident register history verifies',()=>{
 const f=incident054();
 assert.equal(check054(f,{count:1,head:f.entries[0].hash}).ok,true);
});
test('empty incident register remains nonauthorizing',()=>{
 const f=incident054();f.entries=[];f.evidence=[];
 const r=check054(f);assert.equal(r.ok,true);assert.equal(r.authorized,false);
});
test('trusted floor detects incident deletion',()=>{
 const f=incident054(),head=f.entries[0].hash;f.entries=[];f.evidence=[];
 assert.equal(check054(f,{count:1,head}).reason,'RECEIPT_INCIDENT_ROLLBACK');
});
test('trusted floor detects competing incident history',()=>{
 const f=incident054();
 assert.equal(check054(f,{count:1,head:'f'.repeat(64)}).reason,
 'RECEIPT_INCIDENT_FORK');
});
test('fake rival custodian signature fails original verification',()=>{
 const f=incident054(),right=f.evidence[0].right;
 right.attestation.signature=sign(null,
  receiptCheckpointPayload(right.body,'guardian-a'),
  forged.privateKey).toString('base64');
 assert.equal(check054(f).reason,'UNVERIFIED_RECEIPT_EQUIVOCATION');
});
test('identical receipt statements cannot be escalated as conflict',()=>{
 const f=incident054();f.evidence[0].right=structuredClone(f.evidence[0].left);
 assert.equal(check054(f).reason,'UNVERIFIED_RECEIPT_EQUIVOCATION');
});
test('original archival byte modification invalidates incident',()=>{
 const f=incident054();
 f.evidence[0].canonicalHistory[0].source.entries[0].transfer.bundle.records[0]
 .source.evidence[0].canonicalHistory[0].source.history[0]
 .evidence[0].left[0].post.replicas[0].artifacts[0].base64='YmFk';
 assert.match(check054(f).reason,/^CHECKPOINT_/);
});
test('tampered canonical checkpoint signature denied',()=>{
 const f=incident054();
 f.evidence[0].canonicalHistory[0].seal.attestations[0].signature='a'.repeat(88);
 assert.match(check054(f).reason,/^CHECKPOINT_/);
});
test('untrusted witness public key substitution cannot support conflict',()=>{
 const f=incident054();f.evidence[0].trust={...f.evidence[0].trust,publicKeyPem:pem(forged)};
 assert.equal(check054(f).reason,'CONFLICT_NOT_BOUND_TO_CANONICAL_CHECKPOINT');
});
test('canonical checkpoint hash substitution denied',()=>{
 const f=incident054();f.entries[0].body.canonicalCheckpointHash='f'.repeat(64);
 assert.equal(check054(f).reason,'CONFLICT_NOT_BOUND_TO_CANONICAL_CHECKPOINT');
});
test('changed conflict digest denied',()=>{
 const f=incident054();f.entries[0].body.equivocationDigest='f'.repeat(64);
 assert.equal(check054(f).reason,'INCIDENT_EVIDENCE_CONTEXT_CONFLICT');
});
test('forged OWNER signature denied',()=>{
 const f=incident054(),body=f.entries[0].body;
 f.entries[0].reviews[0].signature=sign(null,
  receiptIncidentReviewPayload(body,'review-owner','OWNER'),
  forged.privateKey).toString('base64');
 assert.equal(check054(f).reason,'INVALID_INCIDENT_REVIEW_SIGNATURE');
});
test('SECURITY signature missing denied',()=>{
 const f=incident054();f.entries[0].reviews.pop();
 assert.equal(check054(f).reason,'BROKEN_INCIDENT_REGISTER');
});
test('duplicate reviewer cannot impersonate SECURITY',()=>{
 const f=incident054();
 f.entries[0].reviews[1]={...f.entries[0].reviews[0]};
 assert.equal(check054(f).reason,'INVALID_OR_DUPLICATE_INCIDENT_REVIEW');
});
test('review policy pin substitution denied',()=>{
 const f=incident054();f.policyPin.digest='f'.repeat(64);
 assert.equal(check054(f).reason,'UNTRUSTED_INCIDENT_POLICY');
});
test('revoked reviewer cannot approve',()=>{
 const f=incident054();f.p.reviewers[1].status='REVOKED';
 f.policyPin.digest=keyQuorumPolicyDigest(f.p);
 assert.equal(check054(f).reason,'INCIDENT_EVIDENCE_CONTEXT_CONFLICT');
});
test('incident action cannot close or release evidence',()=>{
 const f=incident054();f.entries[0].body.action='CLOSE_INCIDENT';
 assert.equal(check054(f).reason,'BROKEN_INCIDENT_REGISTER');
});
test('tampered incident entry hash denied',()=>{
 const f=incident054();f.entries[0].hash='f'.repeat(64);
 assert.equal(check054(f).reason,'TAMPERED_INCIDENT_ENTRY');
});
test('duplicate incident ID and conflicting evidence replay denied',()=>{
 const f=incident054(),first=f.entries[0];
 const body={...first.body,sequence:2,previousHash:first.hash};
 const reviews=[['review-owner','OWNER',owner],['review-security','SECURITY',security]]
  .map(([reviewerId,role,k])=>({reviewerId,signature:sign(null,
    receiptIncidentReviewPayload(body,reviewerId,role),
    k.privateKey).toString('base64')}));
 f.entries.push({body,reviews,hash:receiptIncidentEntryHash(body,reviews)});
 f.evidence.push(f.evidence[0]);
 assert.equal(check054(f).reason,'REPLAYED_INCIDENT_OR_EQUIVOCATION');
});
test('invalid structures fail closed',()=>{
 const f=incident054();f.entries=null;
 assert.equal(check054(f).ok,false);
 assert.throws(()=>receiptIncidentReviewPayload({},'review-owner','OWNER'),
  /INVALID_RECEIPT_INCIDENT_PAYLOAD/);
});
