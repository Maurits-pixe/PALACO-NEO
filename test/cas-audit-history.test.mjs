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
import {auditHistoryEntryHash,verifyAuditCheckpointSuccession,inspectAuditHistoryFork,INITIAL_AUDIT_HISTORY_POSITION as historyGenesis} from '../src/cas-audit-history.mjs';

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
test('empty audit checkpoint succession remains non-authorizing',()=>{
 const r=verifyAuditCheckpointSuccession([],historyGenesis);
 assert.equal(r.ok,true);assert.equal(r.authorized,false);
 assert.equal(r.candidate.position.count,0);
});
test('single independently signed audit checkpoint re-verifies original fork evidence',()=>{
 const r=verifyAuditCheckpointSuccession([item()],historyGenesis);
 assert.equal(r.ok,true);assert.equal(r.phase,'AUDIT_HISTORY_VERIFIED_HOLD');
 assert.equal(r.candidate.journalPosition.count,1);
});
test('two successively anchored checkpoints preserve journal lineage',()=>{
 const r=verifyAuditCheckpointSuccession(chain(),historyGenesis);
 assert.equal(r.ok,true);assert.equal(r.candidate.position.count,2);
 assert.equal(r.candidate.journalPosition.count,2);
});
test('audit history digest binds previous signed checkpoint hash',()=>{
 const h=chain();
 const a=auditHistoryEntryHash(1,historyGenesis.head,h[0].seal);
 const b=auditHistoryEntryHash(2,a,h[1].seal);
 assert.equal(verifyAuditCheckpointSuccession(h,historyGenesis).candidate.position.head,b);
});
test('duplicate checkpoint ID is rejected across valid-looking entries',()=>{
 const h=chain();h[1].seal.body.checkpointId=h[0].seal.body.checkpointId;
 assert.equal(verifyAuditCheckpointSuccession(h,historyGenesis).reason,'AUDIT_CHECKPOINT_ID_REPLAY');
});
test('missing prior audit register evidence is rejected',()=>{
 const h=chain();h[1].entries=h[1].entries.slice(1);
 assert.equal(verifyAuditCheckpointSuccession(h,historyGenesis).ok,false);
});
test('a conflicting signed journal ancestry is denied',()=>{
 const h=chain();h[1].seal.body.anchoredFloor.head='f'.repeat(64);
 assert.equal(verifyAuditCheckpointSuccession(h,historyGenesis).reason,
  'AUDIT_JOURNAL_ANCESTOR_CONFLICT');
});
test('changing returning custodian signing key fails continuity checks',()=>{
 const h=chain();
 h[1].trusts[0].publicKeyPem=pem(custodianC);
 h[1].seal.attestations[0]=assertion(h[1].seal.body,'custodian-a',custodianC);
 assert.equal(verifyAuditCheckpointSuccession(h,historyGenesis).reason,
  'CUSTODIAN_KEY_CHANGED_WITHOUT_ROTATION_PROOF');
});
test('cannot reuse an old custodian key under another identity',()=>{
 const h=chain();
 h[1].trusts[0].custodianId='custodian-c';
 h[1].trusts[0].expectedCheckpointId=h[1].seal.body.checkpointId;
 h[1].seal.attestations[0]=assertion(h[1].seal.body,'custodian-c',custodianA);
 h[1].expectedCustodianIds[0]='custodian-c';
 assert.equal(verifyAuditCheckpointSuccession(h,historyGenesis).reason,
  'REUSED_KEY_ACROSS_CUSTODIAN_IDENTITIES');
});
test('forged signature at earlier checkpoint cannot be hidden by later attestations',()=>{
 const h=chain();h[0].seal.attestations[0].signature='a'.repeat(88);
 assert.match(verifyAuditCheckpointSuccession(h,historyGenesis).reason,/^AUDIT_CHECKPOINT_/);
});
test('damaged original bytes from prior fork invalidate entire audit chain',()=>{
 const h=chain();h[0].evidence[0].left[0].post.replicas[0].artifacts[0].base64='YmFk';
 assert.match(verifyAuditCheckpointSuccession(h,historyGenesis).reason,/^AUDIT_CHECKPOINT_/);
});
test('externally pinned history floor detects truncation',()=>{
 const h=chain();
 const good=verifyAuditCheckpointSuccession(h,historyGenesis);
 assert.equal(verifyAuditCheckpointSuccession([h[0]],good.candidate.position).reason,
  'AUDIT_HISTORY_ROLLBACK');
});
test('externally pinned alternate audit history is rejected',()=>{
 const h=chain();
 assert.equal(verifyAuditCheckpointSuccession(h,{count:1,head:'f'.repeat(64)}).reason,
  'TRUSTED_AUDIT_HISTORY_FORK');
});
test('identical valid histories do not create fake fork',()=>{
 const h=chain();
 assert.equal(inspectAuditHistoryFork(h,structuredClone(h),historyGenesis).phase,
  'NO_PROVEN_FORK');
});
test('valid shorter prefix versus extension does not create fork',()=>{
 const h=chain();
 assert.equal(inspectAuditHistoryFork([h[0]],h,historyGenesis).phase,'NO_PROVEN_FORK');
});
test('two fully verified audit branches with different valid tips provide fork evidence',()=>{
 const a=item(),b=next(a,'-branch','checkpoint-alt');
 const c=next(a,'-other','checkpoint-other');
 const r=inspectAuditHistoryFork([a,b],[a,c],historyGenesis);
 assert.equal(r.phase,'AUDIT_HISTORY_FORK_HOLD');
 assert.equal(r.authorized,false);assert.equal(r.candidate.sequence,2);
});
test('forged competing branch cannot produce fork evidence',()=>{
 const a=item(),b=next(a,'-branch','checkpoint-alt');
 const c=next(a,'-other','checkpoint-other');
 c.seal.attestations[1].signature='a'.repeat(88);
 assert.equal(inspectAuditHistoryFork([a,b],[a,c],historyGenesis).reason,
  'UNVERIFIED_AUDIT_BRANCH');
});
test('an anchored floor rejects an alternative branch outright',()=>{
 const a=item(),b=next(a,'-branch','checkpoint-alt');
 const c=next(a,'-other','checkpoint-other');
 const pin=verifyAuditCheckpointSuccession([a,b],historyGenesis).candidate.position;
 assert.equal(inspectAuditHistoryFork([a,b],[a,c],pin).ok,false);
});
test('malformed history is denied',()=>{
 assert.equal(verifyAuditCheckpointSuccession(null,historyGenesis).ok,false);
 assert.equal(inspectAuditHistoryFork(null,[],historyGenesis).ok,false);
 assert.throws(()=>auditHistoryEntryHash(0,historyGenesis.head,fixture().seal),
  /INVALID_HISTORY_LINK/);
});
