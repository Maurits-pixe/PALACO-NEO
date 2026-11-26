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
import {auditCheckpointPayload,auditCheckpointHash,verifyAuditCheckpoint,inspectAuditCustodianEquivocation} from '../src/cas-audit-checkpoint.mjs';

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
test('two independently keyed custodians attest full cryptographic audit history',()=>{
 const r=check(fixture());
 assert.equal(r.ok,true);assert.equal(r.authorized,false);
 assert.equal(r.phase,'AUDIT_CHECKPOINT_VERIFIED_HOLD');
 assert.equal(r.candidate.cases[0].status,'ESCALATED_HOLD');
});
test('sealing digest is independent of custodian ordering',()=>{
 const f=fixture(),one=auditCheckpointHash(f.seal);
 f.seal.attestations.reverse();
 assert.equal(auditCheckpointHash(f.seal),one);
 assert.equal(check(f).ok,true);
});
test('tampered original fork evidence refuses otherwise valid signed checkpoint',()=>{
 const f=fixture();f.rows[0].evidence.right[0].post.replicas[0].artifacts[0].base64='YmFk';
 assert.match(check(f).reason,/^JOURNAL_/);
});
test('truncated audit history cannot satisfy pinned checkpoint',()=>{
 const f=fixture();f.rows=[];
 assert.equal(check(f).reason,'CHECKPOINT_STATE_OR_ANCHOR_CONFLICT');
});
test('externally pinned rollback floor is enforced',()=>{
 const f=fixture();const floor={count:1,head:'f'.repeat(64)};
 assert.equal(check(f,floor).reason,'JOURNAL_CONFLICT_JOURNAL_FORK');
});
test('incorrect checkpoint ledger tip fails',()=>{
 const f=fixture();f.seal.body.position.head='f'.repeat(64);
 assert.equal(check(f).reason,'CHECKPOINT_STATE_OR_ANCHOR_CONFLICT');
});
test('stale or forged custody signature is refused',()=>{
 const f=fixture();f.seal.attestations[0].signature=sign(null,
  auditCheckpointPayload(f.seal.body,'custodian-a'),
  attacker.privateKey).toString('base64');
 assert.equal(check(f).reason,'INVALID_OR_DUPLICATE_CUSTODY_SIGNATURE');
});
test('duplicate custodian identity cannot replace another',()=>{
 const f=fixture();f.seal.attestations[1]={...f.seal.attestations[0]};
 assert.equal(check(f).reason,'INVALID_OR_DUPLICATE_CUSTODY_SIGNATURE');
});
test('same Ed25519 key used by two custodian identities is refused',()=>{
 const f=fixture();f.trusts[1].publicKeyPem=pem(custodianA);
 assert.equal(check(f).reason,'INVALID_OR_NONINDEPENDENT_CUSTODY_ROSTER');
});
test('reviewer key reused as audit custodian key is refused',()=>{
 const f=fixture();f.trusts[0].publicKeyPem=pem(owner);
 assert.equal(check(f).reason,'INVALID_OR_NONINDEPENDENT_CUSTODY_ROSTER');
});
test('revoked or unknown custody signer is refused',()=>{
 const f=fixture();f.trusts[0].status='REVOKED';
 assert.equal(check(f).reason,'INVALID_OR_NONINDEPENDENT_CUSTODY_ROSTER');
});
test('missing a mandatory attestation prevents checkpoint acceptance',()=>{
 const f=fixture();f.seal.attestations.pop();
 assert.equal(check(f).reason,'INVALID_CHECKPOINT_INPUT');
});
test('checkpoint cannot be silently reassigned to a different namespace',()=>{
 const f=fixture();f.seal.body.namespace='OTHER-NAMESPACE';
 assert.equal(check(f).reason,'CHECKPOINT_STATE_OR_ANCHOR_CONFLICT');
});
test('two individually valid contradictory claims of one key yield equivocation evidence',()=>{
 const f=fixture(),b=f.seal.body;
 const alt={...b,position:{...b.position,head:'f'.repeat(64)}};
 const left={body:b,attestation:f.seal.attestations[0]};
 const right={body:alt,attestation:assertion(alt,'custodian-a',custodianA)};
 const result=inspectAuditCustodianEquivocation(left,right,f.trusts[0],auditGenesis);
 assert.equal(result.ok,true);assert.equal(result.phase,'EQUIVOCATION_EVIDENCE_HOLD');
 assert.equal(result.authorized,false);
 assert.equal(result.candidate.heads.length,2);
});
test('identical signed claims are not an equivocation',()=>{
 const f=fixture(),a={body:f.seal.body,attestation:f.seal.attestations[0]};
 assert.equal(inspectAuditCustodianEquivocation(a,a,f.trusts[0],auditGenesis).phase,
  'NO_CONFLICT');
});
test('forged conflicting signature is not valid evidence',()=>{
 const f=fixture(),b={...f.seal.body,position:{count:1,head:'f'.repeat(64)}};
 const a={body:f.seal.body,attestation:f.seal.attestations[0]};
 const fake={body:b,attestation:assertion(b,'custodian-a',attacker)};
 assert.equal(inspectAuditCustodianEquivocation(a,fake,f.trusts[0],auditGenesis).reason,
  'UNVERIFIED_CUSTODY_STATEMENT');
});
test('distinct checkpoint IDs are not directly comparable as equivocation',()=>{
 const f=fixture(),b={...f.seal.body,checkpointId:'checkpoint-042'};
 const a={body:f.seal.body,attestation:f.seal.attestations[0]};
 const other={body:b,attestation:assertion(b,'custodian-a',custodianA)};
 assert.equal(inspectAuditCustodianEquivocation(a,other,f.trusts[0],auditGenesis).reason,
  'UNRELATED_CUSTODY_STATEMENTS');
});
test('a different external trusted floor blocks equivocation evidence',()=>{
 const f=fixture(),a={body:f.seal.body,attestation:f.seal.attestations[0]};
 assert.equal(inspectAuditCustodianEquivocation(a,a,f.trusts[0],
  {count:1,head:'f'.repeat(64)}).reason,'INVALID_EQUIVOCATION_INPUT');
});
test('invalid signatures and malformed inputs fail closed',()=>{
 const f=fixture();
 assert.equal(check(f,auditGenesis,['custodian-a','custodian-a']).ok,false);
 assert.equal(verifyAuditCheckpoint([],[],f.p,f.policyPin,auditGenesis,null,[],[]).ok,false);
 assert.throws(()=>auditCheckpointPayload({},'custodian-a'),/INVALID_AUDIT_CHECKPOINT/);
});
