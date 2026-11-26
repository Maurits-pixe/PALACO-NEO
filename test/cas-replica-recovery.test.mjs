import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {transferInventoryDigest} from '../src/cas-custody-lineage.mjs';
import {replicaObservationPayload,assessReplicaArchive}
 from '../src/cas-replica-recovery.mjs';

const ns='PALACO-NEO-TEST',caseId='case-036';
const position={count:1,head:'a'.repeat(64)};
const keys=[generateKeyPairSync('ed25519'),generateKeyPairSync('ed25519'),
 generateKeyPairSync('ed25519')];
const attacker=generateKeyPairSync('ed25519');
const pem=k=>k.publicKey.export({type:'spki',format:'pem'});
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const bytes1=Buffer.from('forensic bytes one');
const bytes2=Buffer.from('forensic bytes two');
const manifest=()=>({schema:'NEO-035-INVENTORY-v1',caseId,artifacts:[
 {artifactId:'file-001',sha256:sha(bytes1),byteLength:bytes1.length},
 {artifactId:'file-002',sha256:sha(bytes2),byteLength:bytes2.length}]});
const artifactBytes=()=>[
 {artifactId:'file-001',base64:bytes1.toString('base64')},
 {artifactId:'file-002',base64:bytes2.toString('base64')}];
const rep=(i,missing=[],key=keys[i],status=missing.length?'INCOMPLETE':'PRESENT')=>{
 const replicaId='replica-00'+(i+1),observationId='observation-00'+(i+1);
 const body={schema:'NEO-036-REPLICA-v1',namespace:ns,caseId,replicaId,
  inventoryDigest:transferInventoryDigest(manifest()),lineagePosition:position,observationId};
 const signature=sign(null,replicaObservationPayload(body,status),
  key.privateKey).toString('base64');
 return {body,status,signature,artifacts:artifactBytes().filter(a=>!missing.includes(a.artifactId))};
};
const trust=i=>({namespace:ns,replicaId:'replica-00'+(i+1),
 publicKeyPem:pem(keys[i]),status:'ACTIVE',expectedObservationId:'observation-00'+(i+1)});
const fixture=(missing=[])=>({records:[rep(0),rep(1),rep(2,missing)],
 trusts:[trust(0),trust(1),trust(2)]});
const check=(f,opts={})=>assessReplicaArchive(
 opts.manifest??manifest(),opts.digest??transferInventoryDigest(manifest()),
 opts.position??position,f.records,f.trusts,
 opts.ids??['replica-001','replica-002','replica-003'],opts.namespace??ns);
test('three replicas match all original manifest bytes but never grant authority',()=>{
 const r=check(fixture());assert.equal(r.ok,true);
 assert.equal(r.phase,'VERIFIED_ASSERTIONS_ONLY');assert.equal(r.authorized,false);
 assert.equal(r.candidate.healthyReplicas.length,3);
});
test('two complete replicas allow repair proposal for missing artifact in third',()=>{
 const r=check(fixture(['file-002']));
 assert.equal(r.phase,'REPAIR_PROPOSAL_ONLY');assert.equal(r.authorized,false);
 assert.deepEqual(r.candidate.repairProposal.missingArtifactIds,['file-002']);
 assert.equal(r.candidate.healthyReplicas.length,2);
});
test('only one complete replica is insufficient for repair',()=>{
 const f=fixture(['file-001']);f.records[1]=rep(1,['file-002']);
 const r=check(f);assert.equal(r.phase,'HOLD');assert.equal(r.reason,'INSUFFICIENT_VERIFIED_REPLICAS');
});
test('an invalid byte digest is never treated as a missing file',()=>{
 const f=fixture();f.records[2].artifacts[0].base64=Buffer.from('altered').toString('base64');
 assert.equal(check(f).reason,'CORRUPTED_REPLICA_BYTES');
});
test('missing replica cannot falsely declare PRESENT',()=>{
 const f=fixture(['file-002']);f.records[2].status='PRESENT';
 assert.equal(check(f).reason,'INVALID_REPLICA_SIGNATURE');
});
test('signed PRESENT claim missing bytes is rejected even with valid signature',()=>{
 const f=fixture();f.records[2].artifacts.pop();
 assert.equal(check(f).reason,'FALSE_REPLICA_COMPLETENESS_CLAIM');
});
test('forged replica signature is refused',()=>{
 const f=fixture();f.records[1]=rep(1,[],attacker);
 assert.equal(check(f).reason,'INVALID_REPLICA_SIGNATURE');
});
test('revoked replica trust is refused',()=>{
 const f=fixture();f.trusts[0].status='REVOKED';
 assert.equal(check(f).reason,'INVALID_REPLICA_IDENTITY_OR_CONTEXT');
});
test('two identities reusing the same signing key are refused',()=>{
 const f=fixture();f.records[1]=rep(1,[],keys[0]);
 f.trusts[1].publicKeyPem=pem(keys[0]);
 assert.equal(check(f).reason,'INVALID_OR_DUPLICATE_REPLICA_KEY');
});
test('independently pinned inventory digest is mandatory',()=>{
 assert.equal(check(fixture(),{digest:'f'.repeat(64)}).reason,'INVALID_REPLICA_INPUT_OR_PIN');
});
test('lineage floor mismatch blocks all replica evidence',()=>{
 assert.equal(check(fixture(),{position:{count:2,head:'f'.repeat(64)}}).ok,false);
});
test('unexpected namespace rejected even with otherwise matching bytes',()=>{
 assert.equal(check(fixture(),{namespace:'OTHER-NAMESPACE'}).reason,
  'INVALID_REPLICA_IDENTITY_OR_CONTEXT');
});
test('missing expected replica and duplicate IDs are blocked',()=>{
 const f=fixture();f.records[1].body.replicaId='replica-001';
 assert.equal(check(f).reason,'INVALID_REPLICA_IDENTITY_OR_CONTEXT');
});
test('unknown artifact inserted into a replica is refused',()=>{
 const f=fixture();f.records[0].artifacts.push({artifactId:'unknown-001',
  base64:Buffer.from('more bytes').toString('base64')});
 assert.equal(check(f).reason,'INVALID_ARTIFACT_ENCODING_OR_INVENTORY');
});
test('duplicate manifest artifact ID is refused',()=>{
 const m=manifest();m.artifacts.push({...m.artifacts[0]});
 assert.equal(check(fixture(),{manifest:m}).reason,'INVALID_MANIFEST');
});
test('reused observation ID is refused even if signed by different keys',()=>{
 const f=fixture();
 const same='observation-001';
 f.records[1].body.observationId=same;
 f.records[1].signature=sign(null,replicaObservationPayload(f.records[1].body,'PRESENT'),
  keys[1].privateKey).toString('base64');
 f.trusts[1].expectedObservationId=same;
 assert.equal(check(f).reason,'REPLAYED_OBSERVATION_ID');
});
test('malformed source and missing replica trust fail closed',()=>{
 const f=fixture();f.trusts.pop();
 assert.equal(check(f).ok,false);
 assert.throws(()=>replicaObservationPayload({},'PRESENT'),/INVALID_REPLICA/);
});
