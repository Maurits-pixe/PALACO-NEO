import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {policyActivationPayload} from '../src/cas-policy-activation.mjs';
import {policyActivationEntryHash,policyCheckpointPayload,
 INITIAL_POLICY_ACTIVATION_POSITION as genesis} from '../src/cas-policy-activation-ledger.mjs';
import {reconcilePolicyWitnesses,classifyPolicyCheckpointRecovery}
 from '../src/cas-policy-witness-recovery.mjs';

const namespace='PALACO-NEO-TEST',a={version:1,digest:'a'.repeat(64)},
 b={version:2,digest:'b'.repeat(64)};
const custodian=generateKeyPairSync('ed25519');
const witnessOne=generateKeyPairSync('ed25519'),witnessTwo=generateKeyPairSync('ed25519');
const forger=generateKeyPairSync('ed25519');
const pem=k=>k.publicKey.export({type:'spki',format:'pem'});
const req={schema:'NEO-029-CAS-v1',namespace,operationId:'operation-031',
 changeId:'change-031',decisionHead:'d'.repeat(64),before:a,after:b};
const receipt={request:req,custodianId:'custodian-001',outcome:'APPLIED',
 signature:sign(null,policyActivationPayload(req,'custodian-001','APPLIED'),
 custodian.privateKey).toString('base64')};
const recordBody={sequence:1,previousHash:genesis.head,request:req,receipt};
const record={...recordBody,hash:policyActivationEntryHash(recordBody)};
const entries=()=>[structuredClone(record)];
const custodianTrust=()=>[{namespace,custodianId:'custodian-001',
 publicKeyPem:pem(custodian),status:'ACTIVE',
 expectedOperationId:'operation-031',trustedBefore:a}];
const checkpoint=()=>({namespace,count:1,head:record.hash,activePolicy:b});
function witness(id,key,cp=checkpoint(),floor=genesis,signer=key){
 const seal={checkpoint:cp,witnessId:id,signature:sign(null,
 policyCheckpointPayload(cp,id),signer.privateKey).toString('base64')};
 return {seal,trust:{namespace,witnessId:id,publicKeyPem:pem(key),
 status:'ACTIVE',trustedCheckpointFloor:floor}};
}
const witnesses=()=>[witness('witness-001',witnessOne),witness('witness-002',witnessTwo)];
const ids=['witness-001','witness-002'];
const check=(ws=witnesses(),observed=b,records=entries(),trust=custodianTrust())=>
 reconcilePolicyWitnesses(records,trust,a,genesis,ws,observed,ids);

test('two independently keyed valid witness statements agree without authority',()=>{
 const r=check();
 assert.equal(r.phase,'CONSISTENT');assert.equal(r.authorized,false);
});
test('external policy still BEFORE causes HOLD for uncertain commit',()=>{
 assert.equal(check(witnesses(),a).reason,'EXTERNAL_POLICY_LAGS_SIGNED_CHECKPOINT');
});
test('unexpected external policy causes HOLD',()=>{
 assert.equal(check(witnesses(),{version:3,digest:'c'.repeat(64)}).phase,'HOLD');
});
test('one missing witness fails closed',()=>{
 assert.equal(check(witnesses().slice(0,1)).reason,'INVALID_WITNESS_INPUT');
});
test('duplicate witness identity fails closed',()=>{
 const ws=witnesses();ws[1]=witness('witness-001',witnessTwo);
 assert.equal(check(ws).reason,'DUPLICATE_OR_UNEXPECTED_WITNESS');
});
test('the same signing key under two identities is denied',()=>{
 const ws=[witness('witness-001',witnessOne),witness('witness-002',witnessOne)];
 assert.equal(check(ws).reason,'SHARED_WITNESS_SIGNING_KEY');
});
test('forged witness signature is denied',()=>{
 const ws=[witness('witness-001',witnessOne,checkpoint(),genesis,forger),witnesses()[1]];
 assert.equal(check(ws).phase,'HOLD');
});
test('revoked witness is denied',()=>{
 const ws=witnesses();ws[0].trust.status='REVOKED';
 assert.equal(check(ws).phase,'HOLD');
});
test('a mismatched checkpoint is rejected against actual ledger',()=>{
 const cp={...checkpoint(),activePolicy:a};
 const ws=[witness('witness-001',witnessOne,cp),witnesses()[1]];
 assert.equal(check(ws).phase,'HOLD');
});
test('rollback of authenticated witness floor fails',()=>{
 const ws=witnesses();ws[0].trust.trustedCheckpointFloor={count:2,head:'e'.repeat(64)};
 assert.equal(check(ws).phase,'HOLD');
});
test('invalid custodian signature causes HOLD before witnesses are counted',()=>{
 const records=entries();records[0].receipt.signature='x';
 assert.equal(check(witnesses(),b,records).reason,'INVALID_ACTIVATION_LEDGER');
});
test('unchanged verified checkpoint is classified without authority',()=>{
 const r=classifyPolicyCheckpointRecovery(genesis,genesis,[]);
 assert.equal(r.phase,'UNCHANGED');assert.equal(r.authorized,false);
});
test('append since trusted genesis needs independent review',()=>{
 const r=classifyPolicyCheckpointRecovery(genesis,{count:1,head:record.hash},entries());
 assert.equal(r.phase,'PENDING_INDEPENDENT_REVIEW');assert.equal(r.authorized,false);
});
test('rollback below trusted previous count is HOLD',()=>{
 assert.equal(classifyPolicyCheckpointRecovery({count:1,head:record.hash},
  genesis,[]).reason,'CHECKPOINT_ROLLBACK');
});
test('forked previous or candidate checkpoint is HOLD',()=>{
 assert.equal(classifyPolicyCheckpointRecovery({count:1,head:'f'.repeat(64)},
  {count:1,head:record.hash},entries()).phase,'HOLD');
 assert.equal(classifyPolicyCheckpointRecovery(genesis,
  {count:1,head:'f'.repeat(64)},entries()).phase,'HOLD');
});
test('malformed or missing evidence is never accepted',()=>{
 assert.equal(classifyPolicyCheckpointRecovery(null,genesis,[]).phase,'HOLD');
 assert.equal(check(null).phase,'HOLD');
});
