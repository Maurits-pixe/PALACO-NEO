import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {recoveryChallengeDigest} from '../src/recovery-challenge.mjs';
import {prepareAnchorCAS,anchorCASSigningPayload} from '../src/anchor-cas.mjs';
import {INITIAL_CAS_PROOF_POSITION as genesis,verifyCASProofLedger,
 proposeCASProofAppend,compareCASProofObservations} from '../src/cas-proof-ledger.mjs';

const ns='PALACO-NEO-TEST',challenge='a'.repeat(64),custodianId='trusted-custodian';
const beforeRegister={schema:'NEO-019-v1',namespace:ns,challenges:[
 {challenge,signerId:'recovery-witness',status:'ISSUED'}]};
const afterRegister={schema:'NEO-019-v1',namespace:ns,challenges:[
 {challenge,signerId:'recovery-witness',status:'CONSUMED'}]};
const before={namespace:ns,revision:9,digest:recoveryChallengeDigest(beforeRegister)};
const after={namespace:ns,revision:10,digest:recoveryChallengeDigest(afterRegister)};
const plan={schema:'NEO-021-v1',namespace:ns,challenge,before,after,proposedRegistry:afterRegister};
const custodian=generateKeyPairSync('ed25519'),forger=generateKeyPairSync('ed25519');
const pem=k=>k.publicKey.export({type:'spki',format:'pem'});
const operationId='neo023-operation';
const cas=()=>prepareAnchorCAS(plan,afterRegister,before,operationId).candidate;
const envelope=(key=custodian,c=cas())=>({cas:c,custodianId,signature:sign(null,
 anchorCASSigningPayload(c,custodianId),key.privateKey).toString('base64')});
const trust=()=>({namespace:ns,custodianId,status:'ACTIVE',publicKeyPem:pem(custodian),
 expectedOperationId:operationId,trustedBefore:before});
const append=()=>proposeCASProofAppend([],genesis,plan,envelope(),trust());

test('genesis ledger is structurally valid and grants no authority',()=>{
 const s=verifyCASProofLedger([],genesis);
 assert.equal(s.ok,true);assert.equal(s.authorized,false);assert.equal(s.position.head,genesis.head);
});
test('cryptographically verified custodian receipt produces one proof entry',()=>{
 const p=append();
 assert.equal(p.ok,true);assert.equal(p.authorized,false);
 assert.equal(p.candidate.entry.sequence,1);
 assert.equal(verifyCASProofLedger([p.candidate.entry]).ok,true);
});
test('forged custodian signature is rejected',()=>{
 assert.equal(proposeCASProofAppend([],genesis,plan,envelope(forger),trust()).ok,false);
});
test('revoked custodian is rejected',()=>{
 assert.equal(proposeCASProofAppend([],genesis,plan,envelope(),
  {...trust(),status:'REVOKED'}).ok,false);
});
test('wrong externally trusted operation rejected',()=>{
 assert.equal(proposeCASProofAppend([],genesis,plan,envelope(),
  {...trust(),expectedOperationId:'another-operation'}).ok,false);
});
test('stale head prevents duplicate proposal',()=>{
 const p=append().candidate;
 assert.equal(proposeCASProofAppend([p.entry],genesis,plan,envelope(),trust()).reason,
  'TRUSTED_HEAD_CONFLICT');
});
test('duplicate operation ID refused at current head',()=>{
 const p=append().candidate;
 assert.equal(proposeCASProofAppend([p.entry],p.position,plan,envelope(),trust()).reason,
  'OPERATION_REPLAY');
});
test('record edit is detected by hash chain',()=>{
 const p=append().candidate;
 assert.equal(verifyCASProofLedger([{...p.entry,custodianId:'other-custodian'}]).ok,false);
});
test('rollback below separately trusted count is held',()=>{
 const p=append().candidate;
 assert.equal(verifyCASProofLedger([],p.position).reason,'ROLLBACK_BELOW_TRUSTED_FLOOR');
 assert.equal(compareCASProofObservations([],[],p.position).phase,'HOLD');
});
test('equal observations remain structurally stable, not authorized',()=>{
 const p=append().candidate;
 const r=compareCASProofObservations([p.entry],[p.entry],genesis);
 assert.equal(r.phase,'STABLE');assert.equal(r.authorized,false);
});
test('different observations conflict even when one extends a trusted floor',()=>{
 const p=append().candidate;
 assert.equal(compareCASProofObservations([],[p.entry],genesis).reason,
  'CONFLICTING_OBSERVATIONS');
});
test('untrusted floor digest cannot be used to certify a ledger',()=>{
 const p=append().candidate;
 assert.equal(verifyCASProofLedger([p.entry],{count:1,head:'f'.repeat(64)}).reason,
  'TRUSTED_FLOOR_CONFLICT');
});
test('malformed inputs fail closed',()=>{
 assert.equal(proposeCASProofAppend(null,genesis,plan,envelope(),trust()).ok,false);
 assert.equal(compareCASProofObservations([],[],null).phase,'HOLD');
 assert.equal(verifyCASProofLedger([{bad:true}]).ok,false);
});
