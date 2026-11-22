import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {recoveryChallengeDigest} from '../src/recovery-challenge.mjs';
import {prepareAnchorCAS,anchorCASSigningPayload,verifyAnchorCASReceipt}
 from '../src/anchor-cas.mjs';

const ns='PALACO-NEO-TEST',challenge='a'.repeat(64);
const beforeRegister={schema:'NEO-019-v1',namespace:ns,challenges:[
 {challenge,signerId:'recovery-witness',status:'ISSUED'}
]};
const afterRegister={schema:'NEO-019-v1',namespace:ns,challenges:[
 {challenge,signerId:'recovery-witness',status:'CONSUMED'}
]};
const before={namespace:ns,revision:9,digest:recoveryChallengeDigest(beforeRegister)};
const after={namespace:ns,revision:10,digest:recoveryChallengeDigest(afterRegister)};
const plan={schema:'NEO-021-v1',namespace:ns,challenge,before,after,proposedRegistry:afterRegister};
const operationId='operation-neo022';
const custodianId='trusted-custodian';
const signer=generateKeyPairSync('ed25519'),wrong=generateKeyPairSync('ed25519');
const pem=k=>k.publicKey.export({type:'spki',format:'pem'});
const request=()=>prepareAnchorCAS(plan,afterRegister,before,operationId).candidate;
const signed=(cas=request(),key=signer,id=custodianId)=>({
 cas,custodianId:id,
 signature:sign(null,anchorCASSigningPayload(cas,id),key.privateKey).toString('base64')
});
const trust=()=>({namespace:ns,custodianId,status:'ACTIVE',
 publicKeyPem:pem(signer),expectedOperationId:operationId,trustedBefore:before});
test('pending local change creates non-authorizing CAS request',()=>{
 const prepared=prepareAnchorCAS(plan,afterRegister,before,operationId);
 assert.equal(prepared.ok,true);assert.equal(prepared.authorized,false);
 assert.equal(prepared.candidate.after.digest,after.digest);
});
test('not-committed plan cannot initiate external CAS',()=>{
 assert.equal(prepareAnchorCAS(plan,beforeRegister,before,operationId).ok,false);
});
test('already advanced external anchor does not create second CAS',()=>{
 assert.equal(prepareAnchorCAS(plan,afterRegister,after,operationId).ok,false);
});
test('signed trusted custodian receipt verifies without authorization',()=>{
 const verified=verifyAnchorCASReceipt(plan,signed(),trust());
 assert.equal(verified.ok,true);assert.equal(verified.authorized,false);
 assert.equal(verified.candidate.outcome,'APPLIED');
});
test('forged custodian signature rejected',()=>{
 assert.equal(verifyAnchorCASReceipt(plan,signed(request(),wrong),trust()).reason,
  'INVALID_CUSTODIAN_SIGNATURE');
});
test('revoked custodian rejected',()=>{
 assert.equal(verifyAnchorCASReceipt(plan,signed(),{...trust(),status:'REVOKED'}).reason,
  'REVOKED_CUSTODIAN');
});
test('reused operation ID fails when independent expected ID advances',()=>{
 assert.equal(verifyAnchorCASReceipt(plan,signed(),
  {...trust(),expectedOperationId:'operation-next'}).reason,'OPERATION_REPLAY_OR_MISMATCH');
});
test('custodian identity substitution is detected',()=>{
 assert.equal(verifyAnchorCASReceipt(plan,{...signed(),custodianId:'another-custodian'},trust()).reason,
  'CUSTODIAN_OR_NAMESPACE_MISMATCH');
});
test('different independent before-anchor is a conflict',()=>{
 assert.equal(verifyAnchorCASReceipt(plan,signed(),
  {...trust(),trustedBefore:{...before,digest:'f'.repeat(64)}}).reason,
  'TRUSTED_BEFORE_CONFLICT');
});
test('receipt for an unexpected successor or rejected outcome is refused',()=>{
 const changed={...request(),after:{...after,digest:'f'.repeat(64)}};
 assert.equal(verifyAnchorCASReceipt(plan,signed(changed),trust()).reason,'CAS_PLAN_MISMATCH');
 const rejected={...request(),outcome:'REJECTED'};
 assert.equal(verifyAnchorCASReceipt(plan,signed(rejected),trust()).reason,'CAS_PLAN_MISMATCH');
});
test('modified plan cannot validate old custodian receipt',()=>{
 const different={...plan,challenge:'b'.repeat(64)};
 assert.equal(verifyAnchorCASReceipt(different,signed(),trust()).reason,'CAS_PLAN_MISMATCH');
});
test('malformed input and signature fail closed',()=>{
 assert.equal(verifyAnchorCASReceipt(plan,null,trust()).ok,false);
 assert.equal(verifyAnchorCASReceipt(plan,{...signed(),signature:'bad'},trust()).reason,'INVALID_SIGNATURE');
 assert.equal(prepareAnchorCAS(plan,afterRegister,before,'!').ok,false);
});
