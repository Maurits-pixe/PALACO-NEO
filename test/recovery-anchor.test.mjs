import test from 'node:test';
import assert from 'node:assert/strict';
import {recoveryChallengeDigest} from '../src/recovery-challenge.mjs';
import {proposeRecoveryAnchor,reconcileRecoveryAnchor,verifyAnchorSequence} from '../src/recovery-anchor.mjs';

const ns='NEO-020-TEST',nonce='a'.repeat(64),nonce2='b'.repeat(64);
const old=()=>({schema:'NEO-019-v1',namespace:ns,challenges:[
 {challenge:nonce,signerId:'witness-001',status:'ISSUED'},
 {challenge:nonce2,signerId:'witness-002',status:'ISSUED'}]});
const newer=()=>({...old(),challenges:[
 {challenge:nonce,signerId:'witness-001',status:'CONSUMED'},
 {challenge:nonce2,signerId:'witness-002',status:'ISSUED'}]});
const start=()=>({namespace:ns,revision:4,digest:recoveryChallengeDigest(old())});
const proposal=()=>proposeRecoveryAnchor(start(),old(),newer(),nonce);
test('valid one-time challenge transition produces nonauthorizing anchor',()=>{
 const r=proposal();assert.equal(r.ok,true);assert.equal(r.authorized,false);
 assert.equal(r.candidate.revision,5);assert.equal(r.candidate.digest,recoveryChallengeDigest(newer()));
});
test('old and committed snapshots classified distinctly',()=>{
 const after=proposal().candidate;
 assert.equal(reconcileRecoveryAnchor(old(),start(),after).status,'NOT_COMMITTED');
 assert.equal(reconcileRecoveryAnchor(newer(),start(),after).status,'COMMITTED');
});
test('unknown or corrupted register is HOLD',()=>{
 assert.equal(reconcileRecoveryAnchor({...old(),challenges:[]},start(),proposal().candidate).status,'HOLD');
 assert.equal(reconcileRecoveryAnchor(null,start(),proposal().candidate).status,'HOLD');
});
test('stale external anchor rejects proposal',()=>{
 assert.equal(proposeRecoveryAnchor({...start(),digest:'f'.repeat(64)},old(),newer(),nonce).reason,'UNTRUSTED_BEFORE');
});
test('extra state changes rejected',()=>{
 const changed=newer();changed.challenges[1].status='CONSUMED';
 assert.equal(proposeRecoveryAnchor(start(),old(),changed,nonce).reason,'UNEXPECTED_REGISTRY_CHANGE');
});
test('wrong signer or absent challenge fails',()=>{
 const changed=newer();changed.challenges[0].signerId='other-witness';
 assert.equal(proposeRecoveryAnchor(start(),old(),changed,nonce).ok,false);
 assert.equal(proposeRecoveryAnchor(start(),old(),newer(),'c'.repeat(64)).reason,'INVALID_CONSUMPTION');
});
test('rollback revision and wrong namespace fail closed',()=>{
 const next=proposal().candidate;
 assert.equal(reconcileRecoveryAnchor(newer(),start(),{...next,revision:4}).status,'HOLD');
 assert.equal(reconcileRecoveryAnchor(newer(),start(),{...next,namespace:'OTHER-NEO'}).status,'HOLD');
});
test('monotonic sequence validates structure without authority',()=>{
 const r=verifyAnchorSequence([start(),proposal().candidate]);
 assert.equal(r.status,'STRUCTURALLY_VALID');assert.equal(r.authorized,false);assert.equal(r.checksum.length,64);
});
test('duplicate revision or equal digest rejected',()=>{
 assert.equal(verifyAnchorSequence([start(),start()]).status,'HOLD');
 assert.equal(verifyAnchorSequence([start(),{...proposal().candidate,digest:start().digest}]).status,'HOLD');
});
test('empty, malformed and revision overflow fail closed',()=>{
 assert.equal(verifyAnchorSequence([]).status,'HOLD');
 assert.equal(proposeRecoveryAnchor({...start(),revision:Number.MAX_SAFE_INTEGER},old(),newer(),nonce).reason,'REVISION_OVERFLOW');
});
