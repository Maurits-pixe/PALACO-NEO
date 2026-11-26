import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {keyRegistryDigest} from '../src/key-registry.mjs';
import {proposeRegistryTransition} from '../src/registry-transition.mjs';
import {reviewPayload} from '../src/approval-review.mjs';
import {reviewerPolicyDigest,proposeReviewedDecision} from '../src/review-ledger.mjs';
import {REVIEW_INITIAL_POSITION as genesis} from '../src/review-recovery.mjs';
import {createRecoveryEvidence} from '../src/recovery-evidence.mjs';
import {recoveryAttestationPayload} from '../src/recovery-attestation.mjs';
import {recoveryChallengeDigest} from '../src/recovery-challenge.mjs';
import {prepareRecoveryHandoff,classifyRecoveryHandoff} from '../src/recovery-handoff.mjs';

const ns='PALACO-NEO-TEST',challenge='a'.repeat(64),otherChallenge='b'.repeat(64);
const witness=generateKeyPairSync('ed25519');
const otherWitness=generateKeyPairSync('ed25519');
const owner=generateKeyPairSync('ed25519'),security=generateKeyPairSync('ed25519'),key=generateKeyPairSync('ed25519');
const pem=x=>x.publicKey.export({type:'spki',format:'pem'});
const keyEntry=id=>({id,publicKeyPem:pem(key),status:'ACTIVE',fromCount:0,throughCount:10});
const beforeKeys={version:1,namespace:ns,keys:[keyEntry('key-one'),keyEntry('key-two')]};
const keyPin={version:1,digest:keyRegistryDigest(beforeKeys)};
const transition=proposeRegistryTransition(beforeKeys,keyPin,{type:'REVOKE',keyId:'key-one',replacement:null}).candidate;
const policy={version:1,namespace:ns,reviewers:[
 {id:'review-owner',role:'OWNER',status:'ACTIVE',publicKeyPem:pem(owner)},
 {id:'review-security',role:'SECURITY',status:'ACTIVE',publicKeyPem:pem(security)}
]};
const proofs=[['review-owner',owner],['review-security',security]].map(([reviewerId,k])=>({
 reviewerId,signature:sign(null,reviewPayload(ns,keyPin,transition.pin),k.privateKey).toString('base64')
}));
const decision=proposeReviewedDecision({beforeRegistry:beforeKeys,afterRegistry:transition.registry,
 beforePin:keyPin,afterPin:transition.pin,reviews:proofs,policy,
 trustedPolicyPin:{version:1,digest:reviewerPolicyDigest(policy)},
 transitionId:'neo-021-proof',ledger:[],trustedLedgerHead:genesis.head}).candidate;
const receipt=createRecoveryEvidence([decision.entry],genesis,decision).receipt;
const signEnvelope=(k=witness,nonce=challenge)=>({namespace:ns,challenge:nonce,signerId:'review-witness',receipt,
 signature:sign(null,recoveryAttestationPayload(ns,nonce,'review-witness',receipt),k.privateKey).toString('base64')
});
const trust=()=>({namespace:ns,expectedChallenge:challenge,signerId:'review-witness',
 status:'ACTIVE',publicKeyPem:pem(witness),trustedBefore:genesis});
const original=()=>({schema:'NEO-019-v1',namespace:ns,challenges:[
 {challenge,signerId:'review-witness',status:'ISSUED'},
 {challenge:otherChallenge,signerId:'review-witness',status:'ISSUED'}
]});
const before=()=>({namespace:ns,revision:7,digest:recoveryChallengeDigest(original())});
const planned=()=>prepareRecoveryHandoff(original(),before(),signEnvelope(),trust());
test('produces non-authorizing plan bound to exactly one consumption',()=>{
 const p=planned();assert.equal(p.ok,true);assert.equal(p.authorized,false);
 assert.equal(p.plan.after.revision,8);
 assert.equal(p.plan.proposedRegistry.challenges[0].status,'CONSUMED');
 assert.equal(p.plan.proposedRegistry.challenges[1].status,'ISSUED');
});
test('both before is NOT_COMMITTED',()=>{
 const p=planned().plan;
 assert.deepEqual(classifyRecoveryHandoff(p,original(),before()),
  {phase:'NOT_COMMITTED',reason:'BOTH_AT_BEFORE',authorized:false});
});
test('local consumption with external old anchor is PENDING, not permission',()=>{
 const p=planned().plan,r=classifyRecoveryHandoff(p,p.proposedRegistry,before());
 assert.equal(r.phase,'PENDING_ANCHOR_CAS');assert.equal(r.authorized,false);
});
test('both advanced is COMMITTED but without authorization',()=>{
 const p=planned().plan,r=classifyRecoveryHandoff(p,p.proposedRegistry,p.after);
 assert.equal(r.phase,'COMMITTED');assert.equal(r.authorized,false);
});
test('external advanced but local stale is HOLD',()=>{
 const p=planned().plan;
 assert.equal(classifyRecoveryHandoff(p,original(),p.after).reason,'EXTERNAL_ADVANCED_LOCAL_BEHIND');
});
test('unknown external anchor is HOLD',()=>{
 const p=planned().plan;
 assert.equal(classifyRecoveryHandoff(p,p.proposedRegistry,{...p.after,digest:'f'.repeat(64)}).phase,'HOLD');
});
test('unexpected local register edit is HOLD',()=>{
 const p=planned().plan,changed=structuredClone(p.proposedRegistry);
 changed.challenges[1].status='CONSUMED';
 assert.equal(classifyRecoveryHandoff(p,changed,p.after).reason,'UNKNOWN_LOCAL_STATE');
});
test('old consumed challenge and wrong external pin cannot prepare',()=>{
 const consumed=original();consumed.challenges[0].status='CONSUMED';
 assert.equal(prepareRecoveryHandoff(consumed,{...before(),digest:recoveryChallengeDigest(consumed)},
  signEnvelope(),trust()).ok,false);
 assert.equal(prepareRecoveryHandoff(original(),{...before(),digest:'f'.repeat(64)},
  signEnvelope(),trust()).ok,false);
});
test('invalid signature or revoked witness cannot prepare',()=>{
 assert.equal(prepareRecoveryHandoff(original(),before(),signEnvelope(otherWitness),trust()).ok,false);
 assert.equal(prepareRecoveryHandoff(original(),before(),signEnvelope(),{...trust(),status:'REVOKED'}).ok,false);
});
test('altered plan and invalid data fail closed',()=>{
 const p=planned().plan;
 assert.equal(classifyRecoveryHandoff({...p,after:{...p.after,revision:9}},
  p.proposedRegistry,p.after).phase,'HOLD');
 assert.equal(classifyRecoveryHandoff(null,original(),before()).phase,'HOLD');
 assert.equal(prepareRecoveryHandoff(original(),null,signEnvelope(),trust()).ok,false);
});
