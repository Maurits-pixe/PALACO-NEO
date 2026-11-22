import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {keyRegistryDigest} from '../src/key-registry.mjs';
import {proposeRegistryTransition} from '../src/registry-transition.mjs';
import {reviewPayload} from '../src/approval-review.mjs';
import {reviewerPolicyDigest,proposeReviewedDecision} from '../src/review-ledger.mjs';
import {createRecoveryEvidence,compareRecoveryEvidence} from '../src/recovery-evidence.mjs';
import {REVIEW_INITIAL_POSITION as genesis} from '../src/review-recovery.mjs';

const ns='PALACO-NEO-TEST';
const owner=generateKeyPairSync('ed25519');
const security=generateKeyPairSync('ed25519');
const key=generateKeyPairSync('ed25519');
const pem=k=>k.publicKey.export({type:'spki',format:'pem'});
const entry=id=>({id,publicKeyPem:pem(key),status:'ACTIVE',fromCount:0,throughCount:20});
const previous={version:1,namespace:ns,keys:[entry('key-old'),entry('key-live')]};
const oldPin={version:1,digest:keyRegistryDigest(previous)};
const transition=proposeRegistryTransition(previous,oldPin,
  {type:'REVOKE',keyId:'key-old',replacement:null}).candidate;
const policy={version:1,namespace:ns,reviewers:[
 {id:'review-owner',role:'OWNER',status:'ACTIVE',publicKeyPem:pem(owner)},
 {id:'review-security',role:'SECURITY',status:'ACTIVE',publicKeyPem:pem(security)}
]};
const reviews=[['review-owner',owner],['review-security',security]].map(([reviewerId,k])=>({
 reviewerId,signature:sign(null,reviewPayload(ns,oldPin,transition.pin),k.privateKey).toString('base64')
}));
const proposal=proposeReviewedDecision({
 beforeRegistry:previous,afterRegistry:transition.registry,beforePin:oldPin,
 afterPin:transition.pin,reviews,policy,trustedPolicyPin:{version:1,digest:reviewerPolicyDigest(policy)},
 transitionId:'neo-017-test',ledger:[],trustedLedgerHead:genesis.head
}).candidate;
test('genesis produces unsigned NOT_COMMITTED evidence with no authority',()=>{
 const r=createRecoveryEvidence([],genesis,proposal);
 assert.equal(r.ok,true);
 assert.equal(r.authorized,false);
 assert.equal(r.receipt.status,'NOT_COMMITTED');
 assert.equal(r.receipt.receiptDigest.length,64);
});
test('verified appended proposal produces COMMITTED evidence',()=>{
 const r=createRecoveryEvidence([proposal.entry],genesis,proposal);
 assert.equal(r.ok,true);assert.equal(r.receipt.status,'COMMITTED');
});
test('same observations are stable but never authorized',()=>{
 const a=createRecoveryEvidence([proposal.entry],genesis,proposal);
 const b=createRecoveryEvidence([proposal.entry],genesis,proposal);
 assert.deepEqual(compareRecoveryEvidence(a,b),{
  status:'STABLE',reason:'TWO_IDENTICAL_OBSERVATIONS_NO_AUTHORITY',authorized:false
 });
});
test('different pre- and post-commit observations are conservatively held',()=>{
 const a=createRecoveryEvidence([],genesis,proposal);
 const b=createRecoveryEvidence([proposal.entry],genesis,proposal);
 assert.equal(compareRecoveryEvidence(a,b).reason,'CONFLICTING_OBSERVATIONS');
});
test('fabricated proposal head is denied',()=>{
 const bad={entry:{...proposal.entry},head:'f'.repeat(64)};
 assert.equal(createRecoveryEvidence([],genesis,bad).reason,'INVALID_PROPOSAL_CHAIN');
});
test('tampered current ledger refuses evidence',()=>{
 const changed={...proposal.entry,transitionId:'forged'};
 assert.equal(createRecoveryEvidence([changed],genesis,proposal).reason,'INVALID_OBSERVED_LEDGER');
});
test('incorrect trusted prewrite head refused',()=>{
 assert.equal(createRecoveryEvidence([proposal.entry],{count:0,head:'f'.repeat(64)},proposal).reason,
 'TRUSTED_PREFIX_CONFLICT');
});
test('receipt field manipulation detected when comparing',()=>{
 const r=createRecoveryEvidence([],genesis,proposal);
 const corrupt={...r,receipt:{...r.receipt,observed:{count:7,head:r.receipt.observed.head}}};
 assert.equal(compareRecoveryEvidence(corrupt,r).reason,'RECEIPT_TAMPERED');
});
test('missing trusted context fails closed',()=>{
 assert.equal(createRecoveryEvidence([],null,proposal).ok,false);
 assert.equal(compareRecoveryEvidence(null,null).status,'HOLD');
});
