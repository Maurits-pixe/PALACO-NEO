import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {keyRegistryDigest} from '../src/key-registry.mjs';
import {proposeRegistryTransition} from '../src/registry-transition.mjs';
import {reviewPayload} from '../src/approval-review.mjs';
import {REVIEW_GENESIS,reviewerPolicyDigest,verifyReviewLedger,
 proposeReviewedDecision} from '../src/review-ledger.mjs';

const ns='PALACO-NEO-TEST';
const owner=generateKeyPairSync('ed25519'),security=generateKeyPairSync('ed25519');
const k=generateKeyPairSync('ed25519');
const pem=p=>p.publicKey.export({type:'spki',format:'pem'});
const regkey=id=>({id,publicKeyPem:pem(k),status:'ACTIVE',fromCount:0,throughCount:10});
const before={version:1,namespace:ns,keys:[regkey('key-001'),regkey('key-keep')]};
const beforePin={version:1,digest:keyRegistryDigest(before)};
const transition=proposeRegistryTransition(before,beforePin,
 {type:'REVOKE',keyId:'key-001',replacement:null}).candidate;
const policy=()=>({version:1,namespace:ns,reviewers:[
 {id:'owner-review',role:'OWNER',status:'ACTIVE',publicKeyPem:pem(owner)},
 {id:'security-review',role:'SECURITY',status:'ACTIVE',publicKeyPem:pem(security)}
]});
const policyPin=p=>({version:p.version,digest:reviewerPolicyDigest(p)});
const review=(reviewerId,key)=>({reviewerId,signature:sign(null,
 reviewPayload(ns,beforePin,transition.pin),key.privateKey).toString('base64')});
const reviews=()=>[review('owner-review',owner),review('security-review',security)];
const input=()=>{const p=policy();return {beforeRegistry:before,
 afterRegistry:transition.registry,beforePin,afterPin:transition.pin,
 reviews:reviews(),policy:p,trustedPolicyPin:policyPin(p),transitionId:'transition-001',
 ledger:[],trustedLedgerHead:REVIEW_GENESIS}};
test('valid two-person review creates proposal, never authorization',()=>{
 const r=proposeReviewedDecision(input());
 assert.equal(r.ok,true);assert.equal(r.authorized,false);
 assert.equal(verifyReviewLedger([r.candidate.entry],r.candidate.head).ok,true);
});
test('revoked reviewer causes HOLD',()=>{
 const i=input();i.policy.reviewers[1].status='REVOKED';
 i.trustedPolicyPin=policyPin(i.policy);
 assert.equal(proposeReviewedDecision(i).ok,false);
});
test('policy modified after independent pin is rejected',()=>{
 const i=input();i.policy.reviewers[0].status='REVOKED';
 assert.equal(proposeReviewedDecision(i).reason,'UNTRUSTED_REVIEWER_POLICY');
});
test('old version pin rejected',()=>{
 const i=input();i.trustedPolicyPin.version=2;
 assert.equal(proposeReviewedDecision(i).reason,'UNTRUSTED_REVIEWER_POLICY');
});
test('duplicate transition cannot be reused',()=>{
 const i=input(),first=proposeReviewedDecision(i);
 i.ledger=[first.candidate.entry];i.trustedLedgerHead=first.candidate.head;
 assert.equal(proposeReviewedDecision(i).reason,'REPLAY');
});
test('same registry transition with new ID is also replay',()=>{
 const i=input(),first=proposeReviewedDecision(i);
 i.ledger=[first.candidate.entry];i.trustedLedgerHead=first.candidate.head;
 i.transitionId='transition-002';
 assert.equal(proposeReviewedDecision(i).reason,'REPLAY');
});
test('wrong independent ledger head is refused',()=>{
 const i=input();i.trustedLedgerHead='f'.repeat(64);
 assert.equal(proposeReviewedDecision(i).reason,'LEDGER_TRUSTED_HEAD_CONFLICT');
});
test('tampered ledger item cannot verify',()=>{
 const i=input(),first=proposeReviewedDecision(i);
 assert.equal(verifyReviewLedger([{...first.candidate.entry,transitionId:'changed'}]).ok,false);
});
test('wrong reviewer signature causes HOLD',()=>{
 const i=input();i.reviews[1].signature=i.reviews[0].signature;
 assert.equal(proposeReviewedDecision(i).ok,false);
});
test('malformed and duplicate reviewer policy fails',()=>{
 const i=input();i.policy.reviewers[1].id=i.policy.reviewers[0].id;
 assert.equal(proposeReviewedDecision(i).reason,'INVALID_TRUST_INPUT');
});
