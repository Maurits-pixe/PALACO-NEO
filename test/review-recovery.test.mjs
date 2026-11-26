import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync, sign} from 'node:crypto';
import {keyRegistryDigest} from '../src/key-registry.mjs';
import {proposeRegistryTransition} from '../src/registry-transition.mjs';
import {reviewPayload} from '../src/approval-review.mjs';
import {reviewerPolicyDigest, proposeReviewedDecision} from '../src/review-ledger.mjs';
import {classifyReviewRecovery,classifyReviewWritePreflight,REVIEW_INITIAL_POSITION} from '../src/review-recovery.mjs';

const namespace='PALACO-NEO-TEST';
const owner=generateKeyPairSync('ed25519'),security=generateKeyPairSync('ed25519');
const active=generateKeyPairSync('ed25519');
const pem=x=>x.publicKey.export({type:'spki',format:'pem'});
const key=id=>({id,publicKeyPem:pem(active),status:'ACTIVE',fromCount:0,throughCount:10});
const old={version:1,namespace,keys:[key('key-001'),key('key-keep')]};
const oldPin={version:1,digest:keyRegistryDigest(old)};
const transition=proposeRegistryTransition(old,oldPin,{type:'REVOKE',keyId:'key-001',replacement:null}).candidate;
const policy={version:1,namespace,reviewers:[
  {id:'review-owner',role:'OWNER',status:'ACTIVE',publicKeyPem:pem(owner)},
  {id:'review-security',role:'SECURITY',status:'ACTIVE',publicKeyPem:pem(security)}
]};
const proof=(id,privateKey)=>({reviewerId:id,
  signature:sign(null,reviewPayload(namespace,oldPin,transition.pin),privateKey).toString('base64')});
const proposal=proposeReviewedDecision({
 beforeRegistry:old,afterRegistry:transition.registry,beforePin:oldPin,afterPin:transition.pin,
 reviews:[proof('review-owner',owner.privateKey),proof('review-security',security.privateKey)],
 policy,trustedPolicyPin:{version:1,digest:reviewerPolicyDigest(policy)},
 transitionId:'neo-011-transition',ledger:[],trustedLedgerHead:REVIEW_INITIAL_POSITION.head
}).candidate;
const existing=[proposal.entry];
test('prewrite state classified as NOT_COMMITTED without authority',()=>{
 assert.deepEqual(classifyReviewRecovery([],REVIEW_INITIAL_POSITION,proposal),
 {status:'NOT_COMMITTED',reason:'MATCHES_PREWRITE_HEAD',authorized:false});
});
test('exact staged proposal is COMMITTED classification, never authorization',()=>{
 assert.deepEqual(classifyReviewRecovery(existing,REVIEW_INITIAL_POSITION,proposal),
 {status:'COMMITTED',reason:'MATCHES_PREWRITE_PROPOSAL',authorized:false});
});
test('mutated record is rejected',()=>{
 assert.equal(classifyReviewRecovery([{...proposal.entry,transitionId:'altered'}],
 REVIEW_INITIAL_POSITION,proposal).status,'HOLD');
});
test('different proposed head is rejected',()=>{
 assert.equal(classifyReviewRecovery(existing,REVIEW_INITIAL_POSITION,
 {...proposal,head:'f'.repeat(64)}).status,'HOLD');
});
test('stale trusted base blocks proposed outcome',()=>{
 assert.equal(classifyReviewRecovery(existing,
 {count:1,head:proposal.head},proposal).status,'HOLD');
});
test('preflight detects a concurrent ledger advance',()=>{
 assert.equal(classifyReviewWritePreflight(existing,REVIEW_INITIAL_POSITION).status,'HOLD');
});
test('preflight matches exact pinned position',()=>{
 assert.equal(classifyReviewWritePreflight([],REVIEW_INITIAL_POSITION).status,'MATCH');
});
test('empty or malformed state fails closed',()=>{
 for(const value of [null,undefined,{},'bad'])
  assert.equal(classifyReviewRecovery([],value,proposal).status,'HOLD');
});
test('preflight rejects forged head and malformed state',()=>{
 assert.equal(classifyReviewWritePreflight(existing,{count:1,head:'f'.repeat(64)}).status,'HOLD');
 assert.equal(classifyReviewWritePreflight(null,REVIEW_INITIAL_POSITION).status,'HOLD');
});
