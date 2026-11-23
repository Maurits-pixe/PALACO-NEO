import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {keyQuorumPolicyDigest} from '../src/cas-key-quorum.mjs';
import {policySuccessionPayload,policySuccessionEntryHash,
 verifyPolicySuccessionChain,INITIAL_POLICY_SUCCESSION_POSITION as genesis}
 from '../src/cas-policy-succession.mjs';

const namespace='PALACO-NEO-TEST';
const owner=generateKeyPairSync('ed25519');
const security=generateKeyPairSync('ed25519');
const replacement=generateKeyPairSync('ed25519');
const attacker=generateKeyPairSync('ed25519');
const pem=x=>x.publicKey.export({type:'spki',format:'pem'});
const base=()=>({schema:'NEO-027-POLICY-v1',namespace,version:1,reviewers:[
 {reviewerId:'review-owner',role:'OWNER',status:'ACTIVE',publicKeyPem:pem(owner)},
 {reviewerId:'review-security',role:'SECURITY',status:'ACTIVE',publicKeyPem:pem(security)}
]});
const pin=p=>({version:p.version,digest:keyQuorumPolicyDigest(p)});
const added=(previous=base())=>({schema:'NEO-027-POLICY-v1',namespace,
 version:previous.version+1,reviewers:[...previous.reviewers,
 {reviewerId:'owner-extra',role:'OWNER',status:'ACTIVE',publicKeyPem:pem(replacement)}]});
const revoked=(previous=added())=>({...previous,version:previous.version+1,
 reviewers:previous.reviewers.map(r=>r.reviewerId==='owner-extra'?{...r,status:'REVOKED'}:{...r})});
const create=(previous,next,sequence,previousHash,changeId,keys=[owner,security])=>{
 const body={namespace,sequence,previousHash,changeId,
  beforeVersion:previous.version,beforeDigest:keyQuorumPolicyDigest(previous),
  afterVersion:next.version,afterDigest:keyQuorumPolicyDigest(next)};
 const reviews=[['review-owner','OWNER',keys[0]],['review-security','SECURITY',keys[1]]]
   .map(([reviewerId,role,key])=>({reviewerId,signature:sign(null,
      policySuccessionPayload(body,reviewerId,role),key.privateKey).toString('base64')}));
 return {...body,nextPolicy:next,reviews,hash:policySuccessionEntryHash(body,reviews)};
};
const first=()=>create(base(),added(),1,genesis.head,'change-001');
const check=(events,opts={})=>verifyPolicySuccessionChain(events,
 opts.initial??base(),opts.pin??pin(base()),opts.floor??genesis);
test('independent old-policy OWNER+SECURITY signatures validate one reviewer addition',()=>{
 const e=first(),r=check([e]);
 assert.equal(r.ok,true);assert.equal(r.authorized,false);
 assert.equal(r.policy.version,2);assert.equal(r.position.head,e.hash);
});
test('successive change is validated against the policy in force before that change',()=>{
 const a=first(),b=create(added(),revoked(),2,a.hash,'change-002');
 const r=check([a,b]);
 assert.equal(r.ok,true);assert.equal(r.policy.version,3);
 assert.equal(r.policy.reviewers[2].status,'REVOKED');
});
test('role reassignment of existing reviewer is forbidden',()=>{
 const next=added();next.reviewers[0]={...next.reviewers[0],role:'SECURITY'};
 next.reviewers[2]={...next.reviewers[2],role:'OWNER'};
 assert.equal(check([create(base(),next,1,genesis.head,'change-001')]).reason,
  'UNEXPECTED_POLICY_TRANSITION');
});
test('two changes in one event are forbidden',()=>{
 const next=added();next.reviewers[0]={...next.reviewers[0],status:'REVOKED'};
 assert.equal(check([create(base(),next,1,genesis.head,'change-001')]).reason,
  'UNEXPECTED_POLICY_TRANSITION');
});
test('unsigned or forged old-policy signature refused',()=>{
 const e=create(base(),added(),1,genesis.head,'change-001',[attacker,security]);
 assert.equal(check([e]).reason,'INVALID_REVIEW_SIGNATURE');
});
test('missing and duplicate quorum reviews refused',()=>{
 const e=first(),only={...e,reviews:e.reviews.slice(0,1)};
 assert.equal(check([only]).ok,false);
 const dup={...e,reviews:[e.reviews[0],e.reviews[0]]};
 assert.equal(check([dup]).reason,'DUPLICATE_REVIEWER');
});
test('newly added reviewer cannot retroactively approve their own addition',()=>{
 const e=first(),body=Object.fromEntries(['namespace','sequence','previousHash',
 'changeId','beforeVersion','beforeDigest','afterVersion','afterDigest'].map(k=>[k,e[k]]));
 const forged={reviewerId:'owner-extra',signature:sign(null,
  policySuccessionPayload(body,'owner-extra','OWNER'),replacement.privateKey).toString('base64')};
 const substituted={...e,reviews:[forged,e.reviews[1]]};
 assert.equal(check([substituted]).reason,'UNKNOWN_OR_REVOKED_REVIEWER');
});
test('old policy pin mismatch refuses all events',()=>{
 const e=first();assert.equal(check([e],{pin:{version:1,digest:'f'.repeat(64)}}).reason,
  'UNTRUSTED_INITIAL_POLICY');
});
test('untrusted successor policy edit is detected',()=>{
 const e=first(),modified={...e,nextPolicy:revoked()};
 assert.equal(check([modified]).ok,false);
});
test('rollback below trusted head and forked trusted head rejected',()=>{
 const e=first(),trusted={count:1,head:e.hash};
 assert.equal(check([],{floor:trusted}).reason,'ROLLBACK_BELOW_TRUSTED_FLOOR');
 assert.equal(check([e],{floor:{count:1,head:'f'.repeat(64)}}).reason,
  'TRUSTED_FLOOR_CONFLICT');
});
test('duplicate event ID and chain tampering fail closed',()=>{
 const e=first(),next=create(added(),revoked(),2,e.hash,'change-001');
 assert.equal(check([e,next]).ok,false);
 assert.equal(check([{...e,hash:'f'.repeat(64)}]).reason,'BROKEN_CHAIN_HASH');
});
test('cannot revoke the only active OWNER or SECURITY',()=>{
 const previous=base(),next={...previous,version:2,
  reviewers:previous.reviewers.map(r=>r.role==='OWNER'?{...r,status:'REVOKED'}:r)};
 assert.equal(check([create(previous,next,1,genesis.head,'change-001')]).reason,
  'UNEXPECTED_POLICY_TRANSITION');
});
test('single key rotation is allowed only when signed by prior key',()=>{
 const previous=base(),next={...previous,version:2,
  reviewers:previous.reviewers.map(r=>r.role==='OWNER'?
   {...r,publicKeyPem:pem(replacement)}:r)};
 assert.equal(check([create(previous,next,1,genesis.head,'rotate-owner')]).ok,true);
 const wrong=create(previous,next,1,genesis.head,'rotate-owner',[replacement,security]);
 assert.equal(check([wrong]).reason,'INVALID_REVIEW_SIGNATURE');
});
test('empty chain validates the pinned initial policy but grants no authority',()=>{
 const r=check([]);assert.equal(r.ok,true);assert.equal(r.authorized,false);
});
