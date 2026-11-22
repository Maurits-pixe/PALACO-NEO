import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {mkdtemp,rm,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {keyRegistryDigest} from '../src/key-registry.mjs';
import {reviewPayload} from '../src/approval-review.mjs';
import {proposeRegistryTransition} from '../src/registry-transition.mjs';
import {reviewerPolicyDigest} from '../src/review-ledger.mjs';
import {commitReviewProposal,INITIAL_REVIEW_STORE_POSITION as genesis} from '../src/review-storage.mjs';

const ns='PALACO-NEO-TEST';
const owner=generateKeyPairSync('ed25519');
const security=generateKeyPairSync('ed25519');
const key=generateKeyPairSync('ed25519');
const pem=k=>k.publicKey.export({type:'spki',format:'pem'});
const keyEntry=id=>({id,publicKeyPem:pem(key),status:'ACTIVE',fromCount:0,throughCount:20});
const before={version:1,namespace:ns,keys:[keyEntry('key-first'),keyEntry('key-other')]};
const beforePin={version:1,digest:keyRegistryDigest(before)};
const next=proposeRegistryTransition(before,beforePin,
  {type:'REVOKE',keyId:'key-first',replacement:null}).candidate;
const policy=()=>({version:1,namespace:ns,reviewers:[
  {id:'owner-id',role:'OWNER',status:'ACTIVE',publicKeyPem:pem(owner)},
  {id:'security-id',role:'SECURITY',status:'ACTIVE',publicKeyPem:pem(security)}
]});
const signature=(k)=>sign(null,reviewPayload(ns,beforePin,next.pin),k.privateKey).toString('base64');
const evidence=()=>{
  const p=policy();
  return {beforeRegistry:before,afterRegistry:next.registry,beforePin,afterPin:next.pin,
    reviews:[{reviewerId:'owner-id',signature:signature(owner)},
             {reviewerId:'security-id',signature:signature(security)}],
    policy:p,trustedPolicyPin:{version:p.version,digest:reviewerPolicyDigest(p)},
    transitionId:'neo-013-sec',ledger:[],trustedLedgerHead:genesis.head};
};
async function sandbox(fn){
 const dir=await mkdtemp(join(tmpdir(),'neo013-'));
 try {await fn(dir);} finally {await rm(dir,{recursive:true,force:true});}
}
test('signed evidence accepted only as stored review evidence, no authorization',()=>sandbox(async dir=>{
 const result=await commitReviewProposal(dir,genesis,evidence());
 assert.equal(result.ok,true);assert.equal(result.authorized,false);
}));
test('forged reviewer signature cannot reach disk',()=>sandbox(async dir=>{
 const e=evidence();e.reviews[0].signature=e.reviews[1].signature;
 assert.equal((await commitReviewProposal(dir,genesis,e)).ok,false);
 await assert.rejects(readFile(join(dir,'review-ledger.json')));
}));
test('revoked reviewer cannot write even with valid signature',()=>sandbox(async dir=>{
 const e=evidence();e.policy.reviewers[0].status='REVOKED';
 e.trustedPolicyPin={version:1,digest:reviewerPolicyDigest(e.policy)};
 assert.equal((await commitReviewProposal(dir,genesis,e)).ok,false);
}));
test('tampered independently pinned reviewer policy denied',()=>sandbox(async dir=>{
 const e=evidence();e.policy.reviewers[1].status='REVOKED';
 assert.equal((await commitReviewProposal(dir,genesis,e)).ok,false);
}));
test('fabricated raw proposal does not bypass review',()=>sandbox(async dir=>{
 const raw={entry:{sequence:1,previousHash:genesis.head,hash:'a'.repeat(64)},head:'a'.repeat(64)};
 assert.equal((await commitReviewProposal(dir,genesis,raw)).ok,false);
}));
test('replaying same evidence does not create second entry',()=>sandbox(async dir=>{
 const e=evidence(),first=await commitReviewProposal(dir,genesis,e);
 assert.equal(first.ok,true);
 const beforeBytes=await readFile(join(dir,'review-ledger.json'),'utf8');
 assert.equal((await commitReviewProposal(dir,genesis,e)).ok,false);
 assert.equal(await readFile(join(dir,'review-ledger.json'),'utf8'),beforeBytes);
}));
test('client-supplied fake ledger is replaced by actual locked store state',()=>sandbox(async dir=>{
 const e=evidence();
 e.ledger=[{sequence:1,hash:'a'.repeat(64)}];e.trustedLedgerHead='f'.repeat(64);
 assert.equal((await commitReviewProposal(dir,genesis,e)).ok,true);
}));
test('malformed trust policy cannot store record',()=>sandbox(async dir=>{
 const e=evidence();e.trustedPolicyPin.digest='f'.repeat(64);
 assert.equal((await commitReviewProposal(dir,genesis,e)).ok,false);
}));
