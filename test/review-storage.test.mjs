import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,mkdir,readFile,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {generateKeyPairSync,sign} from 'node:crypto';
import {keyRegistryDigest} from '../src/key-registry.mjs';
import {proposeRegistryTransition} from '../src/registry-transition.mjs';
import {reviewPayload} from '../src/approval-review.mjs';
import {reviewerPolicyDigest,proposeReviewedDecision} from '../src/review-ledger.mjs';
import {commitReviewProposal,inspectReviewStore,reconcileReviewStore,INITIAL_REVIEW_STORE_POSITION as genesis} from '../src/review-storage.mjs';
const ns='PALACO-NEO-TEST';
const owner=generateKeyPairSync('ed25519'),security=generateKeyPairSync('ed25519'),key=generateKeyPairSync('ed25519');
const pem=k=>k.publicKey.export({type:'spki',format:'pem'});
const regkey=id=>({id,publicKeyPem:pem(key),status:'ACTIVE',fromCount:0,throughCount:10});
const old={version:1,namespace:ns,keys:[regkey('key-one'),regkey('key-two')]};
const beforePin={version:1,digest:keyRegistryDigest(old)};
const transition=proposeRegistryTransition(old,beforePin,{type:'REVOKE',keyId:'key-one',replacement:null}).candidate;
const policy={version:1,namespace:ns,reviewers:[
  {id:'owner-review',role:'OWNER',status:'ACTIVE',publicKeyPem:pem(owner)},
  {id:'security-review',role:'SECURITY',status:'ACTIVE',publicKeyPem:pem(security)}
]};
const reviews=[['owner-review',owner],['security-review',security]].map(([reviewerId,k])=>({
 reviewerId,signature:sign(null,reviewPayload(ns,beforePin,transition.pin),k.privateKey).toString('base64')
}));
const evidence={beforeRegistry:old,afterRegistry:transition.registry,
 beforePin,afterPin:transition.pin,reviews,policy,trustedPolicyPin:{version:1,digest:reviewerPolicyDigest(policy)},
 transitionId:'neo-012-review',ledger:[],trustedLedgerHead:genesis.head};
const proposal=proposeReviewedDecision(evidence).candidate;
async function sandbox(fn) {
 const dir=await mkdtemp(join(tmpdir(),'palaco-review012-'));
 try {await fn(dir);} finally {await rm(dir,{recursive:true,force:true});}
}
test('commits verified candidate and can inspect pinned position',()=>sandbox(async dir=>{
 const r=await commitReviewProposal(dir,genesis,evidence);
 assert.equal(r.ok,true);assert.equal(r.authorized,false);
 assert.equal((await inspectReviewStore(dir,r.position)).ok,true);
}));
test('old position cannot overwrite committed data',()=>sandbox(async dir=>{
 const r=await commitReviewProposal(dir,genesis,evidence);
 const before=await readFile(join(dir,'review-ledger.json'),'utf8');
 assert.equal((await commitReviewProposal(dir,genesis,evidence)).reason,'TRUSTED_POSITION_CONFLICT');
 assert.equal(await readFile(join(dir,'review-ledger.json'),'utf8'),before);
 assert.equal((await inspectReviewStore(dir,genesis)).ok,false);
 assert.equal((await reconcileReviewStore(dir,genesis,proposal)).status,'COMMITTED');
 assert.equal(r.authorized,false);
}));
test('pre-existing lock blocks cooperative writer',()=>sandbox(async dir=>{
 await mkdir(join(dir,'.review-ledger.lock'));
 assert.equal((await commitReviewProposal(dir,genesis,evidence)).reason,'LOCKED');
}));
test('corrupted file never resets to genesis',()=>sandbox(async dir=>{
 await writeFile(join(dir,'review-ledger.json'),'{broken');
 assert.equal((await commitReviewProposal(dir,genesis,evidence)).reason,'CORRUPT_STORE');
 assert.equal((await reconcileReviewStore(dir,genesis,proposal)).ok,false);
}));
test('abandoned temporary file never becomes committed state',()=>sandbox(async dir=>{
 await writeFile(join(dir,'.review-ledger-orphan.tmp'),'partial');
 assert.equal((await reconcileReviewStore(dir,genesis,proposal)).status,'NOT_COMMITTED');
}));
test('mutated proposal rejected',()=>sandbox(async dir=>{
 const bad={...evidence,reviews:[{...reviews[0],signature:reviews[1].signature},reviews[1]]};
 assert.equal((await commitReviewProposal(dir,genesis,bad)).ok,false);
}));
test('unknown proposal input rejected',()=>sandbox(async dir=>{
 assert.equal((await commitReviewProposal(dir,genesis,null)).reason,'INVALID_REVIEW_EVIDENCE');
}));
test('missing independent anchor refused',()=>sandbox(async dir=>{
 assert.equal((await commitReviewProposal(dir,null,evidence)).ok,false);
 assert.equal((await inspectReviewStore(dir,null)).ok,false);
}));
