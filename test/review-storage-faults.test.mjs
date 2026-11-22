import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {mkdtemp,rm,writeFile,readFile,rename,mkdir,readdir} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {keyRegistryDigest} from '../src/key-registry.mjs';
import {reviewPayload} from '../src/approval-review.mjs';
import {proposeRegistryTransition} from '../src/registry-transition.mjs';
import {reviewerPolicyDigest,proposeReviewedDecision} from '../src/review-ledger.mjs';
import {commitReviewProposal,inspectReviewStore,reconcileReviewStore,
 INITIAL_REVIEW_STORE_POSITION as genesis} from '../src/review-storage.mjs';

const ns='PALACO-NEO-TEST';
const owner=generateKeyPairSync('ed25519');
const security=generateKeyPairSync('ed25519');
const signer=generateKeyPairSync('ed25519');
const pem=k=>k.publicKey.export({type:'spki',format:'pem'});
const regKey=id=>({id,publicKeyPem:pem(signer),status:'ACTIVE',fromCount:0,throughCount:20});
const before={version:1,namespace:ns,keys:[regKey('key-first'),regKey('key-other')]};
const beforePin={version:1,digest:keyRegistryDigest(before)};
const after=proposeRegistryTransition(before,beforePin,
 {type:'REVOKE',keyId:'key-first',replacement:null}).candidate;
const policy={version:1,namespace:ns,reviewers:[
 {id:'review-owner',role:'OWNER',status:'ACTIVE',publicKeyPem:pem(owner)},
 {id:'review-security',role:'SECURITY',status:'ACTIVE',publicKeyPem:pem(security)}
]};
const reviews=[['review-owner',owner],['review-security',security]].map(([reviewerId,k])=>({
 reviewerId,signature:sign(null,reviewPayload(ns,beforePin,after.pin),k.privateKey).toString('base64')
}));
const input=()=>({beforeRegistry:before,afterRegistry:after.registry,beforePin,
 afterPin:after.pin,reviews,policy,trustedPolicyPin:{version:1,digest:reviewerPolicyDigest(policy)},
 transitionId:'neo-015-fault',ledger:[],trustedLedgerHead:genesis.head});
const proposal=proposeReviewedDecision(input()).candidate;
async function sandbox(fn) {
 const dir=await mkdtemp(join(tmpdir(),'neo015-fault-'));
 try {await fn(dir);} finally {await rm(dir,{recursive:true,force:true});}
}
test('simulated interrupted temp-file write leaves trusted genesis intact',()=>sandbox(async dir=>{
 await writeFile(join(dir,'.review-ledger-interrupted.tmp'),'{half-written');
 assert.equal((await inspectReviewStore(dir,genesis)).ok,true);
 assert.equal((await reconcileReviewStore(dir,genesis,proposal)).status,'NOT_COMMITTED');
}));
test('corrupted temp plus recovered valid state leaves trusted head intact',()=>sandbox(async dir=>{
 const first=await commitReviewProposal(dir,genesis,input());
 assert.equal(first.ok,true);
 await writeFile(join(dir,'.review-ledger-interrupted.tmp'),'bad-utf8');
 assert.equal((await inspectReviewStore(dir,first.position)).ok,true);
 assert.equal((await reconcileReviewStore(dir,genesis,proposal)).status,'COMMITTED');
}));
test('simulated state deletion is rejected against non-genesis trusted head',()=>sandbox(async dir=>{
 const first=await commitReviewProposal(dir,genesis,input());
 assert.equal(first.ok,true);
 await rm(join(dir,'review-ledger.json'));
 assert.equal((await inspectReviewStore(dir,first.position)).reason,'TRUSTED_POSITION_CONFLICT');
 assert.equal((await reconcileReviewStore(dir,{...first.position},proposal)).status,'HOLD');
}));
test('simulated torn state write is refused, not reset',()=>sandbox(async dir=>{
 await writeFile(join(dir,'review-ledger.json'),'{"schema":"NEO-012-v1","entries":[');
 assert.equal((await inspectReviewStore(dir,genesis)).reason,'CORRUPT_STORE');
 assert.equal((await commitReviewProposal(dir,genesis,input())).reason,'CORRUPT_STORE');
}));
test('cooperative simultaneous writes cannot both commit',()=>sandbox(async dir=>{
 const [a,b]=await Promise.all([
  commitReviewProposal(dir,genesis,input()),commitReviewProposal(dir,genesis,input())]);
 assert.equal([a,b].filter(x=>x.ok).length,1);
 assert.equal([a,b].filter(x=>!x.ok).length,1);
 const winner=[a,b].find(x=>x.ok);
 assert.equal((await inspectReviewStore(dir,winner.position)).ok,true);
}));
test('simulated lock left by crashed writer is never stolen',()=>sandbox(async dir=>{
 await mkdir(join(dir,'.review-ledger.lock'));
 assert.equal((await commitReviewProposal(dir,genesis,input())).reason,'LOCKED');
 assert.equal((await readdir(dir)).includes('.review-ledger.lock'),true);
}));
test('unexpected valid but unpinned ledger is rejected',()=>sandbox(async dir=>{
 const first=await commitReviewProposal(dir,genesis,input());
 assert.equal(first.ok,true);
 const state=JSON.parse(await readFile(join(dir,'review-ledger.json'),'utf8'));
 state.entries[0].transitionId='tampered';
 await writeFile(join(dir,'review-ledger.json'),JSON.stringify(state));
 assert.equal((await inspectReviewStore(dir,first.position)).reason,'CORRUPT_STORE');
}));
test('no automatic retry after initial duplicate/replayed write',()=>sandbox(async dir=>{
 const first=await commitReviewProposal(dir,genesis,input());
 assert.equal(first.ok,true);
 const bytes=await readFile(join(dir,'review-ledger.json'),'utf8');
 const again=await commitReviewProposal(dir,first.position,input());
 assert.equal(again.ok,false);
 assert.equal(again.reason,'REVIEW_REPLAY');
 assert.equal(await readFile(join(dir,'review-ledger.json'),'utf8'),bytes);
}));
