import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {mkdtemp,rm,mkdir,readdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {generateKeyPairSync,sign} from 'node:crypto';
import {keyRegistryDigest} from '../src/key-registry.mjs';
import {proposeRegistryTransition} from '../src/registry-transition.mjs';
import {reviewPayload} from '../src/approval-review.mjs';
import {reviewerPolicyDigest,proposeReviewedDecision} from '../src/review-ledger.mjs';
import {inspectReviewStore,reconcileReviewStore,commitReviewProposal,
 INITIAL_REVIEW_STORE_POSITION as genesis} from '../src/review-storage.mjs';

const ns='PALACO-NEO-TEST';
const owner=generateKeyPairSync('ed25519'),security=generateKeyPairSync('ed25519');
const key=generateKeyPairSync('ed25519');
const pem=k=>k.publicKey.export({type:'spki',format:'pem'});
const regkey=id=>({id,publicKeyPem:pem(key),status:'ACTIVE',fromCount:0,throughCount:30});
const before={version:1,namespace:ns,keys:[regkey('key-old'),regkey('key-keep')]};
const beforePin={version:1,digest:keyRegistryDigest(before)};
const after=proposeRegistryTransition(before,beforePin,
 {type:'REVOKE',keyId:'key-old',replacement:null}).candidate;
const policy={version:1,namespace:ns,reviewers:[
 {id:'review-owner',role:'OWNER',status:'ACTIVE',publicKeyPem:pem(owner)},
 {id:'review-security',role:'SECURITY',status:'ACTIVE',publicKeyPem:pem(security)}
]};
const proofs=[['review-owner',owner],['review-security',security]].map(([reviewerId,k])=>({
 reviewerId,signature:sign(null,reviewPayload(ns,beforePin,after.pin),k.privateKey).toString('base64')
}));
const evidence={beforeRegistry:before,afterRegistry:after.registry,beforePin,afterPin:after.pin,
 reviews:proofs,policy,trustedPolicyPin:{version:1,digest:reviewerPolicyDigest(policy)},
 transitionId:'neo-016-crash',ledger:[],trustedLedgerHead:genesis.head};
const proposal=proposeReviewedDecision(evidence).candidate;
async function sandbox(fn) {
 const dir=await mkdtemp(join(tmpdir(),'neo016-crash-'));
 try {await fn(dir);} finally {await rm(dir,{recursive:true,force:true});}
}
/** Spawn and SIGKILL an isolated process at a controlled filesystem boundary.
 * This is not a power-loss/fsync durability test or a kill inside the adapter.
 */
async function killAtBoundary(directory,stage,body) {
 const code=`
 import {mkdir,writeFile,rename} from 'node:fs/promises';
 import {join} from 'node:path';
 const dir=process.argv[1],stage=process.argv[2],body=process.argv[3];
 await mkdir(join(dir,'.review-ledger.lock'));
 const temp=join(dir,'.review-ledger-interrupted.tmp');
 await writeFile(temp,body,'utf8');
 if(stage==='AFTER_RENAME') await rename(temp,join(dir,'review-ledger.json'));
 if(process.send) process.send('READY');
 setInterval(()=>{},1000);
 `;
 const child=spawn(process.execPath,['--input-type=module','-e',code,directory,stage,body],
   {stdio:['ignore','ignore','pipe','ipc']});
 const ready=await new Promise((resolve,reject)=>{
   const timeout=setTimeout(()=>reject(new Error('CHILD_READY_TIMEOUT')),5000);
   child.once('message',v=>{clearTimeout(timeout);resolve(v);});
   child.once('error',e=>{clearTimeout(timeout);reject(e);});
   child.once('exit',(code,signal)=>{clearTimeout(timeout);reject(new Error('CHILD_EXIT_'+code+'_'+signal));});
 });
 assert.equal(ready,'READY');
 const exit=new Promise(resolve=>child.once('exit',(code,signal)=>resolve({code,signal})));
 child.kill('SIGKILL');
 const outcome=await exit;
 assert.equal(outcome.signal,'SIGKILL');
}
test('killed process before rename leaves stale lock and uncommitted state', {skip:process.platform==='win32'},()=>sandbox(async dir=>{
 await killAtBoundary(dir,'BEFORE_RENAME','{partial');
 assert.equal((await inspectReviewStore(dir,genesis)).ok,true);
 assert.equal((await reconcileReviewStore(dir,genesis,proposal)).status,'NOT_COMMITTED');
 assert.equal((await commitReviewProposal(dir,genesis,evidence)).reason,'LOCKED');
 assert.equal((await readdir(dir)).includes('.review-ledger.lock'),true);
}));
test('killed process after rename is classified via independent proposal', {skip:process.platform==='win32'},()=>sandbox(async dir=>{
 const payload=JSON.stringify({schema:'NEO-012-v1',entries:[proposal.entry]})+'\n';
 await killAtBoundary(dir,'AFTER_RENAME',payload);
 const result=await reconcileReviewStore(dir,genesis,proposal);
 assert.equal(result.status,'COMMITTED');
 assert.equal(result.authorized,false);
 assert.equal((await commitReviewProposal(dir,genesis,evidence)).reason,'LOCKED');
}));
test('operator-assisted lock cleanup is external, adapter never steals it', {skip:process.platform==='win32'},()=>sandbox(async dir=>{
 await killAtBoundary(dir,'BEFORE_RENAME','partial');
 assert.equal((await commitReviewProposal(dir,genesis,evidence)).reason,'LOCKED');
 await rm(join(dir,'.review-ledger.lock'),{recursive:true});
 const result=await commitReviewProposal(dir,genesis,evidence);
 assert.equal(result.ok,true);
 assert.equal(result.authorized,false);
}));
