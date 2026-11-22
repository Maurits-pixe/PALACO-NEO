import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {mkdtemp,writeFile,rm,mkdir,readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {keyRegistryDigest} from '../src/key-registry.mjs';
import {proposeRegistryTransition} from '../src/registry-transition.mjs';
import {reviewPayload} from '../src/approval-review.mjs';
import {reviewerPolicyDigest,proposeReviewedDecision} from '../src/review-ledger.mjs';
import {REVIEW_INITIAL_POSITION as genesis} from '../src/review-recovery.mjs';
import {createRecoveryEvidence} from '../src/recovery-evidence.mjs';
import {recoveryAttestationPayload} from '../src/recovery-attestation.mjs';
import {recoveryChallengeDigest,proposeChallengeConsumption} from '../src/recovery-challenge.mjs';
import {consumeRecoveryChallenge,inspectChallengeRegister} from '../src/recovery-challenge-store.mjs';

const ns='PALACO-NEO-TEST',challenge='a'.repeat(64),otherChallenge='b'.repeat(64);
const witness=generateKeyPairSync('ed25519'),wrong=generateKeyPairSync('ed25519');
const owner=generateKeyPairSync('ed25519'),security=generateKeyPairSync('ed25519');
const k=generateKeyPairSync('ed25519');
const pem=x=>x.publicKey.export({type:'spki',format:'pem'});
const regkey=id=>({id,publicKeyPem:pem(k),status:'ACTIVE',fromCount:0,throughCount:10});
const previous={version:1,namespace:ns,keys:[regkey('key-old'),regkey('key-keep')]};
const beforePin={version:1,digest:keyRegistryDigest(previous)};
const change=proposeRegistryTransition(previous,beforePin,
 {type:'REVOKE',keyId:'key-old',replacement:null}).candidate;
const policy={version:1,namespace:ns,reviewers:[
 {id:'owner-review',role:'OWNER',status:'ACTIVE',publicKeyPem:pem(owner)},
 {id:'security-review',role:'SECURITY',status:'ACTIVE',publicKeyPem:pem(security)}
]};
const review=(id,key)=>({reviewerId:id,signature:sign(null,
 reviewPayload(ns,beforePin,change.pin),key.privateKey).toString('base64')});
const proposal=proposeReviewedDecision({beforeRegistry:previous,afterRegistry:change.registry,
 beforePin,afterPin:change.pin,reviews:[review('owner-review',owner),review('security-review',security)],
 policy,trustedPolicyPin:{version:1,digest:reviewerPolicyDigest(policy)},
 transitionId:'neo-019-test',ledger:[],trustedLedgerHead:genesis.head}).candidate;
const receipt=createRecoveryEvidence([proposal.entry],genesis,proposal).receipt;
const signerId='recovery-witness';
const envelope=(nonce=challenge,key=witness)=>({namespace:ns,challenge:nonce,signerId,receipt,
 signature:sign(null,recoveryAttestationPayload(ns,nonce,signerId,receipt),key.privateKey).toString('base64')});
const trust=(nonce=challenge)=>({namespace:ns,expectedChallenge:nonce,signerId,
 status:'ACTIVE',publicKeyPem:pem(witness),trustedBefore:genesis});
const registry=()=>({schema:'NEO-019-v1',namespace:ns,challenges:[
 {challenge,signerId,status:'ISSUED'},{challenge:otherChallenge,signerId,status:'ISSUED'}]});
async function sandbox(fn){
 const dir=await mkdtemp(join(tmpdir(),'neo019-'));
 try{await fn(dir);}finally{await rm(dir,{recursive:true,force:true});}
}
async function provision(dir,reg){
 await writeFile(join(dir,'recovery-challenges.json'),JSON.stringify(reg)+'\n','utf8');
}
test('valid challenge consumption proposal is non-authorizing',()=>{
 const reg=registry(),p=proposeChallengeConsumption(reg,recoveryChallengeDigest(reg),envelope(),trust());
 assert.equal(p.ok,true);assert.equal(p.authorized,false);
 assert.equal(p.candidate.registry.challenges[0].status,'CONSUMED');
 assert.equal(reg.challenges[0].status,'ISSUED');
});
test('consumed, unknown and duplicate challenges fail closed',()=>{
 const reg=registry(),pin=recoveryChallengeDigest(reg);
 const used={...reg,challenges:reg.challenges.map(e=>({...e,status:'CONSUMED'}))};
 assert.equal(proposeChallengeConsumption(used,recoveryChallengeDigest(used),envelope(),trust()).reason,'REPLAY');
 assert.equal(proposeChallengeConsumption(reg,pin,envelope('f'.repeat(64)),trust('f'.repeat(64))).reason,'UNISSUED_CHALLENGE');
 assert.throws(()=>recoveryChallengeDigest({...reg,challenges:[reg.challenges[0],reg.challenges[0]]}));
});
test('invalid witness signature and stale externally pinned registry fail',()=>{
 const reg=registry();
 assert.equal(proposeChallengeConsumption(reg,recoveryChallengeDigest(reg),
 envelope(challenge,wrong),trust()).ok,false);
 assert.equal(proposeChallengeConsumption(reg,'f'.repeat(64),envelope(),trust()).reason,'TRUSTED_REGISTER_MISMATCH');
});
test('local consume updates state but returns no authorization',()=>sandbox(async dir=>{
 const reg=registry(),before=recoveryChallengeDigest(reg);
 await provision(dir,reg);
 assert.equal((await inspectChallengeRegister(dir,before)).ok,true);
 const consumed=await consumeRecoveryChallenge(dir,before,envelope(),trust());
 assert.equal(consumed.ok,true);assert.equal(consumed.authorized,false);
 assert.equal((await inspectChallengeRegister(dir,consumed.digest)).ok,true);
 assert.equal((await inspectChallengeRegister(dir,before)).ok,false);
}));
test('replay with updated externally pinned digest is denied',()=>sandbox(async dir=>{
 const reg=registry(),pin=recoveryChallengeDigest(reg);await provision(dir,reg);
 const done=await consumeRecoveryChallenge(dir,pin,envelope(),trust());
 assert.equal(done.ok,true);
 const bytes=await readFile(join(dir,'recovery-challenges.json'),'utf8');
 assert.equal((await consumeRecoveryChallenge(dir,done.digest,envelope(),trust())).reason,'REPLAY');
 assert.equal(await readFile(join(dir,'recovery-challenges.json'),'utf8'),bytes);
}));
test('two cooperative concurrent consumers cannot both succeed',()=>sandbox(async dir=>{
 const reg=registry(),pin=recoveryChallengeDigest(reg);await provision(dir,reg);
 const results=await Promise.all([
  consumeRecoveryChallenge(dir,pin,envelope(),trust()),
  consumeRecoveryChallenge(dir,pin,envelope(),trust())
 ]);
 assert.equal(results.filter(x=>x.ok).length,1);
 assert.equal(results.filter(x=>!x.ok).length,1);
}));
test('missing registry, corrupt registry and stale lock are denied',()=>sandbox(async dir=>{
 const pin=recoveryChallengeDigest(registry());
 assert.equal((await consumeRecoveryChallenge(dir,pin,envelope(),trust())).reason,'MISSING_OR_CORRUPT_REGISTER');
 await writeFile(join(dir,'recovery-challenges.json'),'{invalid');
 assert.equal((await consumeRecoveryChallenge(dir,pin,envelope(),trust())).reason,'MISSING_OR_CORRUPT_REGISTER');
 await provision(dir,registry());
 await mkdir(join(dir,'.recovery-challenges.lock'));
 assert.equal((await consumeRecoveryChallenge(dir,pin,envelope(),trust())).reason,'LOCKED');
}));
test('unsigned or unissued register cannot authenticate itself',()=>{
 const reg=registry();
 assert.equal(proposeChallengeConsumption(reg,recoveryChallengeDigest(reg),envelope(),
 {...trust(),status:'REVOKED'}).ok,false);
 assert.equal(proposeChallengeConsumption(reg,recoveryChallengeDigest(reg),
 {...envelope(),signerId:'other-signer'},trust()).reason,'SIGNER_MISMATCH');
});
