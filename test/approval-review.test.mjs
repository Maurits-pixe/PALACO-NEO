import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {keyRegistryDigest} from '../src/key-registry.mjs';
import {proposeRegistryTransition} from '../src/registry-transition.mjs';
import {reviewPayload,verifyDualReview} from '../src/approval-review.mjs';
const owner=generateKeyPairSync('ed25519');
const security=generateKeyPairSync('ed25519');
const impostor=generateKeyPairSync('ed25519');
const keypair=generateKeyPairSync('ed25519');
const ns='PALACO-NEO-TEST';
const pem=k=>k.publicKey.export({type:'spki',format:'pem'});
const key=(name)=>({id:name,publicKeyPem:pem(keypair),status:'ACTIVE',fromCount:0,throughCount:10});
const before={version:1,namespace:ns,keys:[key('key-001'),key('key-keep')]};
const oldPin={version:1,digest:keyRegistryDigest(before)};
const proposed=proposeRegistryTransition(before,oldPin,{type:'REVOKE',keyId:'key-001',replacement:null});
const after=proposed.candidate.registry;
const newPin=proposed.candidate.pin;
const trusted=[{id:'review-owner',publicKeyPem:pem(owner),role:'OWNER'},
 {id:'review-security',publicKeyPem:pem(security),role:'SECURITY'}];
const signature=(k,b=oldPin,a=newPin)=>sign(null,reviewPayload(ns,b,a),k.privateKey).toString('base64');
const reviews=()=>[{reviewerId:'review-owner',signature:signature(owner)},
 {reviewerId:'review-security',signature:signature(security)}];
const check=(r=reviews(),trustedKeys=trusted,b=oldPin,a=newPin,beforeReg=before,afterReg=after)=>
 verifyDualReview(beforeReg,afterReg,b,a,r,trustedKeys,ns);
test('two distinct independently trusted roles verify without authority',()=>{
 assert.deepEqual(check(),{ok:true,reason:'DUAL_REVIEW_VERIFIED_NO_AUTHORITY',authorized:false});
});
test('one review insufficient',()=>assert.equal(check(reviews().slice(0,1)).reason,'INVALID_REVIEW_SET'));
test('duplicate reviewer forbidden',()=>{
 const r=reviews();r[1]={...r[0]};
 assert.equal(check(r).reason,'DUPLICATE_OR_INVALID_REVIEW');
});
test('same-role quorum is rejected',()=>{
 const alt=[trusted[0],{...trusted[1],role:'OWNER'}];
 assert.equal(check(reviews(),alt).reason,'ROLE_SEPARATION_REQUIRED');
});
test('foreign signature rejected',()=>{
 const r=reviews();r[1].signature=signature(impostor);
 assert.equal(check(r).reason,'UNTRUSTED_OR_INVALID_SIGNATURE');
});
test('altered transition pin rejected',()=>{
 const altered={...newPin,digest:'a'.repeat(64)};
 assert.equal(check(reviews(),trusted,oldPin,altered).reason,'PIN_MISMATCH');
});
test('reviewer trust list cannot contain duplicate IDs',()=>{
 assert.equal(check(reviews(),[trusted[0],trusted[0]]).reason,'INVALID_REVIEWER_TRUST');
});
test('altered registry denied even with valid signatures',()=>{
 assert.equal(check(reviews(),trusted,oldPin,newPin,before,
  {...after,version:3}).reason,'INVALID_TRANSITION');
});
test('signature is bound to correct checkpoint pair',()=>{
 const r=reviews();r[1].signature=signature(security,
  {version:1,digest:'b'.repeat(64)},newPin);
 assert.equal(check(r).reason,'UNTRUSTED_OR_INVALID_SIGNATURE');
});
test('untrusted signer ID fails closed',()=>{
 const r=reviews();r[0].reviewerId='review-stranger';
 assert.equal(check(r).reason,'UNTRUSTED_OR_INVALID_SIGNATURE');
});
