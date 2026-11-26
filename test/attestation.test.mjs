import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {INITIAL_ANCHOR,proposeCheckpoint} from '../src/checkpoint.mjs';
import {checkpointPayload,verifyAttestedCheckpoint} from '../src/attestation.mjs';

const pair=generateKeyPairSync('ed25519');
const other=generateKeyPairSync('ed25519');
const pub=pair.publicKey.export({type:'spki',format:'pem'});
const otherPub=other.publicKey.export({type:'spki',format:'pem'});
const ns='PALACO-NEO-TEST';
const first=proposeCheckpoint([],INITIAL_ANCHOR,
  {requestId:'neo-006-a',decision:'DENY',reason:'GO13_HOLD'}).candidate;
function envelope(anchor=first.anchor,namespace=ns) {
 return {namespace,anchor,signature:sign(null,checkpointPayload(anchor,namespace),pair.privateKey).toString('base64')};
}
const verify=(records,env,publicKey=pub,options={namespace:ns,minimumCount:0})=>
 verifyAttestedCheckpoint(records,env,publicKey,options);
test('valid signed checkpoint verifies but grants no authorization',()=>{
 assert.deepEqual(verify(first.records,envelope()),{ok:true,reason:'ATTESTATION_VERIFIED_NOT_AUTHORIZED',
  authorized:false,anchor:first.anchor});
});
test('forged or wrong key signature is rejected',()=>{
 assert.equal(verify(first.records,envelope(),otherPub).ok,false);
 const env=envelope();env.signature=env.signature.slice(0,1)==='A'?'B'+env.signature.slice(1):'A'+env.signature.slice(1);
 assert.equal(verify(first.records,env).ok,false);
});
test('altered anchor and chain are rejected',()=>{
 assert.equal(verify(first.records,{...envelope(),anchor:INITIAL_ANCHOR}).ok,false);
 assert.equal(verify([] ,envelope()).reason,'CHAIN_MISMATCH');
});
test('wrong domain namespace is rejected',()=>{
 assert.equal(verify(first.records,envelope(),pub,{namespace:'OTHER-NEO',minimumCount:0}).reason,'INVALID_TRUST_INPUT');
});
test('anti-rollback requires independently maintained floor',()=>{
 assert.equal(verify([],envelope(INITIAL_ANCHOR),pub,{namespace:ns,minimumCount:1}).reason,'ROLLBACK_FLOOR');
});
test('noncanonical signatures fail closed',()=>{
 assert.equal(verify(first.records,{...envelope(),signature:'!'}).reason,'INVALID_SIGNATURE');
});
test('malformed trust input never throws',()=>{
 for(const v of [null,{},undefined,{...envelope(),anchor:{count:0,head:55}}])
   assert.equal(verify(first.records,v).ok,false);
});
test('non-Ed25519 public key rejected',()=>{
 const rsa=generateKeyPairSync('rsa',{modulusLength:2048});
 assert.equal(verify(first.records,envelope(),rsa.publicKey.export({type:'spki',format:'pem'})).ok,false);
});
