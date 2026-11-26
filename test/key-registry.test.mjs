import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync, sign} from 'node:crypto';
import {INITIAL_ANCHOR, proposeCheckpoint} from '../src/checkpoint.mjs';
import {checkpointPayload} from '../src/attestation.mjs';
import {keyRegistryDigest,verifyRegistryAttestation} from '../src/key-registry.mjs';

const ns='PALACO-NEO-TEST';
const pair=generateKeyPairSync('ed25519'), next=generateKeyPairSync('ed25519');
const pem = p => p.publicKey.export({type:'spki',format:'pem'});
const one=proposeCheckpoint([],INITIAL_ANCHOR,
 {requestId:'neo-007-a',decision:'DENY',reason:'GO13_HOLD'}).candidate;
const two=proposeCheckpoint(one.records,one.anchor,
 {requestId:'neo-007-b',decision:'DENY',reason:'GO13_HOLD'}).candidate;
const entry=(keyId='key-001',pairKey=pair,status='ACTIVE',fromCount=0,throughCount=10)=>
 ({id:keyId,publicKeyPem:pem(pairKey),status,fromCount,throughCount});
const registry=(keys=[entry()],version=1)=>({version,namespace:ns,keys});
const signed=(anchor=one.anchor, keyPair=pair,keyId='key-001')=>
 ({namespace:ns,anchor,keyId,
   signature:sign(null,checkpointPayload(anchor,ns),keyPair.privateKey).toString('base64')});
const options=(reg, trustedFloor=INITIAL_ANCHOR)=>({
 namespace:ns,trustedRegistryDigest:keyRegistryDigest(reg),minimumRegistryVersion:1,trustedFloor
});
test('pinned registry attests without authorizing',()=>{
 const reg=registry(), r=verifyRegistryAttestation(one.records,signed(),reg,options(reg));
 assert.equal(r.ok,true);assert.equal(r.authorized,false);
});
test('registry tampering is detected against independent pin',()=>{
 const reg=registry();
 assert.equal(verifyRegistryAttestation(one.records,signed(),{...reg,version:2},options(reg)).reason,
 'REGISTRY_DIGEST_MISMATCH');
});
test('revoked key is denied even for historical signatures',()=>{
 const reg=registry([entry('key-001',pair,'REVOKED')]);
 assert.equal(verifyRegistryAttestation(one.records,signed(),reg,options(reg)).reason,'REVOKED_KEY');
});
test('unknown key and invalid signature fail',()=>{
 const reg=registry();
 assert.equal(verifyRegistryAttestation(one.records,{...signed(),keyId:'key-999'},reg,options(reg)).reason,'UNKNOWN_KEY');
 assert.equal(verifyRegistryAttestation(one.records,signed(one.anchor,next),reg,options(reg)).ok,false);
});
test('rotation supports new key at later count but rejects early key use',()=>{
 const reg=registry([entry('key-001',pair,'ACTIVE',0,1),entry('key-002',next,'ACTIVE',2,10)]);
 const r=verifyRegistryAttestation(two.records,signed(two.anchor,next,'key-002'),reg,options(reg));
 assert.equal(r.ok,true);
 assert.equal(verifyRegistryAttestation(one.records,signed(one.anchor,next,'key-002'),reg,options(reg)).reason,
 'KEY_OUTSIDE_VALIDITY_WINDOW');
});
test('minimum registry version blocks stale registry',()=>{
 const reg=registry();
 assert.equal(verifyRegistryAttestation(one.records,signed(),reg,
 {...options(reg),minimumRegistryVersion:2}).reason,'STALE_REGISTRY');
});
test('floor head rejects fork and rollback',()=>{
 const reg=registry();
 assert.equal(verifyRegistryAttestation(two.records,signed(two.anchor),reg,
 options(reg,{count:1,head:'f'.repeat(64)})).reason,'TRUSTED_FLOOR_CONFLICT');
 assert.equal(verifyRegistryAttestation(one.records,signed(),reg,
 options(reg,{count:2,head:two.anchor.head})).reason,'ROLLBACK_FLOOR');
});
test('correct nonzero floor accepts descendant',()=>{
 const reg=registry();
 assert.equal(verifyRegistryAttestation(two.records,signed(two.anchor),reg,
 options(reg,one.anchor)).ok,true);
});
test('duplicate key IDs and invalid registry fail closed',()=>{
 const reg=registry([entry(),entry()]);
 assert.throws(()=>keyRegistryDigest(reg),/INVALID_REGISTRY/);
 assert.equal(verifyRegistryAttestation(one.records,signed(),reg,{
 namespace:ns,trustedRegistryDigest:'0'.repeat(64),minimumRegistryVersion:1,trustedFloor:INITIAL_ANCHOR
 }).ok,false);
});
test('registry digest stable across key reordering',()=>{
 const a=entry(),b=entry('key-002',next);
 assert.equal(keyRegistryDigest(registry([a,b])),keyRegistryDigest(registry([b,a])));
});
