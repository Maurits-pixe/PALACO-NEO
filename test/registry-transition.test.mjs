import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync} from 'node:crypto';
import {keyRegistryDigest} from '../src/key-registry.mjs';
import {proposeRegistryTransition,reconcileRegistryTransition} from '../src/registry-transition.mjs';

const publicKey=()=>generateKeyPairSync('ed25519').publicKey.export({type:'spki',format:'pem'});
const oldKey=publicKey(),newKey=publicKey();
const key=(id,pem,status='ACTIVE')=>({id,publicKeyPem:pem,status,fromCount:0,throughCount:100});
const base=()=>({version:1,namespace:'PALACO-NEO-TEST',
 keys:[key('key-001',oldKey),key('key-keep',newKey)]});
const pin=r=>({version:r.version,digest:keyRegistryDigest(r)});
const change=(type='REVOKE',replacement=null)=>({type,keyId:'key-001',replacement});

test('revocation creates a new immutable proposal without mutating base',()=>{
 const original=base(),proposal=proposeRegistryTransition(original,pin(original),change());
 assert.equal(proposal.ok,true);assert.equal(proposal.authorized,false);
 assert.equal(proposal.candidate.registry.version,2);
 assert.equal(proposal.candidate.registry.keys[0].status,'REVOKED');
 assert.equal(original.keys[0].status,'ACTIVE');
 assert.equal(Object.isFrozen(proposal.candidate.registry.keys[0]),true);
});
test('unknown base hash and stale pins refuse changes',()=>{
 const r=base(),p=pin(r);
 assert.equal(proposeRegistryTransition(r,{...p,digest:'a'.repeat(64)},change()).reason,'UNTRUSTED_BASE');
 assert.equal(proposeRegistryTransition(r,{...p,version:2},change()).ok,false);
});
test('cannot revoke final active key',()=>{
 const r=base();r.keys.pop();
 assert.equal(proposeRegistryTransition(r,pin(r),change()).reason,'NO_ACTIVE_KEY');
});
test('rotation retains existing key history and appends new key',()=>{
 const r=base(),replacement=key('key-002',publicKey());
 const p=proposeRegistryTransition(r,pin(r),change('ROTATE',replacement));
 assert.equal(p.ok,true);assert.equal(p.candidate.registry.keys.length,3);
 assert.equal(p.candidate.registry.keys[0].publicKeyPem,oldKey);
 assert.equal(p.candidate.registry.keys[0].status,'REVOKED');
});
test('duplicate replacement id and invalid replacement refused',()=>{
 const r=base();
 assert.equal(proposeRegistryTransition(r,pin(r),change('ROTATE',key('key-keep',publicKey()))).reason,'INVALID_REPLACEMENT');
 assert.equal(proposeRegistryTransition(r,pin(r),change('ROTATE',null)).reason,'INVALID_REPLACEMENT');
});
test('inactive and unknown key refused',()=>{
 const r=base();r.keys[0].status='REVOKED';
 assert.equal(proposeRegistryTransition(r,pin(r),change()).reason,'NOT_ACTIVE');
 assert.equal(proposeRegistryTransition(base(),pin(base()),{...change(),keyId:'missing-key'}).reason,'NOT_ACTIVE');
});
test('reconcile previous snapshot after interrupted write',()=>{
 const r=base(),p=proposeRegistryTransition(r,pin(r),change());
 assert.equal(reconcileRegistryTransition(r,pin(r),p.candidate.pin).status,'NOT_COMMITTED');
});
test('reconcile exact proposed snapshot without granting authority',()=>{
 const r=base(),p=proposeRegistryTransition(r,pin(r),change());
 const outcome=reconcileRegistryTransition(p.candidate.registry,pin(r),p.candidate.pin);
 assert.equal(outcome.status,'COMMITTED');assert.equal(outcome.authorized,false);
});
test('unknown or tampered observed registry is held',()=>{
 const r=base(),p=proposeRegistryTransition(r,pin(r),change());
 assert.equal(reconcileRegistryTransition({...p.candidate.registry,version:3},pin(r),p.candidate.pin).status,'HOLD');
 assert.equal(reconcileRegistryTransition(null,pin(r),p.candidate.pin).status,'HOLD');
});
test('mismatched transition pin and missing trust inputs are held',()=>{
 const r=base(),p=proposeRegistryTransition(r,pin(r),change());
 assert.equal(reconcileRegistryTransition(p.candidate.registry,pin(r),{...p.candidate.pin,version:5}).reason,'INVALID_TRUST_INPUT');
 assert.equal(reconcileRegistryTransition(r,null,p.candidate.pin).status,'HOLD');
});
