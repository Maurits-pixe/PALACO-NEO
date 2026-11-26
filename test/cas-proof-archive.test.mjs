import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {recoveryChallengeDigest} from '../src/recovery-challenge.mjs';
import {prepareAnchorCAS,anchorCASSigningPayload} from '../src/anchor-cas.mjs';
import {INITIAL_CAS_PROOF_POSITION as genesis,proposeCASProofAppend}
 from '../src/cas-proof-ledger.mjs';
import {custodianKeySnapshotDigest,verifyCASProofArchive} from '../src/cas-proof-archive.mjs';

const ns='PALACO-NEO-TEST',challenge='a'.repeat(64),custodianId='trusted-custodian';
const oldReg={schema:'NEO-019-v1',namespace:ns,challenges:[
 {challenge,signerId:'recovery-witness',status:'ISSUED'}]};
const newReg={schema:'NEO-019-v1',namespace:ns,challenges:[
 {challenge,signerId:'recovery-witness',status:'CONSUMED'}]};
const before={namespace:ns,revision:9,digest:recoveryChallengeDigest(oldReg)};
const after={namespace:ns,revision:10,digest:recoveryChallengeDigest(newReg)};
const plan={schema:'NEO-021-v1',namespace:ns,challenge,before,after,proposedRegistry:newReg};
const key=generateKeyPairSync('ed25519'),attacker=generateKeyPairSync('ed25519');
const pem=k=>k.publicKey.export({type:'spki',format:'pem'});
const operationId='neo024-operation';
const cas=()=>prepareAnchorCAS(plan,newReg,before,operationId).candidate;
const receipt=(signer=key)=>({cas:cas(),custodianId,
 signature:sign(null,anchorCASSigningPayload(cas(),custodianId),signer.privateKey).toString('base64')});
const snapshot=()=>({schema:'NEO-024-KEYS-v1',namespace:ns,version:1,custodians:[
 {id:custodianId,status:'ACTIVE',publicKeyPem:pem(key)}]});
const pin=x=>({version:x.version,digest:custodianKeySnapshotDigest(x)});
const context=()=>{
 const r=receipt(),trust={namespace:ns,custodianId,status:'ACTIVE',publicKeyPem:pem(key),
 expectedOperationId:operationId,trustedBefore:before};
 const out=proposeCASProofAppend([],genesis,plan,r,trust);
 assert.equal(out.ok,true);
 return {entries:[out.candidate.entry],archive:[{plan,receipt:r}],keys:snapshot()};
};
test('archived original signed CAS receipt and pinned key verify, no authority',()=>{
 const c=context(),r=verifyCASProofArchive(c.entries,c.archive,genesis,c.keys,pin(c.keys));
 assert.equal(r.ok,true);assert.equal(r.authorized,false);
 assert.equal(r.position.count,1);
});
test('tampered archived signature rejected',()=>{
 const c=context();c.archive[0]={...c.archive[0],receipt:{...c.archive[0].receipt,
 signature:receipt(attacker).signature}};
 assert.equal(verifyCASProofArchive(c.entries,c.archive,genesis,c.keys,pin(c.keys)).ok,false);
});
test('different signed receipt not matching ledger commitment denied',()=>{
 const c=context(),other=receipt();
 c.archive[0]={...c.archive[0],receipt:{...other,signature:receipt(attacker).signature}};
 assert.equal(verifyCASProofArchive(c.entries,c.archive,genesis,c.keys,pin(c.keys)).ok,false);
});
test('tampered separately pinned public key history rejected',()=>{
 const c=context(),trusted=pin(c.keys);
 c.keys.custodians[0].publicKeyPem=pem(attacker);
 assert.equal(verifyCASProofArchive(c.entries,c.archive,genesis,c.keys,trusted).reason,
  'UNTRUSTED_KEY_SNAPSHOT');
});
test('revoked witness in trusted snapshot cannot validate receipt',()=>{
 const c=context();c.keys.custodians[0].status='REVOKED';
 assert.equal(verifyCASProofArchive(c.entries,c.archive,genesis,c.keys,pin(c.keys)).reason,
  'REVOKED_CUSTODIAN');
});
test('missing historical signer is denied',()=>{
 const c=context();c.keys.custodians[0].id='unknown-custodian';
 assert.equal(verifyCASProofArchive(c.entries,c.archive,genesis,c.keys,pin(c.keys)).reason,
  'UNKNOWN_HISTORICAL_CUSTODIAN');
});
test('archived proof entry tampering is denied',()=>{
 const c=context();c.entries[0]={...c.entries[0],operationId:'different-operation'};
 assert.equal(verifyCASProofArchive(c.entries,c.archive,genesis,c.keys,pin(c.keys)).ok,false);
});
test('rollback below independently pinned floor denied',()=>{
 const c=context(),floor={count:1,head:c.entries[0].hash};
 assert.equal(verifyCASProofArchive([],[],floor,c.keys,pin(c.keys)).ok,false);
});
test('missing original receipts are not replaceable by hash-only records',()=>{
 const c=context();
 assert.equal(verifyCASProofArchive(c.entries,[],genesis,c.keys,pin(c.keys)).reason,
  'INVALID_ARCHIVE_INPUT');
});
test('invalid, mismatched, and duplicate key snapshots fail closed',()=>{
 const c=context(),p=pin(c.keys);
 assert.equal(verifyCASProofArchive(c.entries,c.archive,genesis,c.keys,
  {version:2,digest:p.digest}).reason,'UNTRUSTED_KEY_SNAPSHOT');
 assert.throws(()=>custodianKeySnapshotDigest({...c.keys,
  custodians:[c.keys.custodians[0],c.keys.custodians[0]]}));
});
test('empty chain passes structure without granting an archive provenance claim',()=>{
 const keys=snapshot();
 const r=verifyCASProofArchive([],[],genesis,keys,pin(keys));
 assert.equal(r.ok,true);assert.equal(r.authorized,false);assert.equal(r.position.count,0);
});
