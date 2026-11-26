import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {recoveryChallengeDigest} from '../src/recovery-challenge.mjs';
import {prepareAnchorCAS,anchorCASSigningPayload} from '../src/anchor-cas.mjs';
import {INITIAL_CAS_PROOF_POSITION as genesis,proposeCASProofAppend}
 from '../src/cas-proof-ledger.mjs';
import {custodianKeyHistoryDigest,proposeCustodianKeyRotation,
 verifyHistoricalCASArchive} from '../src/cas-key-history.mjs';

const ns='PALACO-NEO-TEST',challenge='a'.repeat(64),custodianId='trusted-custodian';
const oldReg={schema:'NEO-019-v1',namespace:ns,challenges:[
 {challenge,signerId:'recovery-witness',status:'ISSUED'}]};
const newReg={schema:'NEO-019-v1',namespace:ns,challenges:[
 {challenge,signerId:'recovery-witness',status:'CONSUMED'}]};
const before={namespace:ns,revision:9,digest:recoveryChallengeDigest(oldReg)};
const after={namespace:ns,revision:10,digest:recoveryChallengeDigest(newReg)};
const plan={schema:'NEO-021-v1',namespace:ns,challenge,before,after,proposedRegistry:newReg};
const oldKey=generateKeyPairSync('ed25519'),newKey=generateKeyPairSync('ed25519');
const pem=k=>k.publicKey.export({type:'spki',format:'pem'});
const operationId='neo025-operation';
const cas=()=>prepareAnchorCAS(plan,newReg,before,operationId).candidate;
const receipt=(key=oldKey)=>({cas:cas(),custodianId,signature:sign(null,
 anchorCASSigningPayload(cas(),custodianId),key.privateKey).toString('base64')});
const history=()=>({schema:'NEO-025-KEY-HISTORY-v1',namespace:ns,version:1,epochs:[
 {custodianId,publicKeyPem:pem(oldKey),fromRevision:1,untilRevision:null,status:'TRUSTED'}]});
const pin=h=>({version:h.version,digest:custodianKeyHistoryDigest(h)});
const rotation=h=>proposeCustodianKeyRotation(h,pin(h),{
 custodianId,cutoverRevision:10,successorPublicKeyPem:pem(newKey)});
const fixture=()=>{
 const r=receipt(),trust={namespace:ns,custodianId,status:'ACTIVE',
 publicKeyPem:pem(oldKey),expectedOperationId:operationId,trustedBefore:before};
 const p=proposeCASProofAppend([],genesis,plan,r,trust);
 assert.equal(p.ok,true);
 return {entries:[p.candidate.entry],archive:[{plan,receipt:r}]};
};
test('historical signed receipt verifies with key active at its revision',()=>{
 const f=fixture(),h=history(),v=verifyHistoricalCASArchive(f.entries,f.archive,genesis,h,pin(h));
 assert.equal(v.ok,true);assert.equal(v.authorized,false);assert.equal(v.position.count,1);
});
test('rotation preserves old verification before exclusive cutover',()=>{
 const f=fixture(),r=rotation(history());
 assert.equal(r.ok,true);assert.equal(r.authorized,false);
 assert.equal(r.candidate.history.epochs[0].untilRevision,10);
 assert.equal(r.candidate.history.epochs[1].fromRevision,10);
 const h=r.candidate.history;
 assert.equal(verifyHistoricalCASArchive(f.entries,f.archive,genesis,h,pin(h)).ok,true);
});
test('new key cannot silently replace old key for earlier signed receipt',()=>{
 const f=fixture(),h=history();
 h.epochs[0].publicKeyPem=pem(newKey);
 assert.equal(verifyHistoricalCASArchive(f.entries,f.archive,genesis,h,pin(h)).ok,false);
});
test('new signature is not accepted under old key revision',()=>{
 const f=fixture(),h=rotation(history()).candidate.history;
 f.archive[0]={plan,receipt:receipt(newKey)};
 assert.equal(verifyHistoricalCASArchive(f.entries,f.archive,genesis,h,pin(h)).ok,false);
});
test('compromised old key epoch rejects even historically valid receipt',()=>{
 const f=fixture(),h=rotation(history()).candidate.history;
 const bad={...h,epochs:h.epochs.map((e,i)=>i===0?{...e,status:'COMPROMISED'}:e)};
 assert.equal(verifyHistoricalCASArchive(f.entries,f.archive,genesis,bad,pin(bad)).reason,
  'COMPROMISED_KEY_EPOCH');
});
test('overlapping key epochs fail closed',()=>{
 const h=rotation(history()).candidate.history;
 const overlapping={...h,epochs:h.epochs.map((e,i)=>i===0?{...e,untilRevision:11}:e)};
 assert.throws(()=>custodianKeyHistoryDigest(overlapping),/OVERLAPPING/);
});
test('incorrect externally trusted history digest rejects all archived receipts',()=>{
 const f=fixture(),h=history();
 assert.equal(verifyHistoricalCASArchive(f.entries,f.archive,genesis,h,
  {version:1,digest:'f'.repeat(64)}).reason,'UNTRUSTED_HISTORY_PIN');
});
test('replayed rotation from old version pin fails',()=>{
 const h=history(),first=rotation(h);
 assert.equal(proposeCustodianKeyRotation(first.candidate.history,pin(h),{
  custodianId,cutoverRevision:11,successorPublicKeyPem:pem(newKey)}).ok,false);
});
test('rotation requires a genuinely later revision and different key',()=>{
 const h=history();
 assert.equal(proposeCustodianKeyRotation(h,pin(h),{
  custodianId,cutoverRevision:1,successorPublicKeyPem:pem(newKey)}).reason,
 'INVALID_CUTOVER');
 assert.equal(proposeCustodianKeyRotation(h,pin(h),{
  custodianId,cutoverRevision:10,successorPublicKeyPem:pem(oldKey)}).ok,false);
});
test('missing historical key epoch refuses signature verification',()=>{
 const f=fixture(),h=history();h.epochs[0].fromRevision=10;
 assert.equal(verifyHistoricalCASArchive(f.entries,f.archive,genesis,h,pin(h)).reason,
  'NO_UNIQUE_TRUSTED_KEY_EPOCH');
});
test('rollback below separately retained proof floor is detected',()=>{
 const f=fixture(),h=history(),floor={count:1,head:f.entries[0].hash};
 assert.equal(verifyHistoricalCASArchive([],[],floor,h,pin(h)).ok,false);
});
test('invalid key material and malformed archive fail closed',()=>{
 const h=history();h.epochs[0].publicKeyPem='not a public key';
 assert.throws(()=>custodianKeyHistoryDigest(h));
 const normal=history(),f=fixture();
 assert.equal(verifyHistoricalCASArchive(f.entries,[],genesis,normal,pin(normal)).ok,false);
});
test('empty ledger is structurally acceptable without authorization',()=>{
 const h=history(),r=verifyHistoricalCASArchive([],[],genesis,h,pin(h));
 assert.equal(r.ok,true);assert.equal(r.authorized,false);
});
