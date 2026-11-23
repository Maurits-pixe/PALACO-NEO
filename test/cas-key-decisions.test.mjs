import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {custodianKeyHistoryDigest,proposeCustodianKeyRotation} from '../src/cas-key-history.mjs';
import {keyDecisionPayload,verifyKeyDecisionChain,
 INITIAL_KEY_DECISION_POSITION as genesis} from '../src/cas-key-decisions.mjs';

const namespace='PALACO-NEO-TEST',custodianId='custodian-001';
const oldKey=generateKeyPairSync('ed25519'),nextKey=generateKeyPairSync('ed25519');
const governor=generateKeyPairSync('ed25519'),forger=generateKeyPairSync('ed25519');
const pem=k=>k.publicKey.export({type:'spki',format:'pem'});
const initial=()=>({schema:'NEO-025-KEY-HISTORY-v1',namespace,version:1,epochs:[
 {custodianId,publicKeyPem:pem(oldKey),fromRevision:1,untilRevision:null,status:'TRUSTED'}]});
const pin=h=>({version:h.version,digest:custodianKeyHistoryDigest(h)});
const governors=()=>[{namespace,governorId:'governor-001',status:'ACTIVE',publicKeyPem:pem(governor)}];
const rotation=()=>proposeCustodianKeyRotation(initial(),pin(initial()),{
 custodianId,cutoverRevision:10,successorPublicKeyPem:pem(nextKey)}).candidate.history;
const rotationEvent=(k=governor)=>{
 const before=initial(),after=rotation();
 const body={namespace,sequence:1,previousHash:genesis.head,decisionId:'rotate-001',
 type:'ROTATE',custodianId,beforeDigest:custodianKeyHistoryDigest(before),
 afterDigest:custodianKeyHistoryDigest(after),beforeVersion:before.version,
 afterVersion:after.version,effectiveRevision:10,successorPublicKeyPem:pem(nextKey)};
 return makeEvent(body,after,k);
};
function makeEvent(body,nextHistory,k=governor){
 const bytes=keyDecisionPayload(body,'governor-001');
 const signature=sign(null,bytes,k.privateKey).toString('base64');
 const hash=createHash('sha256').update(JSON.stringify([
 'PALACO-NEO-KEY-DECISION-CHAIN-v1',bytes.toString('base64'),signature])).digest('hex');
 return {...body,nextHistory,governorId:'governor-001',signature,hash};
}
const check=(events,opts={})=>verifyKeyDecisionChain(events,
 opts.initial??initial(),opts.pin??pin(initial()),
 opts.governors??governors(),opts.floor??genesis);
test('genesis checks against independently pinned initial history',()=>{
 const result=check([]);
 assert.equal(result.ok,true);assert.equal(result.authorized,false);
 assert.deepEqual(result.position,genesis);
});
test('valid signed rotation establishes a verifiable chain',()=>{
 const e=rotationEvent(),r=check([e]);
 assert.equal(r.ok,true);assert.equal(r.authorized,false);
 assert.equal(r.history.version,2);assert.equal(r.position.count,1);
});
test('signed historical compromise decision verifies against pinned governor',()=>{
 const rot=rotationEvent(),old=rot.nextHistory;
 const newHistory={...old,version:3,epochs:old.epochs.map((e,i)=>
  i===0?{...e,status:'COMPROMISED'}:{...e})};
 const body={namespace,sequence:2,previousHash:rot.hash,
 decisionId:'compromise-001',type:'COMPROMISE',custodianId,
 beforeDigest:custodianKeyHistoryDigest(old),
 afterDigest:custodianKeyHistoryDigest(newHistory),
 beforeVersion:2,afterVersion:3,effectiveRevision:1,successorPublicKeyPem:null};
 const second=makeEvent(body,newHistory);
 const verified=check([rot,second]);
 assert.equal(verified.ok,true);assert.equal(verified.history.epochs[0].status,'COMPROMISED');
 assert.equal(verified.position.count,2);
});
test('forged governance signature is refused',()=>{
 assert.equal(check([rotationEvent(forger)]).reason,'INVALID_DECISION_SIGNATURE');
});
test('revoked governance signer cannot authorize transition evidence',()=>{
 const bad=governors();bad[0].status='REVOKED';
 assert.equal(check([rotationEvent()],{governors:bad}).reason,'UNTRUSTED_OR_REVOKED_GOVERNOR');
});
test('tampered next history and changed public key cannot bypass event hash',()=>{
 const event=rotationEvent();
 event.nextHistory={...event.nextHistory,epochs:[...event.nextHistory.epochs]};
 event.nextHistory.epochs[1]={...event.nextHistory.epochs[1],publicKeyPem:pem(forger)};
 assert.equal(check([event]).ok,false);
});
test('replayed same signed decision ID is blocked by chain continuity',()=>{
 const event=rotationEvent();
 assert.equal(check([event,event]).ok,false);
});
test('rollback below externally pinned decision head fails',()=>{
 const event=rotationEvent();
 assert.equal(check([],{floor:{count:1,head:event.hash}}).reason,'ROLLBACK_BELOW_PINNED_FLOOR');
});
test('forged externally pinned head cannot validate chain',()=>{
 const event=rotationEvent();
 assert.equal(check([event],{floor:{count:1,head:'f'.repeat(64)}}).reason,
 'TRUSTED_DECISION_FLOOR_CONFLICT');
});
test('wrong authenticated initial history pin blocks all decisions',()=>{
 const event=rotationEvent();
 assert.equal(check([event],{pin:{version:1,digest:'f'.repeat(64)}}).reason,
  'UNTRUSTED_INITIAL_HISTORY');
});
test('overlap and unexpected history mutation fail closed',()=>{
 const event=rotationEvent();
 event.nextHistory={...event.nextHistory,epochs:event.nextHistory.epochs.map((e,i)=>
  i===0?{...e,untilRevision:11}:e)};
 assert.equal(check([event]).ok,false);
});
test('unsigned decision and malformed input fail closed',()=>{
 const event=rotationEvent();event.signature='bad';
 assert.equal(check([event]).ok,false);
 assert.equal(check(null).ok,false);
 assert.equal(check([],{governors:[]}).ok,false);
});
