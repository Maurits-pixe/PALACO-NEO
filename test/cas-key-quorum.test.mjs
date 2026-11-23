import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {custodianKeyHistoryDigest,proposeCustodianKeyRotation}
 from '../src/cas-key-history.mjs';
import {keyDecisionPayload,INITIAL_KEY_DECISION_POSITION as genesis}
 from '../src/cas-key-decisions.mjs';
import {keyQuorumPolicyDigest,keyQuorumReviewPayload,
 verifyDualKeyDecisionReviews} from '../src/cas-key-quorum.mjs';

const ns='PALACO-NEO-TEST',cid='custodian-001';
const custodian=generateKeyPairSync('ed25519');
const successor=generateKeyPairSync('ed25519');
const governor=generateKeyPairSync('ed25519');
const owner=generateKeyPairSync('ed25519');
const security=generateKeyPairSync('ed25519');
const attacker=generateKeyPairSync('ed25519');
const pem=x=>x.publicKey.export({type:'spki',format:'pem'});
const initial=()=>({schema:'NEO-025-KEY-HISTORY-v1',namespace:ns,version:1,epochs:[
 {custodianId:cid,publicKeyPem:pem(custodian),fromRevision:1,untilRevision:null,status:'TRUSTED'}]});
const pin=h=>({version:h.version,digest:custodianKeyHistoryDigest(h)});
const governors=()=>[{namespace:ns,governorId:'governor-001',
 status:'ACTIVE',publicKeyPem:pem(governor)}];
const policy=()=>({schema:'NEO-027-POLICY-v1',namespace:ns,version:1,reviewers:[
 {reviewerId:'review-owner',role:'OWNER',status:'ACTIVE',publicKeyPem:pem(owner)},
 {reviewerId:'review-security',role:'SECURITY',status:'ACTIVE',publicKeyPem:pem(security)}]});
const event=()=>{
 const before=initial();
 const after=proposeCustodianKeyRotation(before,pin(before),{
  custodianId:cid,cutoverRevision:10,successorPublicKeyPem:pem(successor)}).candidate.history;
 const body={namespace:ns,sequence:1,previousHash:genesis.head,
  decisionId:'neo027-rotation',type:'ROTATE',custodianId:cid,
  beforeDigest:custodianKeyHistoryDigest(before),
  afterDigest:custodianKeyHistoryDigest(after),beforeVersion:1,
  afterVersion:2,effectiveRevision:10,successorPublicKeyPem:pem(successor)};
 const payload=keyDecisionPayload(body,'governor-001');
 const signature=sign(null,payload,governor.privateKey).toString('base64');
 const hash=createHash('sha256').update(JSON.stringify([
  'PALACO-NEO-KEY-DECISION-CHAIN-v1',payload.toString('base64'),signature
 ])).digest('hex');
 return {...body,nextHistory:after,governorId:'governor-001',signature,hash};
};
const reviews=(e=event(),p=policy())=>({
 decisionId:e.decisionId,
 reviews:[['review-owner','OWNER',owner],['review-security','SECURITY',security]]
 .map(([reviewerId,role,k])=>({reviewerId,signature:sign(null,
  keyQuorumReviewPayload(e,reviewerId,role,keyQuorumPolicyDigest(p)),
  k.privateKey).toString('base64')}))
});
const verify=(e=event(),p=policy(),rr=undefined,pp=undefined,gg=governors())=>
 verifyDualKeyDecisionReviews([e],initial(),pin(initial()),gg,genesis,p,
 pp??{version:p.version,digest:keyQuorumPolicyDigest(p)},[rr??reviews(e,p)]);

test('dual OWNER and SECURITY signatures verify, without authority',()=>{
 const r=verify();assert.equal(r.ok,true);assert.equal(r.authorized,false);
 assert.equal(r.position.count,1);assert.equal(r.history.version,2);
});
test('separate roles have distinct signatures, one signer cannot impersonate another',()=>{
 const e=event(),p=policy(),r=reviews(e,p);
 r.reviews[1].signature=r.reviews[0].signature;
 assert.equal(verify(e,p,r).reason,'INVALID_REVIEW_SIGNATURE');
});
test('duplicate reviewer is refused',()=>{
 const e=event(),p=policy(),r=reviews(e,p);
 r.reviews[1]={...r.reviews[0]};
 assert.equal(verify(e,p,r).reason,'DUPLICATE_REVIEWER');
});
test('missing second review is refused',()=>{
 const e=event(),p=policy(),r=reviews(e,p);r.reviews.pop();
 assert.equal(verify(e,p,r).reason,'INCOMPLETE_QUORUM');
});
test('two reviewers in same role are insufficient',()=>{
 const p=policy();p.reviewers.push({reviewerId:'review-owner-two',
  role:'OWNER',status:'ACTIVE',publicKeyPem:pem(attacker)});
 const e=event(),r=reviews(e,p);
 r.reviews[1]={reviewerId:'review-owner-two',signature:sign(null,
  keyQuorumReviewPayload(e,'review-owner-two','OWNER',keyQuorumPolicyDigest(p)),
  attacker.privateKey).toString('base64')};
 assert.equal(verify(e,p,r).reason,'DUPLICATE_ROLE');
});
test('revoked reviewer is rejected',()=>{
 const p=policy(),e=event();p.reviewers[1].status='REVOKED';
 const r=reviews(e,p);
 assert.equal(verify(e,p,r).reason,'UNKNOWN_OR_REVOKED_REVIEWER');
});
test('modified independent policy pin blocks all decisions',()=>{
 const p=policy(),e=event();
 assert.equal(verify(e,p,reviews(e,p),{version:1,digest:'f'.repeat(64)}).reason,
  'UNTRUSTED_QUORUM_POLICY');
});
test('reusing same Ed25519 public key for two identities invalidates policy',()=>{
 const p=policy();p.reviewers[1].publicKeyPem=p.reviewers[0].publicKeyPem;
 assert.throws(()=>keyQuorumPolicyDigest(p),/DUPLICATE_REVIEWER_KEY/);
});
test('altering decision hash invalidates underlying governance proof',()=>{
 const e=event();e.hash='f'.repeat(64);
 assert.equal(verify(e).ok,false);
});
test('forged governor signature fails before review quorum',()=>{
 const e=event();e.signature='a'.repeat(88);
 assert.equal(verify(e).ok,false);
});
test('malformed and foreign policy namespace fail closed',()=>{
 const e=event(),p=policy();p.namespace='DIFFERENT-TEST';
 assert.equal(verify(e,p).ok,false);
 assert.equal(verifyDualKeyDecisionReviews(null,initial(),pin(initial()),
  governors(),genesis,policy(),{version:1,digest:'f'.repeat(64)},[]).ok,false);
});
test('empty decision ledger cannot create execution authority',()=>{
 const p=policy(),r=verifyDualKeyDecisionReviews([],initial(),pin(initial()),
  governors(),genesis,p,{version:p.version,digest:keyQuorumPolicyDigest(p)},[]);
 assert.equal(r.ok,true);assert.equal(r.authorized,false);
});
