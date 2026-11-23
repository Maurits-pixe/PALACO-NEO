import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {policyCheckpointPayload} from '../src/cas-policy-activation-ledger.mjs';
import {inspectWitnessEquivocation} from '../src/cas-witness-equivocation.mjs';
import {keyQuorumPolicyDigest} from '../src/cas-key-quorum.mjs';
import {INITIAL_ESCALATION_POSITION as genesis,escalationReviewPayload,
 escalationEntryHash,verifyEscalationJournal} from '../src/cas-escalation-journal.mjs';

const ns='PALACO-NEO-TEST',wid='witness-001';
const witness=generateKeyPairSync('ed25519'),owner=generateKeyPairSync('ed25519');
const security=generateKeyPairSync('ed25519'),forger=generateKeyPairSync('ed25519');
const pem=k=>k.publicKey.export({type:'spki',format:'pem'});
const cp=(head)=>({namespace:ns,count:1,head,activePolicy:{version:2,digest:'b'.repeat(64)}});
const seal=(checkpoint)=>({checkpoint,witnessId:wid,
 signature:sign(null,policyCheckpointPayload(checkpoint,wid),
  witness.privateKey).toString('base64')});
const trust=()=>({namespace:ns,witnessId:wid,publicKeyPem:pem(witness),
 status:'ACTIVE',trustedCheckpointFloor:{count:0,head:'0'.repeat(64)}});
const dossier=()=>inspectWitnessEquivocation(seal(cp('a'.repeat(64))),
 seal(cp('c'.repeat(64))),trust()).dossier;
const policy=()=>({schema:'NEO-027-POLICY-v1',namespace:ns,version:1,reviewers:[
 {reviewerId:'review-owner',role:'OWNER',status:'ACTIVE',publicKeyPem:pem(owner)},
 {reviewerId:'review-security',role:'SECURITY',status:'ACTIVE',publicKeyPem:pem(security)}]});
const pin=p=>({version:p.version,digest:keyQuorumPolicyDigest(p)});
const entry=(seq,previousHash,action,caseId='case-033',p=policy(),d=dossier(),keys=[owner,security])=>{
 const body={sequence:seq,previousHash,caseId,action,dossierDigest:d.digest};
 const reviews=[['review-owner','OWNER',keys[0]],['review-security','SECURITY',keys[1]]]
  .map(([reviewerId,role,key])=>({reviewerId,
   signature:sign(null,escalationReviewPayload(body,keyQuorumPolicyDigest(p),
    reviewerId,role),key.privateKey).toString('base64')}));
 return {...body,reviews,hash:escalationEntryHash(body,reviews)};
};
const bundle=()=>({dossier:dossier(),witnessTrust:trust()});
const verify=(entries,evidence,p=policy(),floor=genesis,pinned=pin(p))=>
 verifyEscalationJournal(entries,evidence,p,pinned,floor);
test('valid OPEN dual-signature escalates and never authorizes',()=>{
 const e=entry(1,genesis.head,'OPEN'),r=verify([e],[bundle()]);
 assert.equal(r.ok,true);assert.equal(r.authorized,false);
 assert.equal(r.candidate.cases[0].status,'ESCALATED_HOLD');
});
test('second signed REVIEWED_HOLD records attention but never releases',()=>{
 const first=entry(1,genesis.head,'OPEN');
 const second=entry(2,first.hash,'REVIEWED_HOLD');
 const r=verify([first,second],[bundle(),bundle()]);
 assert.equal(r.ok,true);assert.equal(r.candidate.cases[0].status,'ESCALATED_HOLD');
});
test('reviewed case cannot appear without an opening',()=>{
 const e=entry(1,genesis.head,'REVIEWED_HOLD');
 assert.equal(verify([e],[bundle()]).reason,'UNOPENED_OR_CHANGED_CASE');
});
test('replaying an OPEN on same case fails',()=>{
 const a=entry(1,genesis.head,'OPEN'),b=entry(2,a.hash,'OPEN');
 assert.equal(verify([a,b],[bundle(),bundle()]).reason,'CASE_REPLAY');
});
test('forged security signature fails',()=>{
 const e=entry(1,genesis.head,'OPEN','case-033',policy(),dossier(),[owner,forger]);
 assert.equal(verify([e],[bundle()]).reason,'INVALID_REVIEW_SIGNATURE');
});
test('revoked reviewer is refused',()=>{
 const p=policy();p.reviewers[1].status='REVOKED';
 const e=entry(1,genesis.head,'OPEN','case-033',p);
 assert.equal(verify([e],[bundle()],p).reason,'REVOKED_OR_DUPLICATE_REVIEW_ROLE');
});
test('stale policy pin is rejected',()=>{
 const e=entry(1,genesis.head,'OPEN');
 assert.equal(verify([e],[bundle()],policy(),genesis,{version:1,digest:'f'.repeat(64)}).reason,
  'UNTRUSTED_POLICY_PIN');
});
test('dossier hash mismatch rejects journal entry',()=>{
 const e=entry(1,genesis.head,'OPEN');
 assert.equal(verify([{...e,dossierDigest:'f'.repeat(64)}],[bundle()]).reason,
  'UNVERIFIED_FORENSIC_DOSSIER');
});
test('torn or altered dossier signature fails',()=>{
 const evidence=bundle();evidence.dossier={...evidence.dossier,
  first:{...evidence.dossier.first,signature:'a'.repeat(88)}};
 const e=entry(1,genesis.head,'OPEN');
 assert.equal(verify([e],[evidence]).reason,'UNVERIFIED_FORENSIC_DOSSIER');
});
test('tampered journal hash fails',()=>{
 const e=entry(1,genesis.head,'OPEN');
 assert.equal(verify([{...e,hash:'f'.repeat(64)}],[bundle()]).reason,'TAMPERED_JOURNAL_ENTRY');
});
test('rollback below externally trusted floor fails',()=>{
 const e=entry(1,genesis.head,'OPEN');
 assert.equal(verify([],[],policy(),{count:1,head:e.hash}).reason,
  'ROLLBACK_BELOW_TRUSTED_FLOOR');
});
test('forked externally trusted hash fails',()=>{
 const e=entry(1,genesis.head,'OPEN');
 assert.equal(verify([e],[bundle()],policy(),{count:1,head:'f'.repeat(64)}).reason,
  'FORKED_TRUSTED_FLOOR');
});
test('missing security signature fails',()=>{
 const e=entry(1,genesis.head,'OPEN');
 assert.equal(verify([{...e,reviews:e.reviews.slice(0,1)}],[bundle()]).ok,false);
});
test('untrusted witness key is refused in dossier',()=>{
 const evidence=bundle();evidence.witnessTrust.publicKeyPem=pem(forger);
 const e=entry(1,genesis.head,'OPEN');
 assert.equal(verify([e],[evidence]).ok,false);
});
test('unrecognized closure operation cannot be smuggled in',()=>{
 const e=entry(1,genesis.head,'OPEN');
 assert.equal(verify([{...e,action:'CLOSED'}],[bundle()]).ok,false);
});
test('invalid input fails closed and empty state is non-authorizing',()=>{
 assert.equal(verify(null,[]).ok,false);
 const result=verify([],[]);
 assert.equal(result.ok,true);assert.equal(result.authorized,false);
});
