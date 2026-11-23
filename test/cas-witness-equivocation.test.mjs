import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {policyCheckpointPayload} from '../src/cas-policy-activation-ledger.mjs';
import {inspectWitnessEquivocation,verifyWitnessEquivocationDossier,
 classifyWitnessEscalation} from '../src/cas-witness-equivocation.mjs';

const ns='PALACO-NEO-TEST',witnessId='witness-001',genesis='0'.repeat(64);
const signer=generateKeyPairSync('ed25519'),impostor=generateKeyPairSync('ed25519');
const pem=k=>k.publicKey.export({type:'spki',format:'pem'});
const cp=(head='a'.repeat(64),count=1,policyDigest='b'.repeat(64))=>({
 namespace:ns,count,head,activePolicy:{version:count+1,digest:policyDigest}
});
const seal=(checkpoint=cp(),key=signer)=>({
 checkpoint,witnessId,signature:sign(null,
 policyCheckpointPayload(checkpoint,witnessId),key.privateKey).toString('base64')
});
const trust=()=>({namespace:ns,witnessId,publicKeyPem:pem(signer),
 status:'ACTIVE',trustedCheckpointFloor:{count:0,head:genesis}});
const conflict=()=>inspectWitnessEquivocation(seal(cp()),seal(cp('c'.repeat(64))),trust());

test('two different signed statements at same count yield a non-authorizing dossier',()=>{
 const result=conflict();
 assert.equal(result.ok,true);assert.equal(result.reason,'SIGNED_EQUIVOCATION_EVIDENCE');
 assert.equal(result.authorized,false);assert.equal(result.dossier.digest.length,64);
});
test('dossier can be independently reverified from original signatures',()=>{
 const result=verifyWitnessEquivocationDossier(conflict().dossier,trust());
 assert.equal(result.phase,'ESCALATE_HOLD');assert.equal(result.authorized,false);
});
test('evidence digest is independent of order of the two signed statements',()=>{
 const a=seal(cp()),b=seal(cp('c'.repeat(64)));
 const left=inspectWitnessEquivocation(a,b,trust());
 const right=inspectWitnessEquivocation(b,a,trust());
 assert.equal(left.dossier.digest,right.dossier.digest);
});
test('identical signed claims are not equivocation',()=>{
 const a=seal(cp()),b=seal(cp());
 const result=inspectWitnessEquivocation(a,b,trust());
 assert.equal(result.reason,'IDENTICAL_SIGNED_CLAIMS');
 assert.equal(result.dossier,null);
});
test('different signed counts are not sufficient for an equivocation proof',()=>{
 const a=seal(cp()),b=seal(cp('c'.repeat(64),2));
 assert.equal(inspectWitnessEquivocation(a,b,trust()).reason,
  'DIFFERENT_COUNTS_NO_EQUIVOCATION_PROOF');
});
test('different policy digest at identical count is detected',()=>{
 const a=seal(cp()),b=seal(cp('a'.repeat(64),1,'f'.repeat(64)));
 assert.equal(inspectWitnessEquivocation(a,b,trust()).reason,'SIGNED_EQUIVOCATION_EVIDENCE');
});
test('forged signature is rejected before conflict classification',()=>{
 const a=seal(cp()),b=seal(cp('c'.repeat(64)),impostor);
 assert.equal(inspectWitnessEquivocation(a,b,trust()).reason,'UNVERIFIED_SIGNED_CLAIM');
});
test('revoked witness is denied under the supplied policy',()=>{
 assert.equal(inspectWitnessEquivocation(seal(cp()),seal(cp('c'.repeat(64))),
  {...trust(),status:'REVOKED'}).reason,'REVOKED_WITNESS_NOT_ACCEPTED');
});
test('dossier modification is rejected even if one hash looks valid',()=>{
 const d=conflict().dossier;
 assert.equal(verifyWitnessEquivocationDossier({...d,digest:'f'.repeat(64)},trust()).phase,
  'HOLD');
});
test('substituted witness identity cannot be accepted',()=>{
 const a=seal(cp()),b={...seal(cp('c'.repeat(64))),witnessId:'other-witness'};
 assert.equal(inspectWitnessEquivocation(a,b,trust()).reason,'WITNESS_ID_MISMATCH');
});
test('externally trusted floor prevents accepting an older conflicting fork',()=>{
 const a=seal(cp()),b=seal(cp('c'.repeat(64)));
 assert.equal(inspectWitnessEquivocation(a,b,{...trust(),
  trustedCheckpointFloor:{count:1,head:'a'.repeat(64)}}).reason,'UNVERIFIED_SIGNED_CLAIM');
});
test('same key may be evaluated but never establishes physical independence',()=>{
 const d=conflict().dossier;
 assert.equal(classifyWitnessEscalation(d,trust(),null).phase,'ESCALATE_HOLD');
});
test('purported manual reviews never release an equivocation HOLD',()=>{
 const d=conflict().dossier;
 const r=classifyWitnessEscalation(d,trust(),{
  caseId:'case-032',ownerReviewed:true,securityReviewed:true
 });
 assert.equal(r.phase,'ESCALATE_HOLD');assert.equal(r.authorized,false);
 assert.equal(r.reason,'UNAUTHENTICATED_REVIEW_CLAIM_NO_RELEASE');
});
test('missing one human review remains escalated and blocked',()=>{
 const r=classifyWitnessEscalation(conflict().dossier,trust(),{
  caseId:'case-032',ownerReviewed:true,securityReviewed:false
 });
 assert.equal(r.reason,'HUMAN_REVIEW_REQUIRED');
});
test('malformed dossier and trust fail closed',()=>{
 assert.equal(verifyWitnessEquivocationDossier(null,trust()).phase,'HOLD');
 assert.equal(inspectWitnessEquivocation(null,null,trust()).ok,false);
 assert.equal(classifyWitnessEscalation(null,trust(),null).phase,'HOLD');
});
