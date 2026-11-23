import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {keyQuorumPolicyDigest} from '../src/cas-key-quorum.mjs';
import {policySuccessionPayload,policySuccessionEntryHash,
 INITIAL_POLICY_SUCCESSION_POSITION as genesis} from '../src/cas-policy-succession.mjs';
import {preparePolicyActivation,policyActivationPayload,verifyPolicyActivationReceipt,
 reconcilePolicyActivation} from '../src/cas-policy-activation.mjs';

const namespace='PALACO-NEO-TEST';
const owner=generateKeyPairSync('ed25519'),security=generateKeyPairSync('ed25519');
const third=generateKeyPairSync('ed25519'),custodian=generateKeyPairSync('ed25519');
const attacker=generateKeyPairSync('ed25519');
const pem=k=>k.publicKey.export({type:'spki',format:'pem'});
const old=()=>({schema:'NEO-027-POLICY-v1',namespace,version:1,reviewers:[
 {reviewerId:'review-owner',role:'OWNER',status:'ACTIVE',publicKeyPem:pem(owner)},
 {reviewerId:'review-security',role:'SECURITY',status:'ACTIVE',publicKeyPem:pem(security)}
]});
const next=()=>({schema:'NEO-027-POLICY-v1',namespace,version:2,reviewers:[
 ...old().reviewers,{reviewerId:'third-reviewer',role:'OWNER',status:'ACTIVE',publicKeyPem:pem(third)}
]});
const pin=p=>({version:p.version,digest:keyQuorumPolicyDigest(p)});
const event=()=>{
 const body={namespace,sequence:1,previousHash:genesis.head,changeId:'policy-change-001',
 beforeVersion:1,beforeDigest:keyQuorumPolicyDigest(old()),
 afterVersion:2,afterDigest:keyQuorumPolicyDigest(next())};
 const reviews=[['review-owner','OWNER',owner],['review-security','SECURITY',security]]
  .map(([reviewerId,role,key])=>({reviewerId,signature:sign(null,
    policySuccessionPayload(body,reviewerId,role),key.privateKey).toString('base64')}));
 return {...body,nextPolicy:next(),reviews,hash:policySuccessionEntryHash(body,reviews)};
};
const operationId='neo029-operation';
const prepared=()=>preparePolicyActivation([event()],old(),pin(old()),genesis,pin(old()),operationId);
const signed=(request=prepared().candidate,key=custodian,outcome='APPLIED')=>({
 request,custodianId:'external-custodian',outcome,
 signature:sign(null,policyActivationPayload(request,'external-custodian',outcome),
  key.privateKey).toString('base64')
});
const trust=()=>({namespace,custodianId:'external-custodian',
 publicKeyPem:pem(custodian),status:'ACTIVE',expectedOperationId:operationId,
 trustedBefore:pin(old())});

test('verified signed succession generates an external CAS request, never activation',()=>{
 const r=prepared();assert.equal(r.ok,true);assert.equal(r.authorized,false);
 assert.equal(r.candidate.before.version,1);assert.equal(r.candidate.after.version,2);
 assert.equal(r.candidate.decisionHead,event().hash);
});
test('valid independent custodian assertion verifies but does not authorize',()=>{
 const request=prepared().candidate,r=verifyPolicyActivationReceipt(request,signed(request),trust());
 assert.equal(r.ok,true);assert.equal(r.authorized,false);
 assert.equal(r.candidate.evidenceDigest.length,64);
});
test('external policy version conflict blocks request preparation',()=>{
 const r=preparePolicyActivation([event()],old(),pin(old()),genesis,pin(next()),operationId);
 assert.equal(r.reason,'EXTERNAL_POLICY_VERSION_CONFLICT');
});
test('stale or falsified chain floor blocks request preparation',()=>{
 const r=preparePolicyActivation([event()],old(),pin(old()),
  {count:1,head:'f'.repeat(64)},pin(old()),operationId);
 assert.equal(r.ok,false);
});
test('forged custodian signature is denied',()=>{
 const request=prepared().candidate;
 assert.equal(verifyPolicyActivationReceipt(request,signed(request,attacker),trust()).reason,
  'INVALID_CUSTODIAN_SIGNATURE');
});
test('rejected outcome is not an applied activation',()=>{
 const request=prepared().candidate;
 assert.equal(verifyPolicyActivationReceipt(request,signed(request,custodian,'REJECTED'),trust()).reason,
  'CAS_RECEIPT_MISMATCH');
});
test('revoked external custodian is denied',()=>{
 const request=prepared().candidate;
 assert.equal(verifyPolicyActivationReceipt(request,signed(request),
  {...trust(),status:'REVOKED'}).reason,'REVOKED_CUSTODIAN');
});
test('operation replay against a newly pinned operation identifier fails',()=>{
 const request=prepared().candidate;
 assert.equal(verifyPolicyActivationReceipt(request,signed(request),
  {...trust(),expectedOperationId:'neo029-next'}).reason,'OPERATION_REPLAY_OR_MISMATCH');
});
test('receipt from a different policy-change request is refused',()=>{
 const request=prepared().candidate,changed={...request,changeId:'other-change'};
 assert.equal(verifyPolicyActivationReceipt(request,signed(changed),trust()).reason,
  'CAS_RECEIPT_MISMATCH');
});
test('before pin mismatch rejects receipt even with correct signature',()=>{
 const request=prepared().candidate;
 assert.equal(verifyPolicyActivationReceipt(request,signed(request),
  {...trust(),trustedBefore:{...pin(old()),digest:'f'.repeat(64)}}).reason,
 'TRUSTED_BEFORE_CONFLICT');
});
test('no receipt and external still before is NOT_COMMITTED',()=>{
 const r=reconcilePolicyActivation(prepared().candidate,pin(old()),null,trust());
 assert.equal(r.phase,'NOT_COMMITTED');assert.equal(r.authorized,false);
});
test('signed applied claim but independent external still before is HOLD',()=>{
 const request=prepared().candidate;
 assert.equal(reconcilePolicyActivation(request,pin(old()),signed(request),trust()).phase,'HOLD');
});
test('signed applied claim with independently observed successor is OBSERVED_COMMITTED',()=>{
 const request=prepared().candidate;
 const r=reconcilePolicyActivation(request,pin(next()),signed(request),trust());
 assert.equal(r.phase,'OBSERVED_COMMITTED');assert.equal(r.authorized,false);
});
test('externally advanced without authenticated receipt is HOLD',()=>{
 const r=reconcilePolicyActivation(prepared().candidate,pin(next()),null,trust());
 assert.equal(r.phase,'HOLD');
});
test('unexpected forked external version or digest is HOLD',()=>{
 const request=prepared().candidate;
 assert.equal(reconcilePolicyActivation(request,
  {version:3,digest:'e'.repeat(64)},signed(request),trust()).phase,'HOLD');
});
test('forged receipt cannot be substituted during reconciliation',()=>{
 const request=prepared().candidate;
 assert.equal(reconcilePolicyActivation(request,pin(next()),signed(request,attacker),trust()).reason,
  'UNVERIFIED_ACTIVATION_RECEIPT');
});
test('malformed request or signature fails closed',()=>{
 const request=prepared().candidate;
 assert.equal(verifyPolicyActivationReceipt(request,{...signed(request),signature:'bad'},trust()).ok,false);
 assert.equal(reconcilePolicyActivation(null,pin(old()),null,trust()).phase,'HOLD');
 assert.equal(preparePolicyActivation([],old(),pin(old()),genesis,pin(old()),operationId).ok,false);
});
