import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {createRecoveryEvidence} from '../src/recovery-evidence.mjs';
import {reviewerPolicyDigest,proposeReviewedDecision} from '../src/review-ledger.mjs';
import {REVIEW_INITIAL_POSITION as genesis} from '../src/review-recovery.mjs';
import {keyRegistryDigest} from '../src/key-registry.mjs';
import {proposeRegistryTransition} from '../src/registry-transition.mjs';
import {reviewPayload} from '../src/approval-review.mjs';
import {recoveryAttestationPayload,verifyRecoveryAttestation} from '../src/recovery-attestation.mjs';

const namespace='PALACO-NEO-TEST';
const witness=generateKeyPairSync('ed25519');
const other=generateKeyPairSync('ed25519');
const owner=generateKeyPairSync('ed25519'),security=generateKeyPairSync('ed25519');
const key=generateKeyPairSync('ed25519');
const pem=k=>k.publicKey.export({type:'spki',format:'pem'});
const keyEntry=id=>({id,publicKeyPem:pem(key),status:'ACTIVE',fromCount:0,throughCount:30});
const old={version:1,namespace,keys:[keyEntry('key-old'),keyEntry('key-keep')]};
const oldPin={version:1,digest:keyRegistryDigest(old)};
const updated=proposeRegistryTransition(old,oldPin,{type:'REVOKE',keyId:'key-old',replacement:null}).candidate;
const policy={version:1,namespace,reviewers:[
 {id:'review-owner',role:'OWNER',status:'ACTIVE',publicKeyPem:pem(owner)},
 {id:'review-security',role:'SECURITY',status:'ACTIVE',publicKeyPem:pem(security)}
]};
const review=(name,k)=>({reviewerId:name,signature:sign(null,
  reviewPayload(namespace,oldPin,updated.pin),k.privateKey).toString('base64')});
const proposal=proposeReviewedDecision({beforeRegistry:old,afterRegistry:updated.registry,
 beforePin:oldPin,afterPin:updated.pin,
 reviews:[review('review-owner',owner),review('review-security',security)],
 policy,trustedPolicyPin:{version:1,digest:reviewerPolicyDigest(policy)},
 transitionId:'neo-018-test',ledger:[],trustedLedgerHead:genesis.head}).candidate;
const evidence=createRecoveryEvidence([proposal.entry],genesis,proposal);
const challenge='a'.repeat(64);
const trust=()=>({namespace,expectedChallenge:challenge,signerId:'recovery-witness',
 status:'ACTIVE',publicKeyPem:pem(witness),trustedBefore:genesis});
const envelope=(receipt=evidence.receipt,k=witness,token=challenge)=>({
 namespace,challenge:token,signerId:'recovery-witness',receipt,
 signature:sign(null,recoveryAttestationPayload(namespace,token,'recovery-witness',receipt),
 k.privateKey).toString('base64')
});
test('valid signed receipt verifies but grants no authority',()=>{
 const r=verifyRecoveryAttestation(envelope(),trust());
 assert.equal(r.ok,true);assert.equal(r.authorized,false);
 assert.equal(r.receipt.status,'COMMITTED');
});
test('different challenge cannot replay prior signed evidence',()=>{
 assert.equal(verifyRecoveryAttestation(envelope(),{...trust(),expectedChallenge:'b'.repeat(64)}).reason,'CHALLENGE_MISMATCH');
});
test('revoked verification signer is denied',()=>{
 assert.equal(verifyRecoveryAttestation(envelope(),{...trust(),status:'REVOKED'}).reason,'REVOKED_SIGNER');
});
test('signer key substitution fails',()=>{
 assert.equal(verifyRecoveryAttestation(envelope(),{...trust(),publicKeyPem:pem(other)}).reason,'SIGNATURE_MISMATCH');
});
test('signature created by unrelated signer is rejected',()=>{
 assert.equal(verifyRecoveryAttestation(envelope(evidence.receipt,other),trust()).reason,'SIGNATURE_MISMATCH');
});
test('altered receipt is not accepted',()=>{
 const changed={...envelope(),receipt:{...evidence.receipt,status:'NOT_COMMITTED'}};
 assert.equal(verifyRecoveryAttestation(changed,trust()).reason,'INVALID_RECEIPT');
});
test('wrong independently trusted old checkpoint is refused',()=>{
 assert.equal(verifyRecoveryAttestation(envelope(),{...trust(),trustedBefore:{count:0,head:'f'.repeat(64)}}).reason,'TRUSTED_BEFORE_CONFLICT');
});
test('namespace and signer identity are bound into the signature',()=>{
 assert.equal(verifyRecoveryAttestation({...envelope(),namespace:'PALACO-OTHER'},trust()).reason,'IDENTITY_OR_NAMESPACE_MISMATCH');
 assert.equal(verifyRecoveryAttestation({...envelope(),signerId:'other-witness'},trust()).reason,'IDENTITY_OR_NAMESPACE_MISMATCH');
});
test('noncanonical signature and malformed trust input fail closed',()=>{
 assert.equal(verifyRecoveryAttestation({...envelope(),signature:'!!'},trust()).reason,'INVALID_SIGNATURE');
 assert.equal(verifyRecoveryAttestation(envelope(),null).ok,false);
});
test('different valid signed challenge works only with matching external challenge',()=>{
 const token='b'.repeat(64);
 const signed=envelope(evidence.receipt,witness,token);
 assert.equal(verifyRecoveryAttestation(signed,{...trust(),expectedChallenge:token}).ok,true);
 assert.equal(verifyRecoveryAttestation(signed,trust()).ok,false);
});
