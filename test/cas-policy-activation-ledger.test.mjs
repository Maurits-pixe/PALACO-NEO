import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {policyActivationPayload} from '../src/cas-policy-activation.mjs';
import {INITIAL_POLICY_ACTIVATION_POSITION as genesis,policyActivationEntryHash,
 policyCheckpointPayload,verifyPolicyActivationLedger,
 verifyPolicyActivationCheckpoint,reconcileActivationCheckpoint}
 from '../src/cas-policy-activation-ledger.mjs';

const namespace='PALACO-NEO-TEST';
const custodian=generateKeyPairSync('ed25519'),witness=generateKeyPairSync('ed25519');
const forger=generateKeyPairSync('ed25519');
const pem=k=>k.publicKey.export({type:'spki',format:'pem'});
const original={version:1,digest:'a'.repeat(64)};
const p2={version:2,digest:'b'.repeat(64)},p3={version:3,digest:'c'.repeat(64)};
const req=(i,before,after)=>({
 schema:'NEO-029-CAS-v1',namespace,
 operationId:'operation-'+i,changeId:'change-'+i,
 decisionHead:i.toString(16).padStart(64,'0'),before,after
});
const record=(request,sequence,previousHash,key=custodian)=>{
 const receipt={request,custodianId:'custodian-001',outcome:'APPLIED',
 signature:sign(null,policyActivationPayload(request,'custodian-001','APPLIED'),
 key.privateKey).toString('base64')};
 const body={sequence,previousHash,request,receipt};
 return {...body,hash:policyActivationEntryHash(body)};
};
const fixtures=()=>{
 const first=record(req(1,original,p2),1,genesis.head);
 const second=record(req(2,p2,p3),2,first.hash);
 const entries=[first,second];
 const trust=entries.map(e=>({namespace,custodianId:'custodian-001',
  publicKeyPem:pem(custodian),status:'ACTIVE',
  expectedOperationId:e.request.operationId,trustedBefore:e.request.before}));
 return {entries,trust};
};
const checkpoint=(entries,policy,key=witness)=> {
 const cp={namespace,count:entries.length,head:entries.at(-1)?.hash??genesis.head,
  activePolicy:policy};
 return {checkpoint:cp,witnessId:'witness-001',
  signature:sign(null,policyCheckpointPayload(cp,'witness-001'),
   key.privateKey).toString('base64')};
};
const witnessTrust=(floor=genesis)=>({namespace,witnessId:'witness-001',
 publicKeyPem:pem(witness),status:'ACTIVE',trustedCheckpointFloor:floor});
test('full two-step signed policy activation chain verifies without authority',()=>{
 const f=fixtures(),r=verifyPolicyActivationLedger(f.entries,f.trust,original,genesis);
 assert.equal(r.ok,true);assert.equal(r.authorized,false);
 assert.equal(r.candidate.activePolicy.version,3);
});
test('independent witness checkpoint signs final ledger head and policy',()=>{
 const f=fixtures(),cp=checkpoint(f.entries,p3);
 const r=verifyPolicyActivationCheckpoint(f.entries,f.trust,original,genesis,cp,witnessTrust());
 assert.equal(r.ok,true);assert.equal(r.authorized,false);
 assert.equal(r.candidate.position.count,2);
});
test('truncated chain is rejected against externally pinned floor',()=>{
 const f=fixtures(),floor={count:2,head:f.entries[1].hash};
 assert.equal(verifyPolicyActivationLedger([f.entries[0]],[f.trust[0]],original,floor).reason,
 'ROLLBACK_BELOW_TRUSTED_FLOOR');
});
test('signed checkpoint rollback is refused against witnessed floor',()=>{
 const f=fixtures(),cp=checkpoint([f.entries[0]],p2),floor={count:2,head:f.entries[1].hash};
 assert.equal(verifyPolicyActivationCheckpoint([f.entries[0]],[f.trust[0]],
  original,genesis,cp,witnessTrust(floor)).reason,'CHECKPOINT_ROLLBACK');
});
test('forked independently pinned witness head is refused',()=>{
 const f=fixtures(),cp=checkpoint(f.entries,p3);
 assert.equal(verifyPolicyActivationCheckpoint(f.entries,f.trust,original,genesis,
 cp,witnessTrust({count:2,head:'f'.repeat(64)})).reason,'CHECKPOINT_FORK');
});
test('modified ledger entry cannot pass hash verification',()=>{
 const f=fixtures();f.entries[0]={...f.entries[0],hash:'d'.repeat(64)};
 assert.equal(verifyPolicyActivationLedger(f.entries,f.trust,original,genesis).ok,false);
});
test('custodian signature forgery cannot be appended',()=>{
 const f=fixtures();f.entries[0]=record(f.entries[0].request,1,genesis.head,forger);
 assert.equal(verifyPolicyActivationLedger(f.entries,f.trust,original,genesis).ok,false);
});
test('replayed operation ID is rejected',()=>{
 const f=fixtures(),other={...f.entries[1].request,operationId:f.entries[0].request.operationId};
 f.entries[1]=record(other,2,f.entries[0].hash);
 assert.equal(verifyPolicyActivationLedger(f.entries,f.trust,original,genesis).reason,
 'DUPLICATE_OPERATION_OR_CHANGE');
});
test('noncontiguous policy version is denied',()=>{
 const f=fixtures(),r=req(2,original,p3);
 f.entries[1]=record(r,2,f.entries[0].hash);
 assert.equal(verifyPolicyActivationLedger(f.entries,f.trust,original,genesis).reason,
 'NONCONTIGUOUS_POLICY_HISTORY');
});
test('revoked or mismatched custodian trust rejects receipts',()=>{
 const f=fixtures();f.trust[0].status='REVOKED';
 assert.equal(verifyPolicyActivationLedger(f.entries,f.trust,original,genesis).ok,false);
});
test('checkpoint signed by impostor is rejected',()=>{
 const f=fixtures(),cp=checkpoint(f.entries,p3,forger);
 assert.equal(verifyPolicyActivationCheckpoint(f.entries,f.trust,original,genesis,
 cp,witnessTrust()).reason,'INVALID_CHECKPOINT_SIGNATURE');
});
test('checkpoint binding prevents false final active policy',()=>{
 const f=fixtures(),cp=checkpoint(f.entries,p2);
 assert.equal(verifyPolicyActivationCheckpoint(f.entries,f.trust,original,genesis,
 cp,witnessTrust()).reason,'CHECKPOINT_STATE_CONFLICT');
});
test('revoked external checkpoint signer is not trusted',()=>{
 const f=fixtures(),cp=checkpoint(f.entries,p3);
 assert.equal(verifyPolicyActivationCheckpoint(f.entries,f.trust,original,genesis,
 cp,{...witnessTrust(),status:'REVOKED'}).reason,'REVOKED_CHECKPOINT_WITNESS');
});
test('separately observed external policy must match checkpoint',()=>{
 const cp=checkpoint(fixtures().entries,p3);
 assert.equal(reconcileActivationCheckpoint(p3,cp.checkpoint).phase,'MATCH');
 assert.equal(reconcileActivationCheckpoint(p2,cp.checkpoint).phase,'HOLD');
});
test('invalid trust and missing evidence fail closed',()=>{
 const f=fixtures();
 assert.equal(verifyPolicyActivationLedger(null,null,original,genesis).ok,false);
 assert.equal(verifyPolicyActivationCheckpoint(null,null,original,genesis,
  checkpoint(f.entries,p3),witnessTrust()).ok,false);
 assert.equal(reconcileActivationCheckpoint(null,{}).phase,'HOLD');
});
