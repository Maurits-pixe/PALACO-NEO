import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {policyCheckpointPayload} from '../src/cas-policy-activation-ledger.mjs';
import {inspectWitnessEquivocation} from '../src/cas-witness-equivocation.mjs';
import {keyQuorumPolicyDigest} from '../src/cas-key-quorum.mjs';
import {escalationReviewPayload,escalationEntryHash,
 INITIAL_ESCALATION_POSITION as genesis} from '../src/cas-escalation-journal.mjs';
import {caseHandoffPayload,custodyReceiptPayload,verifyCaseHandoff}
 from '../src/cas-case-custody.mjs';
import {transferInventoryDigest,transferStoragePayload,verifyCustodyLineage,
 INITIAL_CUSTODY_LINEAGE_POSITION as start} from '../src/cas-custody-lineage.mjs';

const namespace='PALACO-NEO-TEST',caseId='case-035',witnessId='witness-001';
const owner=generateKeyPairSync('ed25519'),security=generateKeyPairSync('ed25519');
const witness=generateKeyPairSync('ed25519'),beta=generateKeyPairSync('ed25519');
const gamma=generateKeyPairSync('ed25519'),attacker=generateKeyPairSync('ed25519');
const pem=k=>k.publicKey.export({type:'spki',format:'pem'});
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const policy=()=>({schema:'NEO-027-POLICY-v1',namespace,version:1,reviewers:[
 {reviewerId:'review-owner',role:'OWNER',status:'ACTIVE',publicKeyPem:pem(owner)},
 {reviewerId:'review-security',role:'SECURITY',status:'ACTIVE',publicKeyPem:pem(security)}]});
const pin=p=>({version:p.version,digest:keyQuorumPolicyDigest(p)});
const cp=head=>({namespace,count:1,head,activePolicy:{version:2,digest:'b'.repeat(64)}});
const seal=c=>({checkpoint:c,witnessId,signature:sign(null,
 policyCheckpointPayload(c,witnessId),witness.privateKey).toString('base64')});
const witnessTrust=()=>({namespace,witnessId,publicKeyPem:pem(witness),
 status:'ACTIVE',trustedCheckpointFloor:{count:0,head:'0'.repeat(64)}});
const dossier=()=>inspectWitnessEquivocation(seal(cp('a'.repeat(64))),
 seal(cp('c'.repeat(64))),witnessTrust()).dossier;
const context=()=>{
 const p=policy(),d=dossier();
 const body={sequence:1,previousHash:genesis.head,caseId,
  action:'OPEN',dossierDigest:d.digest};
 const reviews=[['review-owner','OWNER',owner],['review-security','SECURITY',security]]
 .map(([reviewerId,role,k])=>({reviewerId,signature:sign(null,
  escalationReviewPayload(body,keyQuorumPolicyDigest(p),reviewerId,role),
  k.privateKey).toString('base64')}));
 const entry={...body,reviews,hash:escalationEntryHash(body,reviews)};
 return {entries:[entry],caseEvidence:[{dossier:d,witnessTrust:witnessTrust()}],
  policy:p,policyPin:pin(p),floor:genesis};
};
const manifest=()=>{
 const bytes=Buffer.from('PALACO forensic source bytes','utf8');
 return {manifest:{schema:'NEO-035-INVENTORY-v1',caseId,artifacts:[
  {artifactId:'file-001',sha256:sha(bytes),byteLength:bytes.length}]},
 artifacts:[{artifactId:'file-001',base64:bytes.toString('base64')}]};
};
const step=(c,from,to,transferId,key,previousHash=start.head)=>{
 const body={schema:'NEO-034-HANDOFF-v1',namespace,caseId,
  dossierDigest:c.caseEvidence[0].dossier.digest,
  journalPosition:{count:1,head:c.entries[0].hash},
  fromCustodian:from,toCustodian:to,transferId,
  policyDigest:keyQuorumPolicyDigest(c.policy)};
 const reviews=[['review-owner','OWNER',owner],['review-security','SECURITY',security]]
 .map(([reviewerId,role,k])=>({reviewerId,signature:sign(null,
  caseHandoffPayload(body,reviewerId,role),k.privateKey).toString('base64')}));
 const custodyReceipt={custodianId:to,outcome:'ACCEPTED',signature:sign(null,
   custodyReceiptPayload(body,to,'ACCEPTED'),key.privateKey).toString('base64')};
 const destinationTrust={namespace,custodianId:to,publicKeyPem:pem(key),
  status:'ACTIVE',expectedTransferId:transferId};
 const handoff={body,reviews,custodyReceipt};
 const handoffResult=verifyCaseHandoff(c.entries,c.caseEvidence,c.policy,
  c.policyPin,c.floor,handoff,destinationTrust);
 assert.equal(handoffResult.ok,true);
 const inventory=manifest();
 const signedBody={namespace,caseId,transferId,
  handoffDigest:handoffResult.candidate.evidenceDigest,
  inventoryDigest:transferInventoryDigest(inventory.manifest),previousHash};
 const storageReceipt={custodianId:to,outcome:'OBSERVED',
  signature:sign(null,transferStoragePayload(signedBody,to,'OBSERVED'),
   key.privateKey).toString('base64')};
 return {handoff,destinationTrust,...inventory,storageReceipt};
};
const check=(c,steps,floor=start)=>verifyCustodyLineage(c.entries,c.caseEvidence,
 c.policy,c.policyPin,c.floor,steps,'custodian-alpha',floor);
test('signed byte inventory and destination storage assertion verify without authority',()=>{
 const c=context(),one=step(c,'custodian-alpha','custodian-beta','transfer-001',beta);
 const r=check(c,[one]);
 assert.equal(r.ok,true);assert.equal(r.authorized,false);
 assert.equal(r.phase,'VERIFIED_ASSERTIONS_ONLY');assert.equal(r.candidate.position.count,1);
});
test('two consecutive transfers preserve custody lineage and identical inventory',()=>{
 const c=context(),one=step(c,'custodian-alpha','custodian-beta','transfer-001',beta);
 const first=check(c,[one]);assert.equal(first.ok,true);
 const two=step(c,'custodian-beta','custodian-gamma','transfer-002',gamma,
  first.candidate.position.head);
 const result=check(c,[one,two]);
 assert.equal(result.ok,true);assert.equal(result.candidate.custodianId,'custodian-gamma');
});
test('reused transfer ID fails closed even with different destination',()=>{
 const c=context(),one=step(c,'custodian-alpha','custodian-beta','transfer-001',beta);
 const initial=check(c,[one]);
 const two=step(c,'custodian-beta','custodian-gamma','transfer-001',gamma,
  initial.candidate.position.head);
 assert.equal(check(c,[one,two]).reason,'TRANSFER_ID_REPLAY');
});
test('noncontiguous custodian source is denied',()=>{
 const c=context(),one=step(c,'custodian-other','custodian-beta','transfer-001',beta);
 assert.equal(check(c,[one]).reason,'NONCONTIGUOUS_CUSTODIAN_LINEAGE');
});
test('unsigned or missing storage attestation enters HOLD',()=>{
 const c=context(),one=step(c,'custodian-alpha','custodian-beta','transfer-001',beta);
 one.storageReceipt=null;
 assert.equal(check(c,[one]).reason,'DESTINATION_STORAGE_NOT_CONFIRMED');
});
test('storage attestation from wrong signing key is rejected',()=>{
 const c=context(),one=step(c,'custodian-alpha','custodian-beta','transfer-001',beta);
 one.storageReceipt.signature=sign(null,
  transferStoragePayload({namespace,caseId,transferId:'transfer-001',
   handoffDigest:verifyCaseHandoff(c.entries,c.caseEvidence,c.policy,c.policyPin,
    c.floor,one.handoff,one.destinationTrust).candidate.evidenceDigest,
   inventoryDigest:transferInventoryDigest(one.manifest),previousHash:start.head},
   'custodian-beta','OBSERVED'),attacker.privateKey).toString('base64');
 assert.equal(check(c,[one]).reason,'INVALID_DESTINATION_STORAGE_ATTESTATION');
});
test('missing bytes from required inventory fail',()=>{
 const c=context(),one=step(c,'custodian-alpha','custodian-beta','transfer-001',beta);
 one.artifacts=[];
 assert.equal(check(c,[one]).reason,'MISSING_OR_TAMPERED_ARTIFACTS');
});
test('altered artifact bytes fail cryptographic byte verification',()=>{
 const c=context(),one=step(c,'custodian-alpha','custodian-beta','transfer-001',beta);
 one.artifacts[0].base64=Buffer.from('tampered').toString('base64');
 assert.equal(check(c,[one]).reason,'MISSING_OR_TAMPERED_ARTIFACTS');
});
test('duplicate artifact IDs in manifest fail',()=>{
 const c=context(),one=step(c,'custodian-alpha','custodian-beta','transfer-001',beta);
 one.manifest.artifacts.push({...one.manifest.artifacts[0]});
 one.artifacts.push({...one.artifacts[0]});
 assert.equal(check(c,[one]).reason,'MISSING_OR_TAMPERED_ARTIFACTS');
});
test('inventory altered after signing cannot validate storage',()=>{
 const c=context(),one=step(c,'custodian-alpha','custodian-beta','transfer-001',beta);
 const bytes=Buffer.from('replacement content');
 one.manifest.artifacts[0]={artifactId:'file-001',sha256:sha(bytes),byteLength:bytes.length};
 one.artifacts[0].base64=bytes.toString('base64');
 assert.equal(check(c,[one]).reason,'INVALID_DESTINATION_STORAGE_ATTESTATION');
});
test('changing inventory during second handoff requires separate policy',()=>{
 const c=context(),one=step(c,'custodian-alpha','custodian-beta','transfer-001',beta);
 const first=check(c,[one]);
 const two=step(c,'custodian-beta','custodian-gamma','transfer-002',gamma,
  first.candidate.position.head);
 const bytes=Buffer.from('new material');
 two.manifest.artifacts[0]={artifactId:'file-001',sha256:sha(bytes),byteLength:bytes.length};
 two.artifacts[0].base64=bytes.toString('base64');
 assert.equal(check(c,[one,two]).reason,'INVENTORY_CHANGED_WITHOUT_AUTHORIZED_PROCEDURE');
});
test('externally pinned lineage count blocks rollback',()=>{
 const c=context(),one=step(c,'custodian-alpha','custodian-beta','transfer-001',beta);
 const first=check(c,[one]);
 assert.equal(check(c,[],first.candidate.position).reason,'LINEAGE_ROLLBACK');
});
test('externally pinned different hash blocks fork',()=>{
 const c=context(),one=step(c,'custodian-alpha','custodian-beta','transfer-001',beta);
 assert.equal(check(c,[one],{count:1,head:'f'.repeat(64)}).reason,'LINEAGE_FORK');
});
test('mismatched original forensic journal is refused before inventory',()=>{
 const c=context(),one=step(c,'custodian-alpha','custodian-beta','transfer-001',beta);
 c.caseEvidence=[];
 assert.equal(check(c,[one]).ok,false);
});
test('empty chain is structurally acceptable but grants no authority',()=>{
 const c=context(),r=check(c,[]);
 assert.equal(r.ok,true);assert.equal(r.authorized,false);assert.equal(r.candidate.position.count,0);
});
test('malformed inputs are denied',()=>{
 const c=context();
 assert.equal(check(c,null).ok,false);
 assert.throws(()=>transferInventoryDigest({}),/INVALID_INVENTORY/);
});
