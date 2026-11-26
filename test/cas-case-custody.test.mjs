import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {policyCheckpointPayload} from '../src/cas-policy-activation-ledger.mjs';
import {inspectWitnessEquivocation} from '../src/cas-witness-equivocation.mjs';
import {keyQuorumPolicyDigest} from '../src/cas-key-quorum.mjs';
import {escalationReviewPayload,escalationEntryHash,
 INITIAL_ESCALATION_POSITION as genesis} from '../src/cas-escalation-journal.mjs';
import {caseHandoffPayload,custodyReceiptPayload,verifyCaseHandoff,
 classifyCaseCustodyObservation} from '../src/cas-case-custody.mjs';

const namespace='PALACO-NEO-TEST',caseId='case-034',witnessId='witness-001';
const owner=generateKeyPairSync('ed25519'),security=generateKeyPairSync('ed25519');
const witness=generateKeyPairSync('ed25519'),destination=generateKeyPairSync('ed25519');
const forger=generateKeyPairSync('ed25519');
const pem=k=>k.publicKey.export({type:'spki',format:'pem'});
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
const journal=(p=policy(),d=dossier())=>{
 const body={sequence:1,previousHash:genesis.head,caseId,action:'OPEN',dossierDigest:d.digest};
 const reviews=[['review-owner','OWNER',owner],['review-security','SECURITY',security]]
 .map(([reviewerId,role,k])=>({reviewerId,signature:sign(null,
  escalationReviewPayload(body,keyQuorumPolicyDigest(p),reviewerId,role),
  k.privateKey).toString('base64')}));
 return {...body,reviews,hash:escalationEntryHash(body,reviews)};
};
const make=()=>{
 const p=policy(),d=dossier(),entry=journal(p,d);
 const body={schema:'NEO-034-HANDOFF-v1',namespace,caseId,dossierDigest:d.digest,
 journalPosition:{count:1,head:entry.hash},fromCustodian:'custodian-alpha',
 toCustodian:'custodian-beta',transferId:'transfer-034',
 policyDigest:keyQuorumPolicyDigest(p)};
 const reviews=[['review-owner','OWNER',owner],['review-security','SECURITY',security]]
 .map(([reviewerId,role,k])=>({reviewerId,signature:sign(null,
  caseHandoffPayload(body,reviewerId,role),k.privateKey).toString('base64')}));
 const custodyReceipt={custodianId:'custodian-beta',outcome:'ACCEPTED',
 signature:sign(null,custodyReceiptPayload(body,'custodian-beta','ACCEPTED'),
  destination.privateKey).toString('base64')};
 const destinationTrust={namespace,custodianId:'custodian-beta',
  publicKeyPem:pem(destination),status:'ACTIVE',expectedTransferId:'transfer-034'};
 return {entries:[entry],caseEvidence:[{dossier:d,witnessTrust:witnessTrust()}],
  policy:p,policyPin:pin(p),floor:genesis,
  handoff:{body,reviews,custodyReceipt},destinationTrust};
};
const verify=c=>verifyCaseHandoff(c.entries,c.caseEvidence,c.policy,c.policyPin,
 c.floor,c.handoff,c.destinationTrust);
test('verified dual-signed handoff and destination receipt preserve HOLD',()=>{
 const c=make(),r=verify(c);
 assert.equal(r.ok,true);assert.equal(r.authorized,false);
 assert.equal(r.candidate.status,'ESCALATED_HOLD');
 assert.equal(r.candidate.evidenceDigest.length,64);
});
test('forged destination acceptance signature is refused',()=>{
 const c=make(),b=c.handoff.body;
 c.handoff.custodyReceipt.signature=sign(null,
  custodyReceiptPayload(b,'custodian-beta','ACCEPTED'),forger.privateKey).toString('base64');
 assert.equal(verify(c).reason,'INVALID_CUSTODY_ACCEPTANCE');
});
test('destination marked revoked cannot be trusted',()=>{
 const c=make();c.destinationTrust.status='REVOKED';
 assert.equal(verify(c).reason,'UNTRUSTED_DESTINATION');
});
test('stale independently pinned journal floor fails',()=>{
 const c=make();c.floor={count:1,head:'f'.repeat(64)};
 assert.equal(verify(c).ok,false);
});
test('missing complete original dossier fails before custody verification',()=>{
 const c=make();c.caseEvidence=[];
 assert.equal(verify(c).ok,false);
});
test('substituted forensic evidence is refused',()=>{
 const c=make();c.caseEvidence[0].dossier={...c.caseEvidence[0].dossier,
  digest:'f'.repeat(64)};
 assert.equal(verify(c).ok,false);
});
test('different case ID cannot use an existing handoff',()=>{
 const c=make();c.handoff.body={...c.handoff.body,caseId:'case-999'};
 assert.equal(verify(c).reason,'MISSING_OR_CHANGED_CASE');
});
test('different journal checkpoint fails before reviewing signatures',()=>{
 const c=make();c.handoff.body.journalPosition={count:1,head:'f'.repeat(64)};
 assert.equal(verify(c).reason,'UNTRUSTED_HANDOFF_CONTEXT');
});
test('forged OWNER review cannot approve transfer',()=>{
 const c=make(),b=c.handoff.body;
 c.handoff.reviews[0].signature=sign(null,
  caseHandoffPayload(b,'review-owner','OWNER'),forger.privateKey).toString('base64');
 assert.equal(verify(c).reason,'INVALID_HANDOFF_SIGNATURE');
});
test('duplicate reviewer cannot fill OWNER and SECURITY quorum',()=>{
 const c=make();c.handoff.reviews[1]={...c.handoff.reviews[0]};
 assert.equal(verify(c).reason,'DUPLICATE_HANDOFF_REVIEWER');
});
test('missing one reviewer fails closed',()=>{
 const c=make();c.handoff.reviews.pop();
 assert.equal(verify(c).reason,'INVALID_HANDOFF_EVIDENCE');
});
test('reviewer status change is denied under externally pinned policy',()=>{
 const c=make();c.policy.reviewers[0].status='REVOKED';
 c.policyPin=pin(c.policy);
 assert.equal(verify(c).ok,false);
});
test('mismatched trusted transfer ID is rejected',()=>{
 const c=make();c.destinationTrust.expectedTransferId='another-transfer';
 assert.equal(verify(c).reason,'UNTRUSTED_DESTINATION');
});
test('destination REJECTED receipt never counts as custody acceptance',()=>{
 const c=make();c.handoff.custodyReceipt.outcome='REJECTED';
 assert.equal(verify(c).reason,'INVALID_CUSTODY_ACCEPTANCE');
});
test('matching claimed observations do not constitute independent custody proof',()=>{
 const c=make(),r=verify(c),ob={caseId,evidenceDigest:r.candidate.evidenceDigest};
 const result=classifyCaseCustodyObservation(r,ob,ob);
 assert.equal(result.phase,'MATCHING_ASSERTIONS');assert.equal(result.authorized,false);
});
test('conflicting claims about custody stay HOLD',()=>{
 const c=make(),r=verify(c),ob={caseId,evidenceDigest:r.candidate.evidenceDigest};
 assert.equal(classifyCaseCustodyObservation(r,ob,
  {...ob,evidenceDigest:'f'.repeat(64)}).phase,'HOLD');
});
test('unverified result, invalid observation or empty evidence are held',()=>{
 const c=make();
 assert.equal(classifyCaseCustodyObservation({ok:true},null,null).phase,'HOLD');
 assert.equal(verifyCaseHandoff([],[],c.policy,c.policyPin,c.floor,c.handoff,
  c.destinationTrust).ok,false);
});
