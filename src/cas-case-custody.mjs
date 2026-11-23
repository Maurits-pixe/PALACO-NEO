import {createHash,createPublicKey,verify as verifySignature} from 'node:crypto';
import {verifyEscalationJournal} from './cas-escalation-journal.mjs';
import {keyQuorumPolicyDigest} from './cas-key-quorum.mjs';

/**
 * NEO-034: offline verification of signed case custody and handoff evidence.
 * Requires complete NEO-033 journal and independently pinned trust keys.
 * No actual storage, transmission, assignment, case release or authorization.
 */
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 (Object.getPrototypeOf(x)===Object.prototype||Object.getPrototypeOf(x)===null);
const exact=(x,keys)=>plain(x)&&Object.keys(x).sort().join(',')===[...keys].sort().join(',');
const id=x=>typeof x==='string'&&/^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const hex=x=>typeof x==='string'&&/^[0-9a-f]{64}$/.test(x);
const position=x=>exact(x,['count','head'])&&Number.isSafeInteger(x.count)&&
 x.count>=0&&x.count<=256&&hex(x.head);
const base64=x=>typeof x==='string'&&/^[A-Za-z0-9+/]{86}==$/.test(x)&&
 Buffer.from(x,'base64').toString('base64')===x;
const deny=reason=>Object.freeze({ok:false,reason,authorized:false,candidate:null});
const pin=x=>exact(x,['version','digest'])&&Number.isSafeInteger(x.version)&&
 x.version>=1&&hex(x.digest);
const custodyKeys=['schema','namespace','caseId','dossierDigest','journalPosition',
 'fromCustodian','toCustodian','transferId','policyDigest'];
const evidenceKeys=['body','reviews','custodyReceipt'];
function hashBytes(bytes){return createHash('sha256').update(bytes).digest('hex');}
function validBody(b){
 return exact(b,custodyKeys)&&b.schema==='NEO-034-HANDOFF-v1'&&
 id(b.namespace)&&id(b.caseId)&&hex(b.dossierDigest)&&position(b.journalPosition)&&
 id(b.fromCustodian)&&id(b.toCustodian)&&b.fromCustodian!==b.toCustodian&&
 id(b.transferId)&&hex(b.policyDigest);
}
/** Bound to a specific journal checkpoint, case and destination custodian. */
export function caseHandoffPayload(body,reviewerId,role){
 if(!validBody(body)||!id(reviewerId)||!['OWNER','SECURITY'].includes(role))
  throw new TypeError('INVALID_HANDOFF_PAYLOAD');
 return Buffer.from(JSON.stringify([
  'PALACO-NEO-CASE-HANDOFF-REVIEW-v1',body.namespace,body.caseId,
  body.dossierDigest,body.journalPosition.count,body.journalPosition.head,
  body.fromCustodian,body.toCustodian,body.transferId,body.policyDigest,
  reviewerId,role
 ]),'utf8');
}
export function custodyReceiptPayload(body,custodianId,outcome){
 if(!validBody(body)||!id(custodianId)||custodianId!==body.toCustodian||
    !['ACCEPTED','REJECTED'].includes(outcome))
  throw new TypeError('INVALID_CUSTODY_RECEIPT');
 return Buffer.from(JSON.stringify([
  'PALACO-NEO-CASE-CUSTODY-RECEIPT-v1',
  body.namespace,body.caseId,body.dossierDigest,
  body.journalPosition.count,body.journalPosition.head,
  body.fromCustodian,body.toCustodian,body.transferId,
  body.policyDigest,custodianId,outcome
 ]),'utf8');
}
function pinnedKey(pem){
 try{
  if(typeof pem!=='string'||pem.length>8192||pem.length===0)return null;
  const key=createPublicKey(pem);
  return key.asymmetricKeyType==='ed25519'?key:null;
 }catch{return null;}
}
function signedBy(pem,payload,signature){
 if(!base64(signature))return false;
 const key=pinnedKey(pem);
 if(!key)return false;
 try{return verifySignature(null,payload,key,Buffer.from(signature,'base64'));}
 catch{return false;}
}
/**
 * The journal MUST revalidate all full forensic dossiers. Custody evidence
 * cannot replace any missing journal entry or original witness signature.
 */
export function verifyCaseHandoff(entries,caseEvidence,policy,policyPin,trustedFloor,
 handoff,destinationTrust){
 const journal=verifyEscalationJournal(entries,caseEvidence,policy,policyPin,trustedFloor);
 if(!journal.ok)return deny('JOURNAL_'+journal.reason);
 let digest;
 try{digest=keyQuorumPolicyDigest(policy);}catch{return deny('INVALID_POLICY');}
 if(!exact(handoff,evidenceKeys)||!validBody(handoff.body)||
    !Array.isArray(handoff.reviews)||handoff.reviews.length!==2||
    !exact(handoff.custodyReceipt,['custodianId','outcome','signature']))
  return deny('INVALID_HANDOFF_EVIDENCE');
 const b=handoff.body;
 if(b.namespace!==policy.namespace||b.policyDigest!==digest||
    b.journalPosition.count!==journal.candidate.position.count||
    b.journalPosition.head!==journal.candidate.position.head)
  return deny('UNTRUSTED_HANDOFF_CONTEXT');
 const c=journal.candidate.cases.find(x=>x.caseId===b.caseId);
 if(!c||c.dossierDigest!==b.dossierDigest||c.status!=='ESCALATED_HOLD')
  return deny('MISSING_OR_CHANGED_CASE');
 const roster=new Map(policy.reviewers.map(r=>[r.reviewerId,r]));
 const ids=new Set(),roles=new Set(),fingerprints=new Set();
 for(const review of handoff.reviews){
  if(!exact(review,['reviewerId','signature'])||!id(review.reviewerId)||
    ids.has(review.reviewerId))return deny('DUPLICATE_HANDOFF_REVIEWER');
  const reviewer=roster.get(review.reviewerId);
  if(!reviewer||reviewer.status!=='ACTIVE'||roles.has(reviewer.role))
   return deny('REVOKED_OR_DUPLICATE_HANDOFF_ROLE');
  const key=pinnedKey(reviewer.publicKeyPem);
  if(!key)return deny('INVALID_REVIEW_KEY');
  const fingerprint=key.export({type:'spki',format:'der'}).toString('base64');
  if(fingerprints.has(fingerprint)||!signedBy(reviewer.publicKeyPem,
     caseHandoffPayload(b,reviewer.reviewerId,reviewer.role),review.signature))
   return deny('INVALID_HANDOFF_SIGNATURE');
  ids.add(reviewer.reviewerId);roles.add(reviewer.role);fingerprints.add(fingerprint);
 }
 if(!roles.has('OWNER')||!roles.has('SECURITY'))
  return deny('MISSING_DUAL_REVIEW');
 if(!exact(destinationTrust,['namespace','custodianId','publicKeyPem','status','expectedTransferId'])||
    destinationTrust.namespace!==b.namespace||
    destinationTrust.custodianId!==b.toCustodian||
    destinationTrust.expectedTransferId!==b.transferId||
    destinationTrust.status!=='ACTIVE')
  return deny('UNTRUSTED_DESTINATION');
 const receipt=handoff.custodyReceipt;
 if(receipt.custodianId!==b.toCustodian||receipt.outcome!=='ACCEPTED'||
    !signedBy(destinationTrust.publicKeyPem,
      custodyReceiptPayload(b,b.toCustodian,'ACCEPTED'),receipt.signature))
  return deny('INVALID_CUSTODY_ACCEPTANCE');
 const evidenceDigest=hashBytes(Buffer.from(JSON.stringify([
  'PALACO-NEO-HANDOFF-EVIDENCE-v1',
  b.namespace,b.caseId,b.dossierDigest,b.journalPosition.count,b.journalPosition.head,
  b.fromCustodian,b.toCustodian,b.transferId,b.policyDigest,
  [...handoff.reviews].sort((a,c)=>a.reviewerId<c.reviewerId?-1:1)
    .map(x=>[x.reviewerId,x.signature]),
  receipt.custodianId,receipt.outcome,receipt.signature
 ]),'utf8'));
 return Object.freeze({ok:true,reason:'SIGNED_HANDOFF_EVIDENCE_NO_AUTHORITY',
  authorized:false,candidate:Object.freeze({
   caseId:b.caseId,status:'ESCALATED_HOLD',evidenceDigest,
   journalPosition:journal.candidate.position
  })});
}
/** Never claim custody merely because two supplied observations match. */
export function classifyCaseCustodyObservation(handoffResult,fromObservation,toObservation){
 if(!plain(handoffResult)||handoffResult.ok!==true||
    handoffResult.reason!=='SIGNED_HANDOFF_EVIDENCE_NO_AUTHORITY'||
    !plain(handoffResult.candidate)||!hex(handoffResult.candidate.evidenceDigest)||
    !exact(fromObservation,['caseId','evidenceDigest'])||
    !exact(toObservation,['caseId','evidenceDigest']))
  return Object.freeze({phase:'HOLD',reason:'UNVERIFIED_CUSTODY_OBSERVATION',authorized:false});
 const c=handoffResult.candidate;
 if(fromObservation.caseId!==c.caseId||toObservation.caseId!==c.caseId||
    fromObservation.evidenceDigest!==c.evidenceDigest||
    toObservation.evidenceDigest!==c.evidenceDigest)
  return Object.freeze({phase:'HOLD',reason:'CONFLICTING_CUSTODY_OBSERVATIONS',authorized:false});
 return Object.freeze({phase:'MATCHING_ASSERTIONS',reason:'NO_INDEPENDENT_CUSTODY_PROOF',
  authorized:false});
}
