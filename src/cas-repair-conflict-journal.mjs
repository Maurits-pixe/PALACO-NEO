import {createHash,createPublicKey,verify as edVerify} from 'node:crypto';
import {inspectRepairCheckpointFork} from './cas-repair-history.mjs';
import {keyQuorumPolicyDigest} from './cas-key-quorum.mjs';

/** NEO-040. Read-only dual-reviewed conflict register: HOLD is irreversible here. */
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 (Object.getPrototypeOf(x)===Object.prototype||Object.getPrototypeOf(x)===null);
const exact=(x,fields)=>plain(x)&&Object.keys(x).sort().join(',')===[...fields].sort().join(',');
const id=x=>typeof x==='string'&&/^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const hex=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const pos=x=>exact(x,['count','head'])&&Number.isSafeInteger(x.count)&&
 x.count>=0&&x.count<=128&&hex(x.head);
const sig=x=>typeof x==='string'&&/^[A-Za-z0-9+/]{86}==$/.test(x)&&
 Buffer.from(x,'base64').toString('base64')===x;
const fail=reason=>Object.freeze({ok:false,phase:'HOLD',reason,authorized:false,candidate:null});
const genesis=Object.freeze({count:0,head:'0'.repeat(64)});
const entryFields=['sequence','previousHash','caseId','action','forkDigest','reviews','hash'];
const bodyFields=['sequence','previousHash','caseId','action','forkDigest'];
const evidenceFields=['left','right','forkFloor'];
const sort=(a,b)=>a<b?-1:a>b?1:0;
const sha=x=>createHash('sha256').update(JSON.stringify(x)).digest('hex');
const validBody=b=>exact(b,bodyFields)&&Number.isSafeInteger(b.sequence)&&
 b.sequence>=1&&b.sequence<=128&&hex(b.previousHash)&&id(b.caseId)&&
 b.action==='ESCALATE_HOLD'&&hex(b.forkDigest);
const forkFields=['position','leftHash','rightHash','sharedSigningWitnesses'];
/** Recompute fork evidence from full signed NEO-039 branches, never a caller verdict. */
export function repairForkEvidenceDigest(forkCandidate){
 if(!exact(forkCandidate,forkFields)||!exact(forkCandidate.position,['count','previousHead'])||
    !Number.isSafeInteger(forkCandidate.position.count)||
    forkCandidate.position.count<1||forkCandidate.position.count>256||
    !hex(forkCandidate.position.previousHead)||!hex(forkCandidate.leftHash)||
    !hex(forkCandidate.rightHash)||forkCandidate.leftHash===forkCandidate.rightHash||
    !Array.isArray(forkCandidate.sharedSigningWitnesses)||
    forkCandidate.sharedSigningWitnesses.length>16||
    forkCandidate.sharedSigningWitnesses.some(x=>!id(x))||
    new Set(forkCandidate.sharedSigningWitnesses).size!==
      forkCandidate.sharedSigningWitnesses.length)
  throw new TypeError('INVALID_FORK_EVIDENCE');
 const heads=[forkCandidate.leftHash,forkCandidate.rightHash].sort();
 return sha(['PALACO-NEO-REPAIR-FORK-EVIDENCE-v1',
  forkCandidate.position.count,forkCandidate.position.previousHead,
  heads,[...forkCandidate.sharedSigningWitnesses].sort()]);
}
export function repairConflictReviewPayload(body,policyDigest,reviewerId,role){
 if(!validBody(body)||!hex(policyDigest)||!id(reviewerId)||
    !['OWNER','SECURITY'].includes(role))
  throw new TypeError('INVALID_FORK_REVIEW');
 return Buffer.from(JSON.stringify(['PALACO-NEO-FORK-ESCALATION-REVIEW-v1',
  body.sequence,body.previousHash,body.caseId,body.action,body.forkDigest,
  policyDigest,reviewerId,role]),'utf8');
}
export function repairConflictEntryHash(body,reviews){
 if(!validBody(body)||!Array.isArray(reviews)||reviews.length!==2||
    reviews.some(x=>!exact(x,['reviewerId','signature'])||
      !id(x.reviewerId)||!sig(x.signature))||
    reviews[0].reviewerId===reviews[1].reviewerId)
  throw new TypeError('INVALID_FORK_JOURNAL_ENTRY');
 return sha(['PALACO-NEO-FORK-ESCALATION-ENTRY-v1',
  body.sequence,body.previousHash,body.caseId,body.action,body.forkDigest,
  [...reviews].sort((a,b)=>sort(a.reviewerId,b.reviewerId))
   .map(r=>[r.reviewerId,r.signature])]);
}
function publicKey(pem){
 try{
  if(typeof pem!=='string'||pem.length>8192)return null;
  const key=createPublicKey(pem);
  return key.asymmetricKeyType==='ed25519'?key:null;
 }catch{return null;}
}
/** Each entry must carry the complete original conflicting histories. */
export function verifyRepairConflictJournal(entries,evidence,policy,policyPin,trustedFloor){
 if(!Array.isArray(entries)||!Array.isArray(evidence)||
    entries.length!==evidence.length||entries.length>128||!pos(trustedFloor)||
    !exact(policyPin,['version','digest'])||
    !Number.isSafeInteger(policyPin.version)||policyPin.version<1||
    !hex(policyPin.digest))
  return fail('INVALID_CONFLICT_JOURNAL_INPUT');
 let digest;
 try{digest=keyQuorumPolicyDigest(policy);}
 catch{return fail('INVALID_REVIEW_POLICY');}
 if(policy.version!==policyPin.version||digest!==policyPin.digest)
  return fail('REVIEW_POLICY_PIN_CONFLICT');
 const reviewers=new Map(policy.reviewers.map(x=>[x.reviewerId,x]));
 let head=genesis.head;
 const cases=new Map(),forks=new Set();
 for(let i=0;i<entries.length;i++){
  const e=entries[i],ev=evidence[i];
  if(!exact(e,entryFields)||!validBody(e)||
     e.sequence!==i+1||e.previousHash!==head||!hex(e.hash)||
     !Array.isArray(e.reviews)||e.reviews.length!==2)
   return fail('BROKEN_CONFLICT_JOURNAL_CHAIN');
  if(!exact(ev,evidenceFields)||!Array.isArray(ev.left)||
     !Array.isArray(ev.right)||!pos(ev.forkFloor))
   return fail('MISSING_OR_INVALID_FORK_EVIDENCE');
  const fork=inspectRepairCheckpointFork(ev.left,ev.right,ev.forkFloor);
  if(!fork.ok||fork.phase!=='FORK_EVIDENCE_HOLD'||!fork.candidate)
   return fail('UNVERIFIED_RECOVERY_FORK');
  let forkDigest;
  try{forkDigest=repairForkEvidenceDigest(fork.candidate);}
  catch{return fail('INVALID_FORK_DIGEST');}
  if(forkDigest!==e.forkDigest)return fail('FORK_EVIDENCE_SUBSTITUTED');
  if(cases.has(e.caseId)||forks.has(forkDigest))
   return fail('DUPLICATE_CONFLICT_CASE_OR_FORK');
  const body=Object.fromEntries(bodyFields.map(k=>[k,e[k]]));
  const seenIds=new Set(),seenRoles=new Set(),seenKeys=new Set();
  for(const review of e.reviews){
   if(!exact(review,['reviewerId','signature'])||!id(review.reviewerId)||
      !sig(review.signature)||seenIds.has(review.reviewerId))
    return fail('INVALID_OR_DUPLICATE_REVIEW');
   const reviewer=reviewers.get(review.reviewerId);
   if(!reviewer||reviewer.status!=='ACTIVE'||seenRoles.has(reviewer.role))
    return fail('REVOKED_OR_DUPLICATE_REVIEW_ROLE');
   const key=publicKey(reviewer.publicKeyPem);
   if(!key)return fail('INVALID_REVIEW_KEY');
   const fingerprint=key.export({type:'spki',format:'der'}).toString('base64');
   if(seenKeys.has(fingerprint)||!edVerify(null,
     repairConflictReviewPayload(body,digest,reviewer.reviewerId,reviewer.role),
     key,Buffer.from(review.signature,'base64')))
    return fail('INVALID_REVIEW_SIGNATURE');
   seenIds.add(review.reviewerId);seenRoles.add(reviewer.role);
   seenKeys.add(fingerprint);
  }
  if(!seenRoles.has('OWNER')||!seenRoles.has('SECURITY'))
   return fail('MISSING_OWNER_SECURITY_QUORUM');
  let calculated;
  try{calculated=repairConflictEntryHash(body,e.reviews);}
  catch{return fail('INVALID_ENTRY_HASH');}
  if(e.hash!==calculated)return fail('TAMPERED_CONFLICT_ENTRY');
  head=e.hash;cases.set(e.caseId,forkDigest);forks.add(forkDigest);
 }
 if(entries.length<trustedFloor.count)return fail('CONFLICT_JOURNAL_ROLLBACK');
 const ancestor=trustedFloor.count===0?genesis.head:
  entries[trustedFloor.count-1].hash;
 if(ancestor!==trustedFloor.head)return fail('CONFLICT_JOURNAL_FORK');
 return Object.freeze({ok:true,phase:'ESCALATION_EVIDENCE_VERIFIED_HOLD',
  reason:'SIGNED_CONFLICT_HISTORY_NO_RELEASE',authorized:false,
  candidate:Object.freeze({position:Object.freeze({count:entries.length,head}),
   cases:Object.freeze([...cases].map(([caseId,forkDigest])=>
    Object.freeze({caseId,forkDigest,status:'ESCALATED_HOLD'})) )})});
}
export const INITIAL_REPAIR_CONFLICT_POSITION=genesis;
