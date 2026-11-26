import {createHash,createPublicKey,verify as verifySignature} from 'node:crypto';
import {assessReplicaArchive} from './cas-replica-recovery.mjs';
import {keyQuorumPolicyDigest} from './cas-key-quorum.mjs';

/** NEO-037: offline, dual-reviewed, never-executable recovery evidence. */
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 (Object.getPrototypeOf(x)===Object.prototype||Object.getPrototypeOf(x)===null);
const exact=(x,fields)=>obj(x)&&Object.keys(x).sort().join(',')===[...fields].sort().join(',');
const id=x=>typeof x==='string'&&/^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const hex=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const sig=x=>typeof x==='string'&&/^[A-Za-z0-9+/]{86}==$/.test(x)&&
 Buffer.from(x,'base64').toString('base64')===x;
const deny=reason=>Object.freeze({ok:false,phase:'HOLD',reason,authorized:false,candidate:null});
const ok=(phase,reason,candidate)=>Object.freeze({ok:true,phase,reason,authorized:false,candidate});
const digest=x=>createHash('sha256').update(JSON.stringify(x)).digest('hex');
const pin=x=>exact(x,['version','digest'])&&Number.isSafeInteger(x.version)&&
 x.version>=1&&hex(x.digest);
const position=x=>exact(x,['count','head'])&&Number.isSafeInteger(x.count)&&
 x.count>=1&&x.count<=64&&hex(x.head);
function signer(pem){
 try{
  if(typeof pem!=='string'||pem.length>8192)return null;
  const key=createPublicKey(pem);
  return key.asymmetricKeyType==='ed25519'?key:null;
 }catch{return null;}
}
function policyDigest(policy,policyPin){
 let value;
 try{value=keyQuorumPolicyDigest(policy);}catch{return null;}
 return pin(policyPin)&&policy.version===policyPin.version&&value===policyPin.digest?
  value:null;
}
function stableProposal(proposal){
 if(!exact(proposal,['caseId','inventoryDigest','lineagePosition',
   'missingArtifactIds','defectiveReplicas']))return null;
 if(!id(proposal.caseId)||!hex(proposal.inventoryDigest)||
   !position(proposal.lineagePosition)||
   !Array.isArray(proposal.missingArtifactIds)||
   proposal.missingArtifactIds.length<1||proposal.missingArtifactIds.length>64||
   !Array.isArray(proposal.defectiveReplicas)||proposal.defectiveReplicas.length<1||
   proposal.defectiveReplicas.length>16)return null;
 const ids=new Set(),missing=new Set();
 for(const a of proposal.missingArtifactIds){
  if(!id(a)||missing.has(a))return null;
  missing.add(a);
 }
 const defective=[];
 for(const r of proposal.defectiveReplicas){
  if(!exact(r,['replicaId','missing'])||!id(r.replicaId)||
     ids.has(r.replicaId)||!Array.isArray(r.missing)||
     r.missing.length<1||r.missing.length>64)return null;
  ids.add(r.replicaId);
  const list=new Set();
  for(const a of r.missing){
   if(!id(a)||list.has(a)||!missing.has(a))return null;
   list.add(a);
  }
  defective.push([r.replicaId,[...list].sort()]);
 }
 const union=[...new Set(defective.flatMap(x=>x[1]))].sort();
 if(union.join(',')!==[...missing].sort().join(','))return null;
 return [proposal.caseId,proposal.inventoryDigest,
  proposal.lineagePosition.count,proposal.lineagePosition.head,
  [...missing].sort(),defective.sort((a,b)=>a[0]<b[0]?-1:1)];
}
export function recoveryProposalDigest(proposal){
 const stable=stableProposal(proposal);
 if(stable===null)throw new TypeError('INVALID_RECOVERY_PROPOSAL');
 return digest(['PALACO-NEO-RECOVERY-PROPOSAL-v1',stable]);
}
export function recoveryReviewPayload(body,reviewerId,role){
 if(!exact(body,['schema','namespace','recoveryId','policyDigest',
  'proposalDigest','inventoryDigest','lineagePosition'])||
   body.schema!=='NEO-037-RECOVERY-v1'||!id(body.namespace)||
   !id(body.recoveryId)||!hex(body.policyDigest)||
   !hex(body.proposalDigest)||!hex(body.inventoryDigest)||
   !position(body.lineagePosition)||!id(reviewerId)||
   !['OWNER','SECURITY'].includes(role))
  throw new TypeError('INVALID_RECOVERY_REVIEW_PAYLOAD');
 return Buffer.from(JSON.stringify(['PALACO-NEO-RECOVERY-REVIEW-v1',
  body.namespace,body.recoveryId,body.policyDigest,body.proposalDigest,
  body.inventoryDigest,body.lineagePosition.count,body.lineagePosition.head,
  reviewerId,role]),'utf8');
}
/**
 * Verify fresh NEO-036 pre-state, replay its exact repair proposal,
 * require separately pinned OWNER + SECURITY signatures, and check post-state
 * (all bytes present, unique fresh observation IDs, same replica roster/keys).
 * This emits evidence ONLY: the operator is never instructed to mutate storage.
 */
export function verifyRecoveryEvidence(manifest,inventoryPin,lineagePosition,
 pre,post,policy,policyPin,approval,expectedNamespace){
 if(!id(expectedNamespace)||!hex(inventoryPin)||!position(lineagePosition)||
    !exact(pre,['replicas','trusts','expectedReplicaIds'])||
    !exact(post,['replicas','trusts','expectedReplicaIds'])||
    !exact(approval,['body','reviews'])||!obj(approval.body)||
    !Array.isArray(approval.reviews)||approval.reviews.length!==2)
  return deny('INVALID_RECOVERY_INPUT');
 const policyHash=policyDigest(policy,policyPin);
 if(policyHash===null||policy.namespace!==expectedNamespace)
  return deny('UNTRUSTED_RECOVERY_POLICY');
 const before=assessReplicaArchive(manifest,inventoryPin,lineagePosition,
  pre.replicas,pre.trusts,pre.expectedReplicaIds,expectedNamespace);
 if(!before.ok||before.phase!=='REPAIR_PROPOSAL_ONLY'||
    !before.candidate?.repairProposal)
  return deny('NO_VERIFIED_REPAIR_PROPOSAL');
 const proposal=before.candidate.repairProposal;
 const b=approval.body;
 let proposalHash;
 try{proposalHash=recoveryProposalDigest(proposal);}catch{return deny('INVALID_PROPOSAL');}
 if(b.schema!=='NEO-037-RECOVERY-v1'||b.namespace!==expectedNamespace||
    !id(b.recoveryId)||b.policyDigest!==policyHash||
    b.proposalDigest!==proposalHash||b.inventoryDigest!==inventoryPin||
    !position(b.lineagePosition)||b.lineagePosition.count!==lineagePosition.count||
    b.lineagePosition.head!==lineagePosition.head)
  return deny('RECOVERY_CONTEXT_CONFLICT');
 const reviewers=new Map(policy.reviewers.map(x=>[x.reviewerId,x]));
 const usedIds=new Set(),usedRoles=new Set(),usedKeys=new Set();
 for(const review of approval.reviews){
  if(!exact(review,['reviewerId','signature'])||!id(review.reviewerId)||
     usedIds.has(review.reviewerId)||!sig(review.signature))
    return deny('INVALID_RECOVERY_REVIEW');
  const reviewer=reviewers.get(review.reviewerId);
  if(!reviewer||reviewer.status!=='ACTIVE'||usedRoles.has(reviewer.role))
   return deny('REVOKED_OR_DUPLICATE_REVIEW_ROLE');
  const key=signer(reviewer.publicKeyPem);
  if(!key)return deny('INVALID_REVIEW_KEY');
  const fingerprint=key.export({type:'spki',format:'der'}).toString('base64');
  if(usedKeys.has(fingerprint))return deny('DUPLICATE_REVIEW_KEY');
  let bytes;
  try{bytes=recoveryReviewPayload(b,reviewer.reviewerId,reviewer.role);}
  catch{return deny('INVALID_RECOVERY_REVIEW_PAYLOAD');}
  if(!verifySignature(null,bytes,key,Buffer.from(review.signature,'base64')))
   return deny('INVALID_RECOVERY_SIGNATURE');
  usedIds.add(review.reviewerId);usedRoles.add(reviewer.role);usedKeys.add(fingerprint);
 }
 if(!usedRoles.has('OWNER')||!usedRoles.has('SECURITY'))
  return deny('MISSING_DUAL_ROLE_REVIEW');
 if(JSON.stringify(pre.expectedReplicaIds)!==JSON.stringify(post.expectedReplicaIds)||
    pre.trusts.length!==post.trusts.length||
    pre.replicas.length!==post.replicas.length)
  return deny('REPLICA_ROSTER_CHANGED');
 const oldTrust=new Map(pre.trusts.map(x=>[x.replicaId,x]));
 const previousIds=new Set(pre.replicas.map(x=>x?.body?.observationId));
 for(const t of post.trusts){
  const old=oldTrust.get(t?.replicaId);
  if(!old||t.publicKeyPem!==old.publicKeyPem||
     t.status!==old.status||t.namespace!==old.namespace||
     t.expectedObservationId===old.expectedObservationId)
   return deny('REPLICA_TRUST_OR_OBSERVATION_CONFLICT');
 }
 for(const r of post.replicas){
  if(previousIds.has(r?.body?.observationId))
   return deny('STALE_POST_REPAIR_OBSERVATION');
 }
 const after=assessReplicaArchive(manifest,inventoryPin,lineagePosition,
  post.replicas,post.trusts,post.expectedReplicaIds,expectedNamespace);
 if(!after.ok||after.phase!=='VERIFIED_ASSERTIONS_ONLY'||
    after.candidate.healthyReplicas.length!==pre.replicas.length)
  return deny('POST_REPAIR_INVENTORY_NOT_VERIFIED');
 return ok('POST_REPAIR_EVIDENCE_VERIFIED_NO_AUTHORITY',
  'REPAIR_CLAIMS_MATCH_INVENTORY_NOT_DURABLE_STORAGE_PROOF',
  Object.freeze({recoveryId:b.recoveryId,proposalDigest:proposalHash,
   inventoryDigest:inventoryPin,verifiedReplicas:Object.freeze(
    [...after.candidate.healthyReplicas]),authorized:false}));
}
