import {createHash,createPublicKey,verify as edVerify} from 'node:crypto';
import {verifyEmergencyQuarantineJournal} from './cas-emergency-quarantine.mjs';
import {keyQuorumPolicyDigest} from './cas-key-quorum.mjs';

/** NEO-047: evidence-only, fully reverified emergency responsibility succession. */
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 (Object.getPrototypeOf(x)===Object.prototype||Object.getPrototypeOf(x)===null);
const exact=(x,fields)=>plain(x)&&Object.keys(x).sort().join(',')===[...fields].sort().join(',');
const id=x=>typeof x==='string'&&/^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const hex=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const sig=x=>typeof x==='string'&&/^[A-Za-z0-9+/]{86}==$/.test(x)&&
 Buffer.from(x,'base64').toString('base64')===x;
const pos=x=>exact(x,['count','head'])&&Number.isSafeInteger(x.count)&&
 x.count>=0&&x.count<=64&&hex(x.head);
const sha=x=>createHash('sha256').update(JSON.stringify(x)).digest('hex');
const deny=reason=>Object.freeze({ok:false,phase:'HOLD',reason,authorized:false,candidate:null});
const genesis=Object.freeze({count:0,head:'0'.repeat(64)});
const bodyKeys=['schema','namespace','sequence','previousHash','handoffId',
 'incidentId','quarantineEntryHash','quarantinePosition','originalCustodianId',
 'originalKeyFingerprint','successorCustodianId','successorKeyFingerprint',
 'lifecycleDigest','policyDigest','action'];
const entryKeys=['body','reviews','successorAcceptance','hash'];
function key(pem){
 try{
  if(typeof pem!=='string'||!pem.length||pem.length>8192)return null;
  const k=createPublicKey(pem);return k.asymmetricKeyType==='ed25519'?k:null;
 }catch{return null;}
}
const fp=k=>createHash('sha256').update(k.export({type:'spki',format:'der'})).digest('hex');
function valid(b){
 return exact(b,bodyKeys)&&b.schema==='NEO-047-RESPONSIBILITY-HANDOFF-v1'&&
 id(b.namespace)&&Number.isSafeInteger(b.sequence)&&
 b.sequence>=1&&b.sequence<=64&&hex(b.previousHash)&&
 id(b.handoffId)&&id(b.incidentId)&&hex(b.quarantineEntryHash)&&
 pos(b.quarantinePosition)&&b.quarantinePosition.count>=1&&
 id(b.originalCustodianId)&&hex(b.originalKeyFingerprint)&&
 id(b.successorCustodianId)&&hex(b.successorKeyFingerprint)&&
 b.originalCustodianId!==b.successorCustodianId&&
 hex(b.lifecycleDigest)&&hex(b.policyDigest)&&
 b.action==='REVIEWED_RESPONSIBILITY_HANDOFF_HOLD';
}
export function responsibilityHandoffPayload(body,signerId,role){
 if(!valid(body)||!id(signerId)||!['OWNER','SECURITY','SUCCESSOR'].includes(role))
  throw new TypeError('INVALID_RESPONSIBILITY_HANDOFF_PAYLOAD');
 return Buffer.from(JSON.stringify([
  'PALACO-NEO-RESPONSIBILITY-HANDOFF-v1',
  body.namespace,body.sequence,body.previousHash,body.handoffId,
  body.incidentId,body.quarantineEntryHash,
  body.quarantinePosition.count,body.quarantinePosition.head,
  body.originalCustodianId,body.originalKeyFingerprint,
  body.successorCustodianId,body.successorKeyFingerprint,
  body.lifecycleDigest,body.policyDigest,body.action,signerId,role
 ]),'utf8');
}
export function responsibilityHandoffEntryHash(body,reviews,successorAcceptance){
 responsibilityHandoffPayload(body,'entry-hash','OWNER');
 if(!Array.isArray(reviews)||reviews.length!==2||
    reviews.some(x=>!exact(x,['reviewerId','signature'])||
      !id(x.reviewerId)||!sig(x.signature))||
    reviews[0].reviewerId===reviews[1].reviewerId||
    !sig(successorAcceptance))
  throw new TypeError('INVALID_HANDOFF_ENTRY');
 return sha(['PALACO-NEO-RESPONSIBILITY-HANDOFF-ENTRY-v1',
  responsibilityHandoffPayload(body,'entry-hash','OWNER').toString('base64'),
  [...reviews].sort((a,b)=>a.reviewerId<b.reviewerId?-1:1)
   .map(r=>[r.reviewerId,r.signature]),successorAcceptance]);
}
/**
 * Reverify ALL original NEO-046 evidence, then require an ordered one-to-one
 * signed handoff for each quarantine. A successor's acknowledgment is a
 * responsibility claim, NEVER a credential or authorization to access.
 */
export function verifyEmergencyResponsibilityHandoffs(
 history,rotations,historyFloor,lifecyclePin,quarantines,
 policy,policyPin,trustedQuarantineFloor,handoffs,trustedHandoffFloor
){
 if(!Array.isArray(handoffs)||handoffs.length>64||!pos(trustedHandoffFloor)||
    !Array.isArray(quarantines)||quarantines.length!==handoffs.length)
  return deny('INCOMPLETE_OR_INVALID_HANDOFF_INPUT');
 const emergency=verifyEmergencyQuarantineJournal(history,rotations,historyFloor,
  lifecyclePin,quarantines,policy,policyPin,trustedQuarantineFloor);
 if(!emergency.ok)return deny('QUARANTINE_'+emergency.reason);
 let policyDigest;
 try{policyDigest=keyQuorumPolicyDigest(policy);}
 catch{return deny('INVALID_HANDOFF_POLICY');}
 if(!exact(policyPin,['version','digest'])||
    policyPin.version!==policy.version||policyPin.digest!==policyDigest)
  return deny('UNTRUSTED_HANDOFF_POLICY_PIN');
 const roster=new Map(policy.reviewers.map(r=>[r.reviewerId,r]));
 const usedHandoffs=new Set(),usedIncidents=new Set(),usedSuccessors=new Set();
 const accepted=[];let last=genesis.head;
 for(let i=0;i<handoffs.length;i++){
  const entry=handoffs[i],body=entry?.body,quarantine=quarantines[i];
  if(!exact(entry,entryKeys)||!valid(body)||!hex(entry.hash)||
     !Array.isArray(entry.reviews)||entry.reviews.length!==2||
     body.sequence!==i+1||body.previousHash!==last)
   return deny('BROKEN_HANDOFF_CHAIN');
  const proposal=emergency.candidate.nominations[i],qb=quarantine.body;
  if(body.namespace!==policy.namespace||body.policyDigest!==policyDigest||
     body.lifecycleDigest!==emergency.candidate.lifecycleDigest||
     body.incidentId!==proposal.incidentId||
     body.quarantineEntryHash!==quarantine.hash||
     body.quarantinePosition.count!==i+1||
     body.quarantinePosition.head!==quarantine.hash||
     body.originalCustodianId!==proposal.custodianId||
     body.originalKeyFingerprint!==proposal.activeKeyFingerprint||
     body.successorCustodianId!==proposal.successorCustodianId||
     body.successorKeyFingerprint!==proposal.successorKeyFingerprint||
     qb.successorCustodianId!==body.successorCustodianId)
   return deny('HANDOFF_CONTEXT_OR_QUARANTINE_CONFLICT');
  if(usedHandoffs.has(body.handoffId)||usedIncidents.has(body.incidentId)||
     usedSuccessors.has(body.successorKeyFingerprint))
   return deny('HANDOFF_REPLAY_OR_SUCCESSOR_REUSE');
  const successorKey=key(qb.successorPublicKeyPem);
  if(!successorKey||fp(successorKey)!==body.successorKeyFingerprint||
     !sig(entry.successorAcceptance)||!edVerify(null,
      responsibilityHandoffPayload(body,body.successorCustodianId,'SUCCESSOR'),
      successorKey,Buffer.from(entry.successorAcceptance,'base64')))
   return deny('INVALID_RESPONSIBILITY_ACCEPTANCE');
  const reviewerIds=new Set(),roles=new Set(),keys=new Set();
  for(const r of entry.reviews){
   if(!exact(r,['reviewerId','signature'])||!id(r.reviewerId)||
      !sig(r.signature)||reviewerIds.has(r.reviewerId))
    return deny('INVALID_OR_DUPLICATE_HANDOFF_REVIEWER');
   const reviewer=roster.get(r.reviewerId);
   const publicKey=reviewer?key(reviewer.publicKeyPem):null;
   if(!publicKey||reviewer.status!=='ACTIVE'||roles.has(reviewer.role)||
      fp(publicKey)===body.successorKeyFingerprint||
      keys.has(fp(publicKey)))
    return deny('REVOKED_OR_NONINDEPENDENT_REVIEWER');
   if(!edVerify(null,responsibilityHandoffPayload(
      body,r.reviewerId,reviewer.role),publicKey,Buffer.from(r.signature,'base64')))
    return deny('INVALID_HANDOFF_REVIEW_SIGNATURE');
   reviewerIds.add(r.reviewerId);roles.add(reviewer.role);keys.add(fp(publicKey));
  }
  if(!roles.has('OWNER')||!roles.has('SECURITY'))
   return deny('MISSING_OWNER_SECURITY_HANDOFF');
  if(responsibilityHandoffEntryHash(body,entry.reviews,entry.successorAcceptance)!==
      entry.hash)
   return deny('TAMPERED_HANDOFF_ENTRY');
  last=entry.hash;usedHandoffs.add(body.handoffId);
  usedIncidents.add(body.incidentId);
  usedSuccessors.add(body.successorKeyFingerprint);
  accepted.push(Object.freeze({handoffId:body.handoffId,
   incidentId:body.incidentId,successorCustodianId:body.successorCustodianId,
   status:'RESPONSIBILITY_CLAIM_REVIEWED_HOLD'}));
 }
 if(handoffs.length<trustedHandoffFloor.count)return deny('HANDOFF_ROLLBACK');
 const trustedHead=trustedHandoffFloor.count===0?genesis.head:
  handoffs[trustedHandoffFloor.count-1].hash;
 if(trustedHead!==trustedHandoffFloor.head)return deny('HANDOFF_FORK');
 return Object.freeze({ok:true,phase:'RESPONSIBILITY_HANDOFF_EVIDENCE_HOLD',
  reason:'VERIFIED_SUCCESSOR_CLAIMS_NO_EXECUTION_AUTHORITY',
  authorized:false,candidate:Object.freeze({
   position:Object.freeze({count:handoffs.length,head:last}),
   quarantinePosition:emergency.candidate.position,
   handoffs:Object.freeze(accepted)})});
}
export const INITIAL_RESPONSIBILITY_HANDOFF_POSITION=genesis;
