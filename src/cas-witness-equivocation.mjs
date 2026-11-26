import {createHash,createPublicKey,verify as edVerify} from 'node:crypto';
import {policyCheckpointPayload} from './cas-policy-activation-ledger.mjs';

/**
 * NEO-032: independent signed-witness equivocation evidence, read-only.
 * Detect two DIFFERENT authenticated claims for the SAME witness/count.
 * Does not infer physical independence, punish signers or execute escalation.
 */
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 (Object.getPrototypeOf(x)===Object.prototype||Object.getPrototypeOf(x)===null);
const exact=(x,keys)=>plain(x)&&Object.keys(x).sort().join(',')===[...keys].sort().join(',');
const id=x=>typeof x==='string'&&/^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const hex=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const position=x=>exact(x,['count','head'])&&Number.isSafeInteger(x.count)&&
 x.count>=0&&x.count<=256&&hex(x.head);
const bad=reason=>Object.freeze({ok:false,reason,authorized:false,dossier:null});
const status=(phase,reason,dossier=null)=>Object.freeze({phase,reason,authorized:false,dossier});
const sealShape=x=>exact(x,['checkpoint','witnessId','signature'])&&id(x.witnessId)&&
 typeof x.signature==='string'&&/^[A-Za-z0-9+/]{86}==$/.test(x.signature);
const claim=x=>JSON.stringify([
 x.namespace,x.count,x.head,x.activePolicy.version,x.activePolicy.digest
]);
const raw=x=>Buffer.from(x,'base64');
function checkSignature(seal,key,namespace,floor){
 if(!sealShape(seal)||seal.checkpoint?.namespace!==namespace)return false;
 let payload;
 try{payload=policyCheckpointPayload(seal.checkpoint,seal.witnessId);}
 catch{return false;}
 const cp=seal.checkpoint;
 if(cp.count<floor.count)return false;
 if(cp.count===floor.count&&cp.head!==floor.head)return false;
 const signature=raw(seal.signature);
 return signature.length===64&&signature.toString('base64')===seal.signature&&
  edVerify(null,payload,key,signature);
}
function canonicalPair(first,second){
 return [first,second].sort((a,b)=>{
  const aa=claim(a.checkpoint),bb=claim(b.checkpoint);
  return aa<bb?-1:aa>bb?1:
    a.signature<b.signature?-1:a.signature>b.signature?1:0;
 });
}
function digestPair(pair,witnessId){
 return createHash('sha256').update(JSON.stringify([
  'PALACO-NEO-WITNESS-EQUIVOCATION-DOSSIER-v1',witnessId,
  pair.map(s=>[claim(s.checkpoint),s.signature])
 ])).digest('hex');
}
/**
 * External trust is a pinned key + separately retained checkpoint floor.
 * A floor above one of the signed claims invalidates it; keep historical
 * floor snapshots separately when investigating older signatures.
 */
export function inspectWitnessEquivocation(first,second,trust){
 if(!exact(trust,['namespace','witnessId','publicKeyPem','status','trustedCheckpointFloor'])||
    !id(trust.namespace)||!id(trust.witnessId)||
    typeof trust.publicKeyPem!=='string'||trust.publicKeyPem.length>8192||
    !['ACTIVE','REVOKED'].includes(trust.status)||
    !position(trust.trustedCheckpointFloor))
  return bad('INVALID_PINNED_WITNESS_TRUST');
 if(trust.status!=='ACTIVE')return bad('REVOKED_WITNESS_NOT_ACCEPTED');
 if(!sealShape(first)||!sealShape(second)||
    first.witnessId!==trust.witnessId||second.witnessId!==trust.witnessId)
  return bad('WITNESS_ID_MISMATCH');
 let key;
 try{key=createPublicKey(trust.publicKeyPem);}
 catch{return bad('INVALID_WITNESS_PUBLIC_KEY');}
 if(key.asymmetricKeyType!=='ed25519')return bad('INVALID_WITNESS_PUBLIC_KEY');
 if(!checkSignature(first,key,trust.namespace,trust.trustedCheckpointFloor)||
    !checkSignature(second,key,trust.namespace,trust.trustedCheckpointFloor))
  return bad('UNVERIFIED_SIGNED_CLAIM');
 const a=first.checkpoint,b=second.checkpoint;
 if(a.count!==b.count)
  return Object.freeze({ok:true,reason:'DIFFERENT_COUNTS_NO_EQUIVOCATION_PROOF',
   authorized:false,dossier:null});
 if(claim(a)===claim(b))
  return Object.freeze({ok:true,reason:'IDENTICAL_SIGNED_CLAIMS',
   authorized:false,dossier:null});
 const pair=canonicalPair(first,second);
 const dossier=Object.freeze({
  schema:'NEO-032-EQUIVOCATION-v1',namespace:trust.namespace,
  witnessId:trust.witnessId,count:a.count,
  first:structuredClone(pair[0]),second:structuredClone(pair[1]),
  digest:digestPair(pair,trust.witnessId)
 });
 return Object.freeze({ok:true,reason:'SIGNED_EQUIVOCATION_EVIDENCE',
  authorized:false,dossier});
}
/** Independently recheck the COMPLETE original signed evidence, never only
 * an untrusted digest or caller-provided verdict.
 */
export function verifyWitnessEquivocationDossier(dossier,trust){
 if(!exact(dossier,['schema','namespace','witnessId','count','first','second','digest'])||
    dossier.schema!=='NEO-032-EQUIVOCATION-v1'||!id(dossier.namespace)||
    !id(dossier.witnessId)||!hex(dossier.digest)||
    !Number.isSafeInteger(dossier.count)||dossier.count<0)
  return status('HOLD','INVALID_DOSSIER');
 const result=inspectWitnessEquivocation(dossier.first,dossier.second,trust);
 if(!result.ok||result.dossier===null)return status('HOLD','UNVERIFIED_EQUIVOCATION_DOSSIER');
 if(result.dossier.namespace!==dossier.namespace||
    result.dossier.witnessId!==dossier.witnessId||
    result.dossier.count!==dossier.count||
    result.dossier.digest!==dossier.digest)
  return status('HOLD','DOSSIER_INTEGRITY_CONFLICT');
 return status('ESCALATE_HOLD','TWO_CONFLICTING_SIGNED_CLAIMS',
  result.dossier);
}
/** Escalation is an audit recommendation only; no quarantine, revocation,
 * notifications or governance actions are carried out here.
 */
export function classifyWitnessEscalation(dossier,trust,reviewEvidence){
 const verified=verifyWitnessEquivocationDossier(dossier,trust);
 if(verified.phase!=='ESCALATE_HOLD')return status('HOLD','INSUFFICIENT_CONFLICT_EVIDENCE');
 if(!exact(reviewEvidence,['caseId','ownerReviewed','securityReviewed'])||
    !id(reviewEvidence.caseId)||typeof reviewEvidence.ownerReviewed!=='boolean'||
    typeof reviewEvidence.securityReviewed!=='boolean')
  return status('ESCALATE_HOLD','HUMAN_REVIEW_REQUIRED');
 if(!reviewEvidence.ownerReviewed||!reviewEvidence.securityReviewed)
  return status('ESCALATE_HOLD','HUMAN_REVIEW_REQUIRED');
 // These booleans are NOT signed attestations; they do not release HOLD.
 return status('ESCALATE_HOLD','UNAUTHENTICATED_REVIEW_CLAIM_NO_RELEASE');
}
