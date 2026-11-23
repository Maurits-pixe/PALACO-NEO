import {createHash,createPublicKey,verify as edVerify} from 'node:crypto';
import {verifyRecoveryEvidence} from './cas-repair-review.mjs';

/** NEO-038: witness-signed, verification-only repair checkpoint. */
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 (Object.getPrototypeOf(x)===Object.prototype||Object.getPrototypeOf(x)===null);
const exact=(x,fields)=>obj(x)&&Object.keys(x).sort().join(',')===[...fields].sort().join(',');
const id=x=>typeof x==='string'&&/^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const hex=x=>typeof x==='string'&&/^[0-9a-f]{64}$/.test(x);
const pos=x=>exact(x,['count','head'])&&Number.isSafeInteger(x.count)&&
 x.count>=0&&x.count<=256&&hex(x.head);
const sig=x=>typeof x==='string'&&/^[A-Za-z0-9+/]{86}==$/.test(x)&&
 Buffer.from(x,'base64').toString('base64')===x;
const hash=x=>createHash('sha256').update(JSON.stringify(x)).digest('hex');
const deny=reason=>Object.freeze({ok:false,phase:'HOLD',reason,authorized:false,candidate:null});
const positionKeys=['count','head'];
const bodyKeys=['schema','namespace','checkpointId','recoveryId','proposalDigest',
 'inventoryDigest','lineagePosition','priorCheckpoint','postEvidenceDigest'];
const sealKeys=['body','witnesses','hash'];
const trustKeys=['namespace','witnessId','publicKeyPem','status','expectedCheckpointId'];
function pub(pem){
 try{
  if(typeof pem!=='string'||pem.length>8192||pem.length===0)return null;
  const key=createPublicKey(pem);
  return key.asymmetricKeyType==='ed25519'?key:null;
 }catch{return null;}
}
function validBody(b){
 return exact(b,bodyKeys)&&b.schema==='NEO-038-REPAIR-CHECKPOINT-v1'&&
 id(b.namespace)&&id(b.checkpointId)&&id(b.recoveryId)&&
 hex(b.proposalDigest)&&hex(b.inventoryDigest)&&
 exact(b.lineagePosition,positionKeys)&&pos(b.lineagePosition)&&
 b.lineagePosition.count>=1&&pos(b.priorCheckpoint)&&
 b.priorCheckpoint.count<256&&hex(b.postEvidenceDigest);
}
export function repairCheckpointPayload(body,witnessId){
 if(!validBody(body)||!id(witnessId))throw new TypeError('INVALID_REPAIR_CHECKPOINT');
 return Buffer.from(JSON.stringify(['PALACO-NEO-REPAIR-CHECKPOINT-v1',
  body.namespace,body.checkpointId,body.recoveryId,body.proposalDigest,
  body.inventoryDigest,body.lineagePosition.count,body.lineagePosition.head,
  body.priorCheckpoint.count,body.priorCheckpoint.head,body.postEvidenceDigest,
  witnessId]),'utf8');
}
export function repairCheckpointHash(body,witnesses){
 repairCheckpointPayload(body,'valid-witness');
 if(!Array.isArray(witnesses)||witnesses.length<2||witnesses.length>16||
   witnesses.some(w=>!exact(w,['witnessId','signature'])||
     !id(w.witnessId)||!sig(w.signature))||
   new Set(witnesses.map(w=>w.witnessId)).size!==witnesses.length)
  throw new TypeError('INVALID_REPAIR_WITNESSES');
 return hash(['PALACO-NEO-REPAIR-CHECKPOINT-ENTRY-v1',
  repairCheckpointPayload(body,'checkpoint-entry').toString('base64'),
  [...witnesses].sort((a,b)=>a.witnessId<b.witnessId?-1:1)
    .map(w=>[w.witnessId,w.signature])]);
}
/**
 * A compact digest of exact, separately verified post-state statements.
 * It binds all reviewer signatures and per-replica signed observations.
 * It is evidence identity, not a guarantee of freshness or durable storage.
 */
export function recoveryPostEvidenceDigest(approval,post){
 if(!obj(approval)||!obj(approval.body)||!Array.isArray(approval.reviews)||
    approval.reviews.length!==2||!obj(post)||!Array.isArray(post.replicas)||
    post.replicas.length<2||post.replicas.length>16)return null;
 const rr=approval.reviews;
 if(rr.some(x=>!exact(x,['reviewerId','signature'])||!id(x.reviewerId)||!sig(x.signature)))
  return null;
 const rows=[];
 for(const r of post.replicas){
  if(!obj(r)||!obj(r.body)||!id(r.body.replicaId)||!id(r.body.observationId)||
      !sig(r.signature)||!Array.isArray(r.artifacts)||r.artifacts.length>64)
   return null;
  const bytes=[];
  for(const a of r.artifacts){
   if(!exact(a,['artifactId','base64'])||!id(a.artifactId)||
       typeof a.base64!=='string'||a.base64.length>1398112)
    return null;
   bytes.push([a.artifactId,createHash('sha256').update(a.base64).digest('hex')]);
  }
  rows.push([r.body.replicaId,r.body.observationId,r.status,r.signature,
   bytes.sort((a,b)=>a[0]<b[0]?-1:1)]);
 }
 return hash(['PALACO-NEO-POST-REPAIR-EVIDENCE-v1',
  approval.body.namespace,approval.body.recoveryId,
  [...rr].sort((a,b)=>a.reviewerId<b.reviewerId?-1:1)
    .map(x=>[x.reviewerId,x.signature]),
  rows.sort((a,b)=>a[0]<b[0]?-1:1)]);
}
/**
 * Re-perform NEO-037 verification against original bytes, reviewer signatures,
 * replica signatures, inventory pin, and prior observations. Independently
 * pinned checkpoint before-position and witness registry MUST come from
 * external custody. No key custody, storage mutation or publication occurs.
 */
export function verifyRepairCheckpoint(manifest,inventoryPin,lineagePosition,
 pre,post,policy,policyPin,approval,expectedNamespace,
 seal,witnessTrust,expectedWitnessIds,trustedBefore,expectedAfter=null){
 if(!pos(trustedBefore)||!Array.isArray(expectedWitnessIds)||
    expectedWitnessIds.length<2||expectedWitnessIds.length>16||
    expectedWitnessIds.some(x=>!id(x))||
    new Set(expectedWitnessIds).size!==expectedWitnessIds.length||
    !Array.isArray(witnessTrust)||witnessTrust.length!==expectedWitnessIds.length||
    !exact(seal,sealKeys)||!validBody(seal.body)||
    !Array.isArray(seal.witnesses)||seal.witnesses.length!==expectedWitnessIds.length||
    !hex(seal.hash)||expectedAfter!==null&&!pos(expectedAfter))
  return deny('INVALID_CHECKPOINT_INPUT');
 const verified=verifyRecoveryEvidence(manifest,inventoryPin,lineagePosition,
   pre,post,policy,policyPin,approval,expectedNamespace);
 if(!verified.ok)return deny('RECOVERY_'+verified.reason);
 const b=seal.body,c=verified.candidate;
 const postDigest=recoveryPostEvidenceDigest(approval,post);
 if(postDigest===null||b.namespace!==expectedNamespace||
    b.recoveryId!==c.recoveryId||b.proposalDigest!==c.proposalDigest||
    b.inventoryDigest!==c.inventoryDigest||
    b.lineagePosition.count!==lineagePosition.count||
    b.lineagePosition.head!==lineagePosition.head||
    b.postEvidenceDigest!==postDigest||
    b.priorCheckpoint.count!==trustedBefore.count||
    b.priorCheckpoint.head!==trustedBefore.head)
   return deny('UNTRUSTED_CHECKPOINT_CONTEXT');
 const known=new Set(),keys=new Set(),signatures=new Map();
 const prohibited=new Set();
 for(const r of [...policy.reviewers,...pre.trusts]){
  const key=pub(r.publicKeyPem);
  if(key)prohibited.add(key.export({type:'spki',format:'der'}).toString('base64'));
 }
 for(const t of witnessTrust){
  if(!exact(t,trustKeys)||!expectedWitnessIds.includes(t.witnessId)||
      t.namespace!==expectedNamespace||t.status!=='ACTIVE'||
      t.expectedCheckpointId!==b.checkpointId||known.has(t.witnessId))
   return deny('UNTRUSTED_CHECKPOINT_WITNESS');
  const key=pub(t.publicKeyPem);
  if(!key)return deny('INVALID_CHECKPOINT_WITNESS_KEY');
  const fp=key.export({type:'spki',format:'der'}).toString('base64');
  if(keys.has(fp)||prohibited.has(fp))
   return deny('SHARED_CHECKPOINT_WITNESS_KEY');
  known.add(t.witnessId);keys.add(fp);signatures.set(t.witnessId,key);
 }
 const signed=new Set();
 for(const w of seal.witnesses){
  if(!exact(w,['witnessId','signature'])||
      !expectedWitnessIds.includes(w.witnessId)||signed.has(w.witnessId)||
      !sig(w.signature))return deny('DUPLICATE_OR_MISSING_WITNESS');
  const key=signatures.get(w.witnessId);
  if(!key||!edVerify(null,repairCheckpointPayload(b,w.witnessId),
   key,Buffer.from(w.signature,'base64')))
   return deny('INVALID_WITNESS_SIGNATURE');
  signed.add(w.witnessId);
 }
 if(signed.size!==expectedWitnessIds.length)return deny('MISSING_WITNESS');
 let digest;
 try{digest=repairCheckpointHash(b,seal.witnesses);}
 catch{return deny('INVALID_CHECKPOINT_HASH');}
 if(digest!==seal.hash)return deny('TAMPERED_CHECKPOINT_HASH');
 const after=Object.freeze({count:trustedBefore.count+1,head:digest});
 if(expectedAfter!==null&&
    (expectedAfter.count!==after.count||expectedAfter.head!==after.head))
  return deny('CHECKPOINT_ROLLBACK_OR_FORK');
 return Object.freeze({ok:true,phase:'SIGNED_REPAIR_CHECKPOINT_NO_AUTHORITY',
   reason:'REPAIRED_BYTES_REVERIFIED_WITNESS_ASSERTIONS_ONLY',
   authorized:false,candidate:Object.freeze({
    position:after,recoveryId:c.recoveryId,inventoryDigest:c.inventoryDigest,
    witnessIds:Object.freeze([...signed].sort()),authorized:false
   })});
}
export const INITIAL_REPAIR_CHECKPOINT_POSITION=Object.freeze({
 count:0,head:'0'.repeat(64)});
