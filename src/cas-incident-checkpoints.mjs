import {createHash,createPublicKey,verify as edVerify} from 'node:crypto';
import {verifyReceiptIncidentJournal} from './cas-receipt-incident-journal.mjs';

/** NEO-055. Read-only signed checkpoints of full NEO-054 incident histories. */
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 (Object.getPrototypeOf(x)===Object.prototype||Object.getPrototypeOf(x)===null);
const exact=(x,k)=>plain(x)&&Object.keys(x).sort().join(',')===[...k].sort().join(',');
const ident=x=>typeof x==='string'&&/^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const hex=x=>typeof x==='string'&&/^[0-9a-f]{64}$/.test(x);
const signature=x=>typeof x==='string'&&/^[A-Za-z0-9+/]{86}==$/.test(x)&&
 Buffer.from(x,'base64').toString('base64')===x;
const position=x=>exact(x,['count','head'])&&Number.isSafeInteger(x.count)&&x.count>=0&&x.count<=64&&hex(x.head);
const sha=x=>createHash('sha256').update(JSON.stringify(x)).digest('hex');
const deny=reason=>Object.freeze({ok:false,phase:'HOLD',reason,authorized:false,candidate:null});
const ok=(phase,reason,candidate)=>Object.freeze({ok:true,phase,reason,authorized:false,candidate});
const initial=Object.freeze({count:0,head:'0'.repeat(64)});
const bodyKeys=['schema','namespace','checkpointId','sequence','previousHash','incidentPosition'];
const sigKeys=['custodianId','signature'];
const trustKeys=['namespace','custodianId','publicKeyPem','status','expectedCheckpointId'];
const recordKeys=['source','seal','custodianTrust','expectedCustodianIds'];
const sourceKeys=['entries','evidence','policy','policyPin','trustedIncidentFloor'];
const sealKeys=['body','attestations','hash'];
function key(pem){
 try{
  if(typeof pem!=='string'||!pem.length||pem.length>8192)return null;
  const k=createPublicKey(pem);return k.asymmetricKeyType==='ed25519'?k:null;
 }catch{return null;}
}
const fp=k=>k.export({type:'spki',format:'der'}).toString('base64');
const bodyValid=b=>exact(b,bodyKeys)&&
 b.schema==='NEO-055-INCIDENT-CHECKPOINT-v1'&&ident(b.namespace)&&
 ident(b.checkpointId)&&Number.isSafeInteger(b.sequence)&&
 b.sequence>=1&&b.sequence<=64&&hex(b.previousHash)&&
 position(b.incidentPosition)&&b.incidentPosition.count>=1;
export function incidentCheckpointPayload(body,custodianId){
 if(!bodyValid(body)||!ident(custodianId))
  throw new TypeError('INVALID_INCIDENT_CHECKPOINT_PAYLOAD');
 return Buffer.from(JSON.stringify(['PALACO-NEO-055-INCIDENT-CHECKPOINT-v1',
  body.namespace,body.checkpointId,body.sequence,body.previousHash,
  body.incidentPosition.count,body.incidentPosition.head,custodianId]),'utf8');
}
export function incidentCheckpointHash(body,attestations){
 incidentCheckpointPayload(body,'entry-hash');
 if(!Array.isArray(attestations)||attestations.length<2||attestations.length>16||
    attestations.some(a=>!exact(a,sigKeys)||!ident(a.custodianId)||
      !signature(a.signature))||
    new Set(attestations.map(a=>a.custodianId)).size!==attestations.length)
  throw new TypeError('INVALID_INCIDENT_CHECKPOINT_ATTESTATIONS');
 return sha(['PALACO-NEO-055-INCIDENT-CHECKPOINT-ENTRY-v1',
  incidentCheckpointPayload(body,'entry-hash').toString('base64'),
  [...attestations].sort((a,b)=>a.custodianId<b.custodianId?-1:1)
   .map(a=>[a.custodianId,a.signature])]);
}
/** Validates every original incident and the complete prior incident prefix.
 * Externally trusted floors and public-key roots must be authenticated.
 */
export function verifyIncidentCheckpointHistory(records,trustedCheckpointFloor){
 if(!Array.isArray(records)||records.length>64||!position(trustedCheckpointFloor))
  return deny('INVALID_INCIDENT_CHECKPOINT_INPUT');
 if(records.length<trustedCheckpointFloor.count)
  return deny('INCIDENT_CHECKPOINT_ROLLBACK');
 let head=initial.head,namespace=null,priorPosition=initial,priorIncidents=[];
 const checkpointIds=new Set(),custodianKeys=new Map(),usedKeys=new Map(),out=[];
 for(let i=0;i<records.length;i++){
  const record=records[i];
  if(!exact(record,recordKeys)||!exact(record?.source,sourceKeys)||
     !exact(record?.seal,sealKeys)||!bodyValid(record.seal.body)||
     !hex(record.seal.hash)||!Array.isArray(record.seal.attestations)||
     !Array.isArray(record.custodianTrust)||!Array.isArray(record.expectedCustodianIds))
   return deny('INVALID_CHECKPOINT_ENTRY');
  const b=record.seal.body,s=record.source;
  if(b.sequence!==i+1||b.previousHash!==head)
   return deny('BROKEN_INCIDENT_CHECKPOINT_CHAIN');
  if(checkpointIds.has(b.checkpointId))return deny('REPLAYED_INCIDENT_CHECKPOINT_ID');
  if(namespace!==null&&namespace!==b.namespace)return deny('CHECKPOINT_NAMESPACE_CHANGED');
  const verified=verifyReceiptIncidentJournal(s.entries,s.evidence,s.policy,
   s.policyPin,s.trustedIncidentFloor);
  if(!verified.ok)return deny('INCIDENT_'+verified.reason);
  const positionNow=verified.candidate.position;
  if(s.policy.namespace!==b.namespace||
     positionNow.count!==b.incidentPosition.count||
     positionNow.head!==b.incidentPosition.head)
   return deny('INCIDENT_CHECKPOINT_CONTEXT_CONFLICT');
  if(positionNow.count<priorPosition.count)
   return deny('INCIDENT_HISTORY_ROLLBACK');
  for(let j=0;j<priorIncidents.length;j++){
   if(s.entries[j]?.hash!==priorIncidents[j].hash||
      s.entries[j]?.body?.incidentId!==priorIncidents[j].id||
      s.entries[j]?.body?.equivocationDigest!==priorIncidents[j].digest)
    return deny('INCIDENT_HISTORY_PREFIX_REWRITTEN');
  }
  const expected=record.expectedCustodianIds;
  if(expected.length<2||expected.length>16||
     expected.length!==record.custodianTrust.length||
     expected.length!==record.seal.attestations.length||
     expected.some(x=>!ident(x))||new Set(expected).size!==expected.length)
   return deny('INVALID_INCIDENT_CUSTODIAN_ROSTER');
  const excluded=new Set();
  for(const r of s.policy.reviewers){
   const k=key(r.publicKeyPem);
   if(!k)return deny('INVALID_POLICY_REVIEWER_KEY');
   excluded.add(fp(k));
  }
  for(const e of s.evidence){
   const k=key(e?.trust?.publicKeyPem);
   if(!k)return deny('INVALID_DISPUTED_CUSTODIAN_KEY');
   excluded.add(fp(k));
   for(const original of e.canonicalHistory){
    for(const t of original.custodianTrust){
     const tk=key(t.publicKeyPem);
     if(!tk)return deny('INVALID_ORIGINAL_CHECKPOINT_KEY');
     excluded.add(fp(tk));
    }
   }
  }
  const roster=new Map(),currentKeys=new Set();
  for(const t of record.custodianTrust){
   if(!exact(t,trustKeys)||!expected.includes(t.custodianId)||
      roster.has(t.custodianId)||t.namespace!==b.namespace||
      t.expectedCheckpointId!==b.checkpointId||t.status!=='ACTIVE')
    return deny('INVALID_OR_REVOKED_INCIDENT_CUSTODIAN');
   const k=key(t.publicKeyPem);
   if(!k)return deny('INVALID_INCIDENT_CUSTODIAN_KEY');
   const fingerprint=fp(k);
   if(currentKeys.has(fingerprint)||excluded.has(fingerprint))
    return deny('NONINDEPENDENT_INCIDENT_CUSTODIAN');
   if(custodianKeys.has(t.custodianId)&&
      custodianKeys.get(t.custodianId)!==fingerprint)
    return deny('INCIDENT_CUSTODIAN_KEY_CHANGED');
   if(usedKeys.has(fingerprint)&&usedKeys.get(fingerprint)!==t.custodianId)
    return deny('INCIDENT_CUSTODIAN_KEY_REASSIGNED');
   currentKeys.add(fingerprint);roster.set(t.custodianId,k);
  }
  const signed=new Set();
  for(const att of record.seal.attestations){
   if(!exact(att,sigKeys)||!ident(att.custodianId)||
      !signature(att.signature)||!roster.has(att.custodianId)||
      signed.has(att.custodianId))
    return deny('DUPLICATE_OR_INVALID_INCIDENT_ATTESTATION');
   const k=roster.get(att.custodianId);
   if(!edVerify(null,incidentCheckpointPayload(b,att.custodianId),
     k,Buffer.from(att.signature,'base64')))
    return deny('FORGED_INCIDENT_CHECKPOINT_ATTESTATION');
   signed.add(att.custodianId);
  }
  if(signed.size!==roster.size)return deny('MISSING_INCIDENT_ATTESTATION');
  if(incidentCheckpointHash(b,record.seal.attestations)!==record.seal.hash)
   return deny('TAMPERED_INCIDENT_CHECKPOINT_HASH');
  for(const t of record.custodianTrust){
   const fingerprint=fp(roster.get(t.custodianId));
   custodianKeys.set(t.custodianId,fingerprint);
   usedKeys.set(fingerprint,t.custodianId);
  }
  namespace=b.namespace;head=record.seal.hash;checkpointIds.add(b.checkpointId);
  priorPosition=positionNow;
  priorIncidents=s.entries.map(x=>({
   hash:x.hash,id:x.body.incidentId,digest:x.body.equivocationDigest
  }));
  out.push(Object.freeze({sequence:i+1,checkpointId:b.checkpointId,head,
   incidentPosition:positionNow}));
 }
 const floorHead=trustedCheckpointFloor.count===0?initial.head:
  out[trustedCheckpointFloor.count-1].head;
 if(floorHead!==trustedCheckpointFloor.head)
  return deny('TRUSTED_INCIDENT_CHECKPOINT_FORK');
 return ok('INCIDENT_CHECKPOINT_HISTORY_VERIFIED_HOLD',
  'SIGNED_INCIDENT_CHECKPOINTS_NO_EXECUTION_AUTHORITY',
  Object.freeze({position:Object.freeze({count:records.length,head}),
   checkpoints:Object.freeze(out)}));
}
/** Contradictory Ed25519 claims from one trusted key, one exact checkpoint.
 * This proves signed inconsistency, not the true external incident history.
 */
export function inspectIncidentCheckpointConflict(left,right,trust,predecessor){
 if(!exact(left,['body','attestation'])||!exact(right,['body','attestation'])||
    !bodyValid(left.body)||!bodyValid(right.body)||
    !exact(trust,trustKeys)||!position(predecessor))
  return deny('INVALID_INCIDENT_CONFLICT_INPUT');
 const a=left.body,b=right.body;
 if(a.namespace!==b.namespace||a.checkpointId!==b.checkpointId||
    a.sequence!==b.sequence||a.previousHash!==b.previousHash||
    a.sequence!==predecessor.count+1||a.previousHash!==predecessor.head||
    trust.namespace!==a.namespace||trust.status!=='ACTIVE'||
    trust.expectedCheckpointId!==a.checkpointId)
  return deny('UNRELATED_INCIDENT_CHECKPOINT_CLAIMS');
 const k=key(trust.publicKeyPem);
 if(!k)return deny('INVALID_INCIDENT_CONFLICT_TRUST_KEY');
 for(const claim of [left,right]){
  if(!exact(claim.attestation,sigKeys)||
     claim.attestation.custodianId!==trust.custodianId||
     !signature(claim.attestation.signature)||
     !edVerify(null,incidentCheckpointPayload(claim.body,trust.custodianId),
       k,Buffer.from(claim.attestation.signature,'base64')))
   return deny('UNVERIFIED_INCIDENT_CHECKPOINT_CLAIM');
 }
 if(a.incidentPosition.count===b.incidentPosition.count&&
    a.incidentPosition.head===b.incidentPosition.head)
  return ok('NO_PROVEN_CONFLICT','MATCHING_SIGNED_INCIDENT_STATE',null);
 const states=[a.incidentPosition,b.incidentPosition].map(p=>[p.count,p.head])
  .sort((x,y)=>x[0]-y[0]||(x[1]<y[1]?-1:x[1]>y[1]?1:0));
 return ok('INCIDENT_CHECKPOINT_CONFLICT_HOLD',
  'TWO_CONTRADICTORY_SIGNED_INCIDENT_STATES',
  Object.freeze({checkpointId:a.checkpointId,custodianId:trust.custodianId,
   sequence:a.sequence,states:Object.freeze(states),
   evidenceDigest:sha(['PALACO-NEO-055-INCIDENT-CHECKPOINT-CONFLICT-v1',
    a.namespace,a.checkpointId,a.sequence,a.previousHash,
    trust.custodianId,fp(k),states])}));
}
export const INITIAL_INCIDENT_CHECKPOINT_POSITION=initial;
