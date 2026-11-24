import {createHash,createPublicKey,verify as edVerify} from 'node:crypto';
import {verifyHandoffConflictJournal} from './cas-handoff-conflict-journal.mjs';
import {keyQuorumPolicyDigest} from './cas-key-quorum.mjs';

/** NEO-050 — independent signed checkpoints of NEO-049 conflict escalations.
 * All results are evidence only. No storage, resolution, or authority.
 */
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 (Object.getPrototypeOf(x)===Object.prototype||Object.getPrototypeOf(x)===null);
const exact=(x,keys)=>plain(x)&&Object.keys(x).sort().join(',')===[...keys].sort().join(',');
const ident=x=>typeof x==='string'&&/^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const hex=x=>typeof x==='string'&&/^[0-9a-f]{64}$/.test(x);
const sig=x=>typeof x==='string'&&/^[A-Za-z0-9+/]{86}==$/.test(x)&&
 Buffer.from(x,'base64').toString('base64')===x;
const position=x=>exact(x,['count','head'])&&Number.isSafeInteger(x.count)&&
 x.count>=0&&x.count<=64&&hex(x.head);
const genesis=Object.freeze({count:0,head:'0'.repeat(64)});
const bodyFields=['schema','namespace','checkpointId','sequence','previousHash',
 'escalationPosition','policyDigest'];
const witnessFields=['custodianId','signature'];
const trustFields=['namespace','custodianId','publicKeyPem','status','expectedCheckpointId'];
const entryFields=['source','seal','custodianTrust','expectedCustodianIds'];
const sealFields=['body','witnesses','hash'];
const sourceFields=['entries','evidence','policy','policyPin','trustedConflictFloor'];
const sha=x=>createHash('sha256').update(JSON.stringify(x)).digest('hex');
const fail=reason=>Object.freeze({ok:false,phase:'HOLD',reason,authorized:false,candidate:null});
const verified=(phase,reason,candidate)=>Object.freeze({ok:true,phase,reason,authorized:false,candidate});
function key(pem){
 try{
  if(typeof pem!=='string'||!pem.length||pem.length>8192)return null;
  const k=createPublicKey(pem);return k.asymmetricKeyType==='ed25519'?k:null;
 }catch{return null;}
}
const fingerprint=k=>k.export({type:'spki',format:'der'}).toString('base64');
const validBody=b=>exact(b,bodyFields)&&
 b.schema==='NEO-050-ESCALATION-CHECKPOINT-v1'&&ident(b.namespace)&&
 ident(b.checkpointId)&&Number.isSafeInteger(b.sequence)&&
 b.sequence>=1&&b.sequence<=64&&hex(b.previousHash)&&
 position(b.escalationPosition)&&hex(b.policyDigest);
export function escalationCheckpointPayload(body,custodianId){
 if(!validBody(body)||!ident(custodianId))
  throw new TypeError('INVALID_ESCALATION_CHECKPOINT');
 return Buffer.from(JSON.stringify(['PALACO-NEO-ESCALATION-CHECKPOINT-v1',
  body.namespace,body.checkpointId,body.sequence,body.previousHash,
  body.escalationPosition.count,body.escalationPosition.head,
  body.policyDigest,custodianId]),'utf8');
}
export function escalationCheckpointHash(body,witnesses){
 escalationCheckpointPayload(body,'entry-hash');
 if(!Array.isArray(witnesses)||witnesses.length<2||witnesses.length>16||
    witnesses.some(w=>!exact(w,witnessFields)||!ident(w.custodianId)||
      !sig(w.signature))||
    new Set(witnesses.map(w=>w.custodianId)).size!==witnesses.length)
  throw new TypeError('INVALID_ESCALATION_CHECKPOINT_WITNESSES');
 return sha(['PALACO-NEO-ESCALATION-CHECKPOINT-ENTRY-v1',
  escalationCheckpointPayload(body,'entry-hash').toString('base64'),
  [...witnesses].sort((a,b)=>a.custodianId<b.custodianId?-1:1)
   .map(w=>[w.custodianId,w.signature])]);
}
/** Replays the COMPLETE original NEO-049 escalation evidence at each entry.
 * A key appearing as an escalation reviewer or disputed witness cannot also
 * act as an independent audit custodian in the same checkpoint.
 */
export function verifyEscalationCheckpointHistory(records,trustedFloor){
 if(!Array.isArray(records)||records.length>64||!position(trustedFloor))
  return fail('INVALID_ESCALATION_CHECKPOINT_INPUT');
 if(records.length<trustedFloor.count)return fail('ESCALATION_CHECKPOINT_ROLLBACK');
 let head=genesis.head,namespace=null,priorEscalation=genesis;
 const checkpointIds=new Set(),previousKeys=new Map(),usedKeys=new Map(),history=[];
 for(let i=0;i<records.length;i++){
  const item=records[i];
  if(!exact(item,entryFields)||!exact(item?.source,sourceFields)||
     !exact(item?.seal,sealFields)||!validBody(item.seal.body)||
     !hex(item.seal.hash)||!Array.isArray(item.seal.witnesses)||
     !Array.isArray(item.custodianTrust)||!Array.isArray(item.expectedCustodianIds))
   return fail('INVALID_CHECKPOINT_ENTRY');
  const b=item.seal.body,src=item.source;
  if(b.sequence!==i+1||b.previousHash!==head)
   return fail('BROKEN_ESCALATION_CHECKPOINT_CHAIN');
  if(checkpointIds.has(b.checkpointId))return fail('REPLAYED_ESCALATION_CHECKPOINT_ID');
  if(namespace!==null&&namespace!==b.namespace)return fail('CHECKPOINT_NAMESPACE_CHANGED');
  const escalation=verifyHandoffConflictJournal(src.entries,src.evidence,
   src.policy,src.policyPin,src.trustedConflictFloor);
  if(!escalation.ok)return fail('ESCALATION_'+escalation.reason);
  let digest;
  try{digest=keyQuorumPolicyDigest(src.policy);}
  catch{return fail('INVALID_ESCALATION_POLICY');}
  if(b.namespace!==src.policy.namespace||b.policyDigest!==digest||
     b.escalationPosition.count!==escalation.candidate.position.count||
     b.escalationPosition.head!==escalation.candidate.position.head)
   return fail('ESCALATION_CHECKPOINT_EVIDENCE_CONFLICT');
  // The complete journal must be an append-only extension of the preceding
  // checkpoint's journal. A repeated identical head is valid, not a new case.
  if(b.escalationPosition.count<priorEscalation.count||
    (priorEscalation.count>0&&
     (src.entries.length<priorEscalation.count||
      src.entries[priorEscalation.count-1].hash!==priorEscalation.head)))
   return fail('ESCALATION_JOURNAL_HISTORY_REWRITTEN');
  const ids=item.expectedCustodianIds;
  if(ids.length<2||ids.length>16||ids.length!==item.custodianTrust.length||
     ids.length!==item.seal.witnesses.length||
     ids.some(x=>!ident(x))||new Set(ids).size!==ids.length)
   return fail('INVALID_ESCALATION_CUSTODIAN_ROSTER');
  const excluded=new Set();
  for(const r of src.policy.reviewers){
   const k=key(r.publicKeyPem);
   if(!k)return fail('INVALID_REVIEWER_PUBLIC_KEY');
   excluded.add(fingerprint(k));
  }
  for(const evidence of src.evidence){
   const k=key(evidence.trust?.publicKeyPem);
   if(!k)return fail('INVALID_CONFLICT_WITNESS_KEY');
   excluded.add(fingerprint(k));
  }
  const trustMap=new Map(),currentKeys=new Set();
  for(const t of item.custodianTrust){
   if(!exact(t,trustFields)||!ids.includes(t.custodianId)||
      trustMap.has(t.custodianId)||t.namespace!==b.namespace||
      t.expectedCheckpointId!==b.checkpointId||t.status!=='ACTIVE')
    return fail('INVALID_OR_REVOKED_AUDIT_CUSTODIAN');
   const k=key(t.publicKeyPem);
   if(!k)return fail('INVALID_CUSTODIAN_KEY');
   const fp=fingerprint(k);
   if(currentKeys.has(fp)||excluded.has(fp))
    return fail('NONINDEPENDENT_ESCALATION_CUSTODIAN');
   if(previousKeys.has(t.custodianId)&&previousKeys.get(t.custodianId)!==fp)
    return fail('CUSTODIAN_KEY_CHANGED_WITHOUT_PROOF');
   if(usedKeys.has(fp)&&usedKeys.get(fp)!==t.custodianId)
    return fail('CUSTODIAN_KEY_REASSIGNED');
   trustMap.set(t.custodianId,k);currentKeys.add(fp);
  }
  const seen=new Set();
  for(const witness of item.seal.witnesses){
   if(!exact(witness,witnessFields)||!ids.includes(witness.custodianId)||
      seen.has(witness.custodianId)||!sig(witness.signature))
    return fail('INVALID_OR_DUPLICATE_ESCALATION_WITNESS');
   const k=trustMap.get(witness.custodianId);
   if(!k||!edVerify(null,escalationCheckpointPayload(b,witness.custodianId),
      k,Buffer.from(witness.signature,'base64')))
    return fail('INVALID_ESCALATION_WITNESS_SIGNATURE');
   seen.add(witness.custodianId);
  }
  if(seen.size!==ids.length)return fail('MISSING_ESCALATION_WITNESS');
  if(escalationCheckpointHash(b,item.seal.witnesses)!==item.seal.hash)
   return fail('TAMPERED_ESCALATION_CHECKPOINT_HASH');
  for(const t of item.custodianTrust){
   const fp=fingerprint(trustMap.get(t.custodianId));
   previousKeys.set(t.custodianId,fp);usedKeys.set(fp,t.custodianId);
  }
  namespace=b.namespace;checkpointIds.add(b.checkpointId);
  priorEscalation=b.escalationPosition;head=item.seal.hash;
  history.push(Object.freeze({sequence:i+1,checkpointId:b.checkpointId,head,
   escalationPosition:b.escalationPosition}));
 }
 const ancestor=trustedFloor.count===0?genesis.head:
  history[trustedFloor.count-1].head;
 if(ancestor!==trustedFloor.head)return fail('TRUSTED_ESCALATION_CHECKPOINT_FORK');
 return verified('ESCALATION_CHECKPOINT_HISTORY_VERIFIED_HOLD',
  'INDEPENDENTLY_SIGNED_ESCALATION_HISTORY_NO_AUTHORITY',
  Object.freeze({position:Object.freeze({count:records.length,head}),
   checkpoints:Object.freeze(history)}));
}
/** A custodian signing two different positions for the same checkpoint
 * creates evidence of inconsistent signed assertions, not proof of which
 * external historical state is correct.
 */
export function inspectEscalationCustodianConflict(a,b,trust,trustedPredecessor){
 if(!exact(a,['body','witness'])||!exact(b,['body','witness'])||
    !validBody(a.body)||!validBody(b.body)||!exact(trust,trustFields)||
    !position(trustedPredecessor))
  return fail('INVALID_CUSTODIAN_CONFLICT_INPUT');
 const x=a.body,y=b.body;
 if(x.namespace!==y.namespace||x.checkpointId!==y.checkpointId||
    x.sequence!==y.sequence||x.previousHash!==y.previousHash||
    x.policyDigest!==y.policyDigest||
    x.sequence!==trustedPredecessor.count+1||
    x.previousHash!==trustedPredecessor.head||
    trust.namespace!==x.namespace||trust.expectedCheckpointId!==x.checkpointId||
    trust.status!=='ACTIVE')return fail('UNRELATED_OR_UNTRUSTED_CLAIMS');
 const k=key(trust.publicKeyPem);
 if(!k)return fail('INVALID_CUSTODIAN_TRUST_KEY');
 for(const claim of [a,b]){
  if(!exact(claim.witness,witnessFields)||claim.witness.custodianId!==trust.custodianId||
     !sig(claim.witness.signature)||!edVerify(null,
       escalationCheckpointPayload(claim.body,trust.custodianId),k,
       Buffer.from(claim.witness.signature,'base64')))
   return fail('UNVERIFIED_CUSTODIAN_CLAIM');
 }
 if(x.escalationPosition.count===y.escalationPosition.count&&
    x.escalationPosition.head===y.escalationPosition.head)
  return verified('NO_PROVEN_CONFLICT','IDENTICAL_SIGNED_ESCALATION_POSITION',null);
 const states=[x.escalationPosition,y.escalationPosition]
  .map(p=>[p.count,p.head]).sort((l,r)=>l[0]-r[0]||
   (l[1]<r[1]?-1:l[1]>r[1]?1:0));
 return verified('ESCALATION_CUSTODIAN_CONFLICT_HOLD',
  'TWO_VALID_CONFLICTING_AUDIT_ASSERTIONS',
  Object.freeze({custodianId:trust.custodianId,checkpointId:x.checkpointId,
   sequence:x.sequence,states:Object.freeze(states),
   evidenceDigest:sha(['PALACO-NEO-ESCALATION-CUSTODIAN-CONFLICT-v1',
    x.namespace,x.checkpointId,x.sequence,x.previousHash,x.policyDigest,states])}));
}
export const INITIAL_ESCALATION_CHECKPOINT_POSITION=genesis;
