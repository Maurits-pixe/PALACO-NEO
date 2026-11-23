import {createHash,createPublicKey,verify as edVerify} from 'node:crypto';
import {verifyRepairConflictJournal,INITIAL_REPAIR_CONFLICT_POSITION}
 from './cas-repair-conflict-journal.mjs';

/** NEO-041: read-only independently witnessed conflict-audit checkpoints. */
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 (Object.getPrototypeOf(x)===Object.prototype||Object.getPrototypeOf(x)===null);
const exact=(x,fields)=>plain(x)&&Object.keys(x).sort().join(',')===[...fields].sort().join(',');
const id=x=>typeof x==='string'&&/^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const hex=x=>typeof x==='string'&&/^[0-9a-f]{64}$/.test(x);
const pos=x=>exact(x,['count','head'])&&Number.isSafeInteger(x.count)&&
 x.count>=0&&x.count<=128&&hex(x.head);
const signature=x=>typeof x==='string'&&/^[A-Za-z0-9+/]{86}==$/.test(x)&&
 Buffer.from(x,'base64').toString('base64')===x;
const deny=reason=>Object.freeze({ok:false,phase:'HOLD',reason,authorized:false,candidate:null});
const accept=(phase,reason,candidate)=>Object.freeze({ok:true,phase,reason,authorized:false,candidate});
const bodyKeys=['schema','namespace','checkpointId','position','anchoredFloor','policyDigest'];
const trustKeys=['namespace','custodianId','publicKeyPem','status','expectedCheckpointId'];
const sealKeys=['body','attestations'];
const attestationKeys=['custodianId','signature'];
const floorKeys=['count','head'];
const boundBody=b=>exact(b,bodyKeys)&&
 b.schema==='NEO-041-AUDIT-CHECKPOINT-v1'&&
 id(b.namespace)&&id(b.checkpointId)&&
 pos(b.position)&&exact(b.position,floorKeys)&&
 pos(b.anchoredFloor)&&exact(b.anchoredFloor,floorKeys)&&
 b.position.count>=b.anchoredFloor.count&&hex(b.policyDigest);
const sha=x=>createHash('sha256').update(JSON.stringify(x)).digest('hex');
function keyOf(pem){
 try{
  if(typeof pem!=='string'||pem.length===0||pem.length>8192)return null;
  const key=createPublicKey(pem);
  return key.asymmetricKeyType==='ed25519'?key:null;
 }catch{return null;}
}
function fingerprint(key){
 return key.export({type:'spki',format:'der'}).toString('base64');
}
export function auditCheckpointPayload(body,custodianId){
 if(!boundBody(body)||!id(custodianId))
  throw new TypeError('INVALID_AUDIT_CHECKPOINT');
 return Buffer.from(JSON.stringify(['PALACO-NEO-AUDIT-CHECKPOINT-v1',
  body.namespace,body.checkpointId,body.position.count,body.position.head,
  body.anchoredFloor.count,body.anchoredFloor.head,body.policyDigest,
  custodianId]),'utf8');
}
function verifyAttestation(body,attestation,trust){
 if(!exact(attestation,attestationKeys)||!id(attestation.custodianId)||
    !signature(attestation.signature)||!exact(trust,trustKeys)||
    trust.custodianId!==attestation.custodianId||
    trust.namespace!==body.namespace||trust.status!=='ACTIVE'||
    trust.expectedCheckpointId!==body.checkpointId)return null;
 const key=keyOf(trust.publicKeyPem);
 if(!key)return null;
 try{
  if(!edVerify(null,auditCheckpointPayload(body,trust.custodianId),key,
      Buffer.from(attestation.signature,'base64')))return null;
 }catch{return null;}
 return key;
}
function trustedRoster(ids,trusts,namespace,checkpointId,forbidden=[]){
 if(!Array.isArray(ids)||!Array.isArray(trusts)||ids.length<2||ids.length>16||
    ids.length!==trusts.length||ids.some(x=>!id(x))||
    new Set(ids).size!==ids.length)return null;
 const known=new Map(),keys=new Set(),untrustedKeys=new Set();
 for(const pem of forbidden){
  const key=keyOf(pem);
  if(key)untrustedKeys.add(fingerprint(key));
 }
 for(const trust of trusts){
  if(!exact(trust,trustKeys)||!ids.includes(trust.custodianId)||
     known.has(trust.custodianId)||trust.namespace!==namespace||
     trust.expectedCheckpointId!==checkpointId||trust.status!=='ACTIVE')
   return null;
  const key=keyOf(trust.publicKeyPem);
  if(!key)return null;
  const fp=fingerprint(key);
  if(keys.has(fp)||untrustedKeys.has(fp))return null;
  keys.add(fp);known.set(trust.custodianId,trust);
 }
 return known.size===ids.length?known:null;
}
export function auditCheckpointHash(seal){
 if(!exact(seal,sealKeys)||!boundBody(seal.body)||
    !Array.isArray(seal.attestations)||seal.attestations.length<2||
    seal.attestations.length>16||
    seal.attestations.some(x=>!exact(x,attestationKeys)||
     !id(x.custodianId)||!signature(x.signature))||
    new Set(seal.attestations.map(x=>x.custodianId)).size!==seal.attestations.length)
  throw new TypeError('INVALID_AUDIT_SEAL');
 return sha(['PALACO-NEO-AUDIT-CHECKPOINT-SEAL-v1',
  auditCheckpointPayload(seal.body,'seal-body').toString('base64'),
  [...seal.attestations].sort((a,b)=>a.custodianId<b.custodianId?-1:1)
   .map(a=>[a.custodianId,a.signature])]);
}
/**
 * A fully supplied NEO-040 log is reverified from original fork evidence.
 * No assertion may move below the independently pinned previous floor.
 */
export function verifyAuditCheckpoint(entries,evidence,policy,policyPin,
 trustedFloor,seal,trusts,expectedCustodianIds){
 if(!pos(trustedFloor)||!exact(seal,sealKeys)||!boundBody(seal.body)||
    !Array.isArray(seal.attestations)||
    seal.attestations.length!==expectedCustodianIds?.length)
  return deny('INVALID_CHECKPOINT_INPUT');
 const b=seal.body;
 const journal=verifyRepairConflictJournal(entries,evidence,policy,policyPin,trustedFloor);
 if(!journal.ok)return deny('JOURNAL_'+journal.reason);
 if(policy.namespace!==b.namespace||policyPin.digest!==b.policyDigest||
    b.anchoredFloor.count!==trustedFloor.count||
    b.anchoredFloor.head!==trustedFloor.head||
    b.position.count!==journal.candidate.position.count||
    b.position.head!==journal.candidate.position.head)
  return deny('CHECKPOINT_STATE_OR_ANCHOR_CONFLICT');
 const roster=trustedRoster(expectedCustodianIds,trusts,b.namespace,b.checkpointId,
  policy.reviewers.map(r=>r.publicKeyPem));
 if(!roster)return deny('INVALID_OR_NONINDEPENDENT_CUSTODY_ROSTER');
 const seen=new Set();
 for(const att of seal.attestations){
  if(!roster.has(att?.custodianId)||seen.has(att.custodianId)||
    !verifyAttestation(b,att,roster.get(att.custodianId)))
   return deny('INVALID_OR_DUPLICATE_CUSTODY_SIGNATURE');
  seen.add(att.custodianId);
 }
 if(seen.size!==roster.size)return deny('MISSING_CUSTODY_SIGNATURE');
 return accept('AUDIT_CHECKPOINT_VERIFIED_HOLD',
  'MULTI_CUSTODIAN_SIGNED_AUDIT_ASSERTIONS_ONLY',Object.freeze({
    position:journal.candidate.position,checkpointId:b.checkpointId,
    sealDigest:auditCheckpointHash(seal),
    custodianIds:Object.freeze([...seen].sort()),
    cases:journal.candidate.cases
  }));
}
/**
 * Detect key-level equivocation even if one signed assertion describes a
 * state that DOES NOT match a valid independently verified journal. Both
 * original signatures and their common trusted floor must still verify.
 */
export function inspectAuditCustodianEquivocation(a,b,trust,trustedFloor){
 if(!pos(trustedFloor)||!plain(a)||!plain(b)||
    !boundBody(a.body)||!boundBody(b.body)||!plain(trust)||
    a.body.anchoredFloor.count!==trustedFloor.count||
    a.body.anchoredFloor.head!==trustedFloor.head||
    b.body.anchoredFloor.count!==trustedFloor.count||
    b.body.anchoredFloor.head!==trustedFloor.head)
  return deny('INVALID_EQUIVOCATION_INPUT');
 if(a.body.namespace!==b.body.namespace||
    a.body.checkpointId!==b.body.checkpointId||
    a.body.policyDigest!==b.body.policyDigest||
    a.body.position.count!==b.body.position.count)
  return deny('UNRELATED_CUSTODY_STATEMENTS');
 const ka=verifyAttestation(a.body,a.attestation,trust);
 const kb=verifyAttestation(b.body,b.attestation,trust);
 if(!ka||!kb)return deny('UNVERIFIED_CUSTODY_STATEMENT');
 if(a.body.position.head===b.body.position.head)
  return accept('NO_CONFLICT','IDENTICAL_POSITION_ASSERTIONS',null);
 const heads=[a.body.position.head,b.body.position.head].sort();
 const candidate=Object.freeze({custodianId:trust.custodianId,
  checkpointId:a.body.checkpointId,positionCount:a.body.position.count,
  anchoredFloor:Object.freeze({...trustedFloor}),
  heads:Object.freeze(heads),
  evidenceDigest:sha(['PALACO-NEO-AUDIT-CUSTODIAN-EQUIVOCATION-v1',
   trust.custodianId,a.body.namespace,a.body.checkpointId,
   a.body.policyDigest,a.body.position.count,trustedFloor.count,
   trustedFloor.head,heads])});
 return accept('EQUIVOCATION_EVIDENCE_HOLD',
  'CONFLICTING_SIGNED_CUSTODIAN_ASSERTIONS',candidate);
}
export const INITIAL_AUDIT_CHECKPOINT_POSITION=INITIAL_REPAIR_CONFLICT_POSITION;
