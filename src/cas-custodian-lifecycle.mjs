import {createHash,createPublicKey} from 'node:crypto';
import {verifyAuditCheckpointSuccession,INITIAL_AUDIT_HISTORY_POSITION}
 from './cas-audit-history.mjs';

/** NEO-044 — immutable-by-hash, verify-only custodian key lineage evidence.
 * No persistence, key activation, release, network calls or authority.
 */
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 (Object.getPrototypeOf(x)===Object.prototype||Object.getPrototypeOf(x)===null);
const exact=(x,fields)=>plain(x)&&Object.keys(x).sort().join(',')===[...fields].sort().join(',');
const hex=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const id=x=>typeof x==='string'&&/^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const fail=reason=>Object.freeze({ok:false,phase:'HOLD',reason,authorized:false,candidate:null});
function fingerprint(pem){
 try{
  if(typeof pem!=='string'||pem.length<1||pem.length>8192)return null;
  const k=createPublicKey(pem);
  return k.asymmetricKeyType==='ed25519'?
   createHash('sha256').update(k.export({type:'spki',format:'der'})).digest('hex'):null;
 }catch{return null;}
}
function fingerprintHistory(history){
 const owners=new Map(),retired=new Set(),active=new Map();
 const records=[],seenRotations=new Set();
 for(let i=0;i<history.length;i++){
  const item=history[i];
  const current=new Map();
  if(!Array.isArray(item.trusts))return null;
  for(const t of item.trusts){
   if(!plain(t)||!id(t.custodianId))return null;
   const fp=fingerprint(t.publicKeyPem);
   if(fp===null||current.has(t.custodianId)||retired.has(fp))
    return null;
   const owner=owners.get(fp);
   if(owner!==undefined&&owner!==t.custodianId)return null;
   owners.set(fp,t.custodianId);
   current.set(t.custodianId,fp);
  }
  for(const [custodianId,fp] of active){
   if(!current.has(custodianId)){
    retired.add(fp);
    records.push([i+1,custodianId,'RETIRED_MISSING',fp]);
   }else if(current.get(custodianId)!==fp){
    retired.add(fp);
    records.push([i+1,custodianId,'RETIRED_ROTATED',fp]);
   }
  }
  for(const [custodianId,fp] of current){
   if(!active.has(custodianId))
    records.push([i+1,custodianId,'INITIAL_OR_RETURN',fp]);
   else if(active.get(custodianId)!==fp)
    records.push([i+1,custodianId,'ACTIVE_ROTATED',fp]);
  }
  active.clear();
  for(const [k,v] of current)active.set(k,v);
 }
 return {records,retired:[...retired].sort(),active:[...active].sort((a,b)=>a[0]<b[0]?-1:1)};
}
/** Independent lifecycle pin protects omissions only if retained externally. */
export function verifyCustodianKeyLifecycle(history,rotations,historyFloor,lifecyclePin=null){
 const base=verifyAuditCheckpointSuccession(history,historyFloor,rotations);
 if(!base.ok)return fail('AUDIT_'+base.reason);
 const view=fingerprintHistory(history);
 if(view===null)return fail('REACTIVATED_OR_REASSIGNED_KEY');
 if(!Array.isArray(rotations))return fail('INVALID_LIFECYCLE_ROTATIONS');
 const byCustodian=new Map();
 for(const r of rotations){
  const b=r?.proof?.body;
  if(!plain(b)||!id(b.rotationId)||!id(b.custodianId)||
     !Number.isSafeInteger(r.atSequence)||r.atSequence!==b.atSequence)
   return fail('INVALID_LIFECYCLE_ROTATION');
  const list=byCustodian.get(b.custodianId)??[];
  list.push([b.atSequence,b.rotationId,fingerprint(b.oldKeyPem),
   fingerprint(b.newKeyPem)]);
  byCustodian.set(b.custodianId,list);
 }
 const rotList=[...byCustodian].sort((a,b)=>a[0]<b[0]?-1:1)
  .flatMap(([custodianId,list])=>list.sort((a,b)=>a[0]-b[0])
    .map(x=>[custodianId,...x]));
 const lifecycleDigest=createHash('sha256').update(JSON.stringify([
  'PALACO-NEO-CUSTODIAN-LIFECYCLE-v1',base.candidate.position.count,
  base.candidate.position.head,view.records,view.retired,view.active,rotList
 ])).digest('hex');
 if(lifecyclePin!==null&&
    (!exact(lifecyclePin,['count','head','digest'])||
     !Number.isSafeInteger(lifecyclePin.count)||lifecyclePin.count<0||
     lifecyclePin.count>64||!hex(lifecyclePin.head)||!hex(lifecyclePin.digest)||
     lifecyclePin.count!==base.candidate.position.count||
     lifecyclePin.head!==base.candidate.position.head||
     lifecyclePin.digest!==lifecycleDigest))
  return fail('TRUSTED_LIFECYCLE_PIN_CONFLICT');
 return Object.freeze({ok:true,phase:'LIFECYCLE_EVIDENCE_VERIFIED_HOLD',
  reason:'SIGNED_KEY_GENERATIONS_VERIFIED_NO_AUTHORITY',authorized:false,
  candidate:Object.freeze({
   position:base.candidate.position,lifecycleDigest,
   active:Object.freeze(view.active.map(([custodianId,fingerprint])=>
    Object.freeze({custodianId,fingerprint}))),
   retiredFingerprints:Object.freeze(view.retired),
   transitions:Object.freeze(view.records.map(([sequence,custodianId,action,fingerprint])=>
    Object.freeze({sequence,custodianId,action,fingerprint})))
  })});
}
export const INITIAL_CUSTODIAN_LIFECYCLE_POSITION=INITIAL_AUDIT_HISTORY_POSITION;
