import {createHash,createPublicKey,verify as edVerify} from 'node:crypto';
import {transferInventoryDigest} from './cas-custody-lineage.mjs';

/** NEO-036. Read-only byte verification and two-replica repair proposal. */
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 (Object.getPrototypeOf(x)===Object.prototype||Object.getPrototypeOf(x)===null);
const exact=(x,fields)=>plain(x)&&Object.keys(x).sort().join(',')===[...fields].sort().join(',');
const id=x=>typeof x==='string'&&/^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const hex=x=>typeof x==='string'&&/^[0-9a-f]{64}$/.test(x);
const pos=x=>exact(x,['count','head'])&&Number.isSafeInteger(x.count)&&
 x.count>=1&&x.count<=64&&hex(x.head);
const denied=reason=>Object.freeze({ok:false,phase:'HOLD',reason,authorized:false,candidate:null});
const result=(phase,reason,candidate=null)=>Object.freeze({
 ok:true,phase,reason,authorized:false,candidate});
const hash=x=>createHash('sha256').update(x).digest('hex');
const goodSig=s=>typeof s==='string'&&/^[A-Za-z0-9+/]{86}==$/.test(s)&&
 Buffer.from(s,'base64').toString('base64')===s;
const bodyKeys=['schema','namespace','caseId','replicaId','inventoryDigest','lineagePosition','observationId'];
const recordKeys=['body','status','signature','artifacts'];
const trustKeys=['namespace','replicaId','publicKeyPem','status','expectedObservationId'];
const itemKeys=['artifactId','base64'];

export function replicaObservationPayload(body,status){
 if(!exact(body,bodyKeys)||body.schema!=='NEO-036-REPLICA-v1'||
    !id(body.namespace)||!id(body.caseId)||!id(body.replicaId)||
    !hex(body.inventoryDigest)||!pos(body.lineagePosition)||
    !id(body.observationId)||!['PRESENT','INCOMPLETE'].includes(status))
  throw new TypeError('INVALID_REPLICA_OBSERVATION');
 return Buffer.from(JSON.stringify(['PALACO-NEO-REPLICA-OBSERVATION-v1',
  body.namespace,body.caseId,body.replicaId,body.inventoryDigest,
  body.lineagePosition.count,body.lineagePosition.head,body.observationId,status]),'utf8');
}
function keyFingerprint(pem){
 try{
  if(typeof pem!=='string'||pem.length===0||pem.length>8192)return null;
  const key=createPublicKey(pem);
  if(key.asymmetricKeyType!=='ed25519')return null;
  return {key,fingerprint:key.export({type:'spki',format:'der'}).toString('base64')};
 }catch{return null;}
}
function validateBytes(artifacts,expected){
 if(!Array.isArray(artifacts)||artifacts.length>expected.length)return null;
 const map=new Map();
 for(const entry of artifacts){
  if(!exact(entry,itemKeys)||!id(entry.artifactId)||map.has(entry.artifactId)||
     typeof entry.base64!=='string'||entry.base64.length>1398112||
     !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(entry.base64))
   return null;
  map.set(entry.artifactId,entry.base64);
 }
 const missing=[],invalid=[];
 for(const e of expected){
  const encoded=map.get(e.artifactId);
  if(encoded===undefined){missing.push(e.artifactId);continue;}
  const bytes=Buffer.from(encoded,'base64');
  if(bytes.toString('base64')!==encoded||bytes.length!==e.byteLength||
     hash(bytes)!==e.sha256)invalid.push(e.artifactId);
 }
 if([...map.keys()].some(k=>!expected.some(e=>e.artifactId===k)))return null;
 return {missing,invalid};
}
/** Every replica signs an inventory identity, not its supplied raw bytes.
 * All available bytes are rehashed against the externally pinned manifest.
 * The signing key and freshness/identity must be separately authenticated.
 */
export function assessReplicaArchive(manifest,pinnedInventoryDigest,lineagePosition,
 replicas,trusts,expectedReplicaIds){
 let digest;
 try{digest=transferInventoryDigest(manifest);}catch{return denied('INVALID_MANIFEST');}
 if(digest!==pinnedInventoryDigest||!hex(pinnedInventoryDigest)||
    !pos(lineagePosition)||!Array.isArray(replicas)||!Array.isArray(trusts)||
    !Array.isArray(expectedReplicaIds)||replicas.length<2||replicas.length>16||
    replicas.length!==trusts.length||replicas.length!==expectedReplicaIds.length||
    expectedReplicaIds.some(x=>!id(x))||
    new Set(expectedReplicaIds).size!==expectedReplicaIds.length)
  return denied('INVALID_REPLICA_INPUT_OR_PIN');
 const ids=new Set(),keys=new Set(),usedObservations=new Set(),good=[],defective=[];
 for(let i=0;i<replicas.length;i++){
  const rec=replicas[i],t=trusts[i];
  if(!exact(rec,recordKeys)||!exact(t,trustKeys)||!plain(rec.body)||
     !expectedReplicaIds.includes(rec.body.replicaId)||
     ids.has(rec.body.replicaId)||rec.body.replicaId!==t.replicaId||
     rec.body.namespace!==t.namespace||
     rec.body.caseId!==manifest.caseId||
     rec.body.inventoryDigest!==digest||
     !pos(rec.body.lineagePosition)||
     rec.body.lineagePosition.count!==lineagePosition.count||
     rec.body.lineagePosition.head!==lineagePosition.head||
     t.status!=='ACTIVE'||t.expectedObservationId!==rec.body.observationId)
   return denied('INVALID_REPLICA_IDENTITY_OR_CONTEXT');
  const material=keyFingerprint(t.publicKeyPem);
  if(!material||keys.has(material.fingerprint))
    return denied('INVALID_OR_DUPLICATE_REPLICA_KEY');
  let payload;
  try{payload=replicaObservationPayload(rec.body,rec.status);}
  catch{return denied('INVALID_REPLICA_STATEMENT');}
  if(!goodSig(rec.signature)||!edVerify(null,payload,material.key,
    Buffer.from(rec.signature,'base64')))
   return denied('INVALID_REPLICA_SIGNATURE');
  if(usedObservations.has(rec.body.observationId))
   return denied('REPLAYED_OBSERVATION_ID');
  const bytes=validateBytes(rec.artifacts,manifest.artifacts);
  if(bytes===null)return denied('INVALID_ARTIFACT_ENCODING_OR_INVENTORY');
  if(bytes.invalid.length>0)
   return denied('CORRUPTED_REPLICA_BYTES');
  if((rec.status==='PRESENT')!== (bytes.missing.length===0))
   return denied('FALSE_REPLICA_COMPLETENESS_CLAIM');
  ids.add(rec.body.replicaId);keys.add(material.fingerprint);
  usedObservations.add(rec.body.observationId);
  if(bytes.missing.length===0)good.push(rec.body.replicaId);
  else defective.push(Object.freeze({replicaId:rec.body.replicaId,
   missing:Object.freeze([...bytes.missing].sort())}));
 }
 const healthy=Object.freeze([...good].sort());
 if(good.length<2)return result('HOLD','INSUFFICIENT_VERIFIED_REPLICAS',
  Object.freeze({healthyReplicas:healthy,repairProposal:null}));
 if(defective.length===0)return result('VERIFIED_ASSERTIONS_ONLY',
   'MULTI_REPLICA_BYTES_MATCH_MANIFEST_NOT_DURABILITY_PROOF',
   Object.freeze({healthyReplicas:healthy,repairProposal:null}));
 const affected=[...new Set(defective.flatMap(x=>x.missing))].sort();
 return result('REPAIR_PROPOSAL_ONLY','INCOMPLETE_REPLICA_RECOVERY_REQUIRES_OPERATOR',
   Object.freeze({healthyReplicas:healthy,
    repairProposal:Object.freeze({
     caseId:manifest.caseId,inventoryDigest:digest,
     lineagePosition:Object.freeze({...lineagePosition}),
     missingArtifactIds:Object.freeze(affected),
     defectiveReplicas:Object.freeze(defective)
    })}));
}
