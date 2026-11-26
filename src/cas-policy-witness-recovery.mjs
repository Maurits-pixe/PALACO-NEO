import {createPublicKey} from 'node:crypto';
import {verifyPolicyActivationLedger,verifyPolicyActivationCheckpoint,
 INITIAL_POLICY_ACTIVATION_POSITION} from './cas-policy-activation-ledger.mjs';

/**
 * NEO-031: read-only multi-witness recovery for independently obtained,
 * signed policy activation observations. Never activates or persists anything.
 */
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 (Object.getPrototypeOf(x)===Object.prototype||Object.getPrototypeOf(x)===null);
const exact=(x,keys)=>plain(x)&&Object.keys(x).sort().join(',')===[...keys].sort().join(',');
const id=x=>typeof x==='string'&&/^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const hex=x=>typeof x==='string'&&/^[0-9a-f]{64}$/.test(x);
const pin=x=>exact(x,['version','digest'])&&Number.isSafeInteger(x.version)&&
 x.version>=1&&hex(x.digest);
const position=x=>exact(x,['count','head'])&&Number.isSafeInteger(x.count)&&
 x.count>=0&&x.count<=256&&hex(x.head);
const output=(phase,reason)=>Object.freeze({phase,reason,authorized:false});
const same=(x,y)=>x.version===y.version&&x.digest===y.digest;

/**
 * All witness keys and floors must be fetched from independent authenticated
 * custody. Valid signatures are evidence of statements, not physical independence.
 * The signed checkpoint may be one revision behind; only exactly one revision
 * lag is recognized as a recoverable observation, never an executable action.
 */
export function reconcilePolicyWitnesses(entries,externalTrust,initialPolicy,ledgerFloor,
 witnesses,externallyObservedPolicy,expectedWitnessIds){
 if(!pin(initialPolicy)||!position(ledgerFloor)||!pin(externallyObservedPolicy)||
    !Array.isArray(witnesses)||witnesses.length<2||witnesses.length>16||
    !Array.isArray(expectedWitnessIds)||expectedWitnessIds.length!==witnesses.length||
    expectedWitnessIds.some(x=>!id(x))||
    new Set(expectedWitnessIds).size!==expectedWitnessIds.length)
   return output('HOLD','INVALID_WITNESS_INPUT');
 const ledger=verifyPolicyActivationLedger(entries,externalTrust,initialPolicy,ledgerFloor);
 if(!ledger.ok)return output('HOLD','INVALID_ACTIVATION_LEDGER');
 const seen=new Set(),keys=new Set(),observations=[];
 for(const w of witnesses) {
  if(!exact(w,['seal','trust'])||!plain(w.seal)||!plain(w.trust)||
    !id(w.seal.witnessId)||!expectedWitnessIds.includes(w.seal.witnessId)||
    seen.has(w.seal.witnessId)||w.trust.witnessId!==w.seal.witnessId)
   return output('HOLD','DUPLICATE_OR_UNEXPECTED_WITNESS');
  const t=w.trust;
  if(typeof t.publicKeyPem!=='string'||t.publicKeyPem.length>8192)
   return output('HOLD','INVALID_WITNESS_KEY');
  let fingerprint;
  try{
   const k=createPublicKey(t.publicKeyPem);
   if(k.asymmetricKeyType!=='ed25519')return output('HOLD','INVALID_WITNESS_KEY');
   fingerprint=k.export({type:'spki',format:'der'}).toString('base64');
  }catch{return output('HOLD','INVALID_WITNESS_KEY');}
  if(keys.has(fingerprint))return output('HOLD','SHARED_WITNESS_SIGNING_KEY');
  seen.add(w.seal.witnessId);keys.add(fingerprint);
  const checked=verifyPolicyActivationCheckpoint(entries,externalTrust,initialPolicy,
   ledgerFloor,w.seal,t);
  if(!checked.ok)return output('HOLD','INVALID_SIGNED_WITNESS_'+checked.reason);
  observations.push(w.seal.checkpoint);
 }
 if(seen.size!==expectedWitnessIds.length)
   return output('HOLD','MISSING_WITNESS');
 const [first,...rest]=observations;
 if(rest.some(x=>x.count!==first.count||x.head!==first.head||
     !same(x.activePolicy,first.activePolicy)))
   return output('HOLD','CONFLICTING_SIGNED_WITNESSES');
 if(!same(first.activePolicy,ledger.candidate.activePolicy)||
    first.count!==ledger.candidate.position.count||
    first.head!==ledger.candidate.position.head)
   return output('HOLD','UNEXPECTED_CHECKPOINT_STATE');
 if(same(externallyObservedPolicy,first.activePolicy))
   return output('CONSISTENT','MATCHING_SIGNED_WITNESSES_NO_AUTHORITY');
 // A separately observed prior policy is a recoverable but unsafe uncertainty.
 // Without authenticated external state freshness, NEVER advance or retry.
 if(entries.length>0&&same(externallyObservedPolicy,entries.at(-1).request.before))
   return output('HOLD','EXTERNAL_POLICY_LAGS_SIGNED_CHECKPOINT');
 return output('HOLD','UNKNOWN_EXTERNAL_POLICY_OR_ROLLBACK');
}

/**
 * Distinguish unchanged, appended, conflicting and truncated ledger evidence
 * from an externally anchored previous checkpoint. Never performs retry.
 */
export function classifyPolicyCheckpointRecovery(before,observed,entries) {
 if(!position(before)||!position(observed)||!Array.isArray(entries)||
    entries.length>256)return output('HOLD','INVALID_RECOVERY_INPUT');
 if(observed.count<before.count)return output('HOLD','CHECKPOINT_ROLLBACK');
 const prefix=before.count===0?INITIAL_POLICY_ACTIVATION_POSITION.head:
   entries[before.count-1]?.hash;
 if(prefix!==before.head)return output('HOLD','CHECKPOINT_FORK_OR_MISSING_PREFIX');
 const tip=observed.count===0?INITIAL_POLICY_ACTIVATION_POSITION.head:
   entries[observed.count-1]?.hash;
 if(tip!==observed.head||entries.length!==observed.count)
   return output('HOLD','UNVERIFIED_OBSERVED_TIP');
 if(observed.count===before.count)
   return output('UNCHANGED','MATCHES_EXTERNAL_CHECKPOINT');
 return output('PENDING_INDEPENDENT_REVIEW','APPENDED_CHAIN_NOT_AUTHORIZED');
}
