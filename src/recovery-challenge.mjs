import {createHash} from 'node:crypto';
import {verifyRecoveryAttestation} from './recovery-attestation.mjs';

/**
 * NEO-019: read-only validation + single-use transition proposal.
 * Never issues challenges, establishes trust or grants any authority.
 */
const plain=x=>x!==null && typeof x==='object' && !Array.isArray(x) &&
  (Object.getPrototypeOf(x)===Object.prototype || Object.getPrototypeOf(x)===null);
const exact=(x,keys)=>plain(x)&&Object.keys(x).sort().join(',')===[...keys].sort().join(',');
const hex=x=>typeof x==='string' && /^[0-9a-f]{64}$/.test(x);
const id=x=>typeof x==='string' && /^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const reject=reason=>Object.freeze({ok:false,reason,authorized:false,candidate:null});
export function recoveryChallengeDigest(reg) {
 if(!exact(reg,['schema','namespace','challenges'])||reg.schema!=='NEO-019-v1'||
    !id(reg.namespace)||!Array.isArray(reg.challenges)||
    reg.challenges.length>10000) throw new TypeError('INVALID_CHALLENGE_REGISTER');
 const seen=new Set();
 for(const item of reg.challenges) {
  if(!exact(item,['challenge','signerId','status'])||!hex(item.challenge)||
     !id(item.signerId)||!['ISSUED','CONSUMED'].includes(item.status)||
     seen.has(item.challenge)) throw new TypeError('INVALID_CHALLENGE_REGISTER');
  seen.add(item.challenge);
 }
 const entries=[...reg.challenges].sort((a,b)=>a.challenge<b.challenge?-1:a.challenge>b.challenge?1:0)
   .map(x=>[x.challenge,x.signerId,x.status]);
 return createHash('sha256').update(JSON.stringify([
   'PALACO-NEO-CHALLENGE-REGISTER-v1',reg.namespace,entries])).digest('hex');
}
export function proposeChallengeConsumption(reg,expectedDigest,envelope,trust) {
 let current;
 try { current=recoveryChallengeDigest(reg); }
 catch {return reject('INVALID_REGISTER');}
 if(!hex(expectedDigest)||current!==expectedDigest)
   return reject('TRUSTED_REGISTER_MISMATCH');
 if(!plain(envelope)||!hex(envelope.challenge)||!id(envelope.signerId)||
    envelope.namespace!==reg.namespace) return reject('INVALID_ENVELOPE');
 const index=reg.challenges.findIndex(e=>e.challenge===envelope.challenge);
 if(index===-1)return reject('UNISSUED_CHALLENGE');
 if(reg.challenges[index].status!=='ISSUED')return reject('REPLAY');
 if(reg.challenges[index].signerId!==envelope.signerId)
   return reject('SIGNER_MISMATCH');
 if(!plain(trust)||trust.expectedChallenge!==envelope.challenge)
   return reject('INVALID_TRUST_INPUT');
 const result=verifyRecoveryAttestation(envelope,trust);
 if(!result.ok)return reject('ATTESTATION_'+result.reason);
 const challenges=reg.challenges.map((e,i)=>Object.freeze(
   i===index?{...e,status:'CONSUMED'}:{...e}));
 const candidate=Object.freeze({schema:'NEO-019-v1',namespace:reg.namespace,
   challenges:Object.freeze(challenges)});
 return Object.freeze({ok:true,reason:'CONSUMPTION_PROPOSAL_ONLY',
   authorized:false,candidate:Object.freeze({registry:candidate,digest:recoveryChallengeDigest(candidate)})});
}
