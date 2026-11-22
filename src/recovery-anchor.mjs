import {createHash} from 'node:crypto';
import {recoveryChallengeDigest} from './recovery-challenge.mjs';

/**
 * NEO-020: deterministic, read-only trust-anchor transition and reconciliation.
 * EXTERNAL custody is mandatory. These objects do not authenticate themselves.
 */
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 (Object.getPrototypeOf(x)===Object.prototype||Object.getPrototypeOf(x)===null);
const exact=(x,keys)=>plain(x)&&Object.keys(x).sort().join(',')===[...keys].sort().join(',');
const hex=x=>typeof x==='string'&&/^[0-9a-f]{64}$/.test(x);
const id=x=>typeof x==='string'&&/^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const positive=x=>Number.isSafeInteger(x)&&x>=1;
const deny=reason=>Object.freeze({status:'HOLD',reason,authorized:false});
const anchorShape=a=>exact(a,['namespace','revision','digest'])&&id(a.namespace)&&
 positive(a.revision)&&hex(a.digest);
const challengeEntry=(reg,challenge)=>reg.challenges.find(x=>x.challenge===challenge);
const validRegistry=reg=>{
 try{return recoveryChallengeDigest(reg);}catch{return null;}
};
export function proposeRecoveryAnchor(before,oldRegistry,newRegistry,challenge) {
 if(!anchorShape(before)||!hex(challenge))return Object.freeze({ok:false,reason:'INVALID_INPUT',authorized:false,candidate:null});
 const oldHash=validRegistry(oldRegistry),newHash=validRegistry(newRegistry);
 if(!oldHash||!newHash||oldRegistry.namespace!==before.namespace||
    newRegistry.namespace!==before.namespace)return Object.freeze({ok:false,reason:'INVALID_REGISTER',authorized:false,candidate:null});
 if(oldHash!==before.digest)return Object.freeze({ok:false,reason:'UNTRUSTED_BEFORE',authorized:false,candidate:null});
 if(oldRegistry.challenges.length!==newRegistry.challenges.length ||
    oldRegistry.challenges.length===0)return Object.freeze({ok:false,reason:'UNEXPECTED_REGISTRY_CHANGE',authorized:false,candidate:null});
 const previous=challengeEntry(oldRegistry,challenge),next=challengeEntry(newRegistry,challenge);
 if(!previous||!next||previous.status!=='ISSUED'||next.status!=='CONSUMED'||
    previous.signerId!==next.signerId)return Object.freeze({ok:false,reason:'INVALID_CONSUMPTION',authorized:false,candidate:null});
 const oldMap=new Map(oldRegistry.challenges.map(x=>[x.challenge,x]));
 for(const item of newRegistry.challenges){
  const prior=oldMap.get(item.challenge);
  if(!prior||prior.signerId!==item.signerId||
    (item.challenge!==challenge && prior.status!==item.status))
   return Object.freeze({ok:false,reason:'UNEXPECTED_REGISTRY_CHANGE',authorized:false,candidate:null});
 }
 if(before.revision===Number.MAX_SAFE_INTEGER)
   return Object.freeze({ok:false,reason:'REVISION_OVERFLOW',authorized:false,candidate:null});
 const candidate=Object.freeze({namespace:before.namespace,revision:before.revision+1,digest:newHash});
 return Object.freeze({ok:true,reason:'ANCHOR_PROPOSAL_ONLY',authorized:false,candidate});
}
/** Read-only post-commit classification against externally retained before and proposed anchors.
 * COMMITTED is an observation, not permission to advance custody.
 */
export function reconcileRecoveryAnchor(observedRegistry,before,proposal) {
 if(!anchorShape(before)||!anchorShape(proposal)||before.namespace!==proposal.namespace||
    proposal.revision!==before.revision+1)return deny('INVALID_ANCHOR_INPUT');
 const seen=validRegistry(observedRegistry);
 if(!seen||observedRegistry.namespace!==before.namespace)return deny('INVALID_OBSERVED_REGISTER');
 if(seen===before.digest)return Object.freeze({status:'NOT_COMMITTED',reason:'MATCHES_TRUSTED_BEFORE',authorized:false});
 if(seen===proposal.digest)return Object.freeze({status:'COMMITTED',reason:'MATCHES_PINNED_PROPOSAL',authorized:false});
 return deny('UNKNOWN_OR_ROLLED_BACK_STATE');
}
/** Check monotonicity of an externally authenticated anchor sequence.
 * Digests alone cannot prove that the transition was legitimate.
 */
export function verifyAnchorSequence(anchors) {
 if(!Array.isArray(anchors)||anchors.length<1||anchors.length>10000||
    !anchorShape(anchors[0]))return deny('INVALID_ANCHOR_SEQUENCE');
 const ns=anchors[0].namespace;
 for(let i=1;i<anchors.length;i++){
  const prev=anchors[i-1],next=anchors[i];
  if(!anchorShape(next)||next.namespace!==ns||next.revision!==prev.revision+1||
     next.digest===prev.digest)return deny('NON_MONOTONIC_SEQUENCE');
 }
 const values=anchors.map(a=>[a.namespace,a.revision,a.digest]);
 const checksum=createHash('sha256').update(JSON.stringify(['PALACO-NEO-ANCHOR-SEQUENCE-v1',values])).digest('hex');
 return Object.freeze({status:'STRUCTURALLY_VALID',reason:'UNAUTHENTICATED_SEQUENCE_ONLY',
   authorized:false,checksum});
}
