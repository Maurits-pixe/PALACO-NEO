import {proposeChallengeConsumption, recoveryChallengeDigest} from './recovery-challenge.mjs';
import {proposeRecoveryAnchor} from './recovery-anchor.mjs';

/**
 * NEO-021: pure two-system handoff preparation and recovery state machine.
 * No atomic transaction across independent custodians is claimed or performed.
 */
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
  (Object.getPrototypeOf(x)===Object.prototype||Object.getPrototypeOf(x)===null);
const exact=(x,keys)=>plain(x)&&Object.keys(x).sort().join(',')===[...keys].sort().join(',');
const hex=x=>typeof x==='string'&&/^[0-9a-f]{64}$/.test(x);
const id=x=>typeof x==='string'&&/^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const anchor=a=>exact(a,['namespace','revision','digest'])&&id(a.namespace)&&
  Number.isSafeInteger(a.revision)&&a.revision>=1&&hex(a.digest);
const deny=reason=>Object.freeze({ok:false,reason,authorized:false,plan:null});
const state=(phase,reason)=>Object.freeze({phase,reason,authorized:false});

/** Compute and bind a single signed challenge consumption to an anchor CAS.
 * Both BEFORE inputs must be supplied from external authenticated custody.
 */
export function prepareRecoveryHandoff(registry,beforeAnchor,envelope,signerTrust) {
 if(!anchor(beforeAnchor)||!plain(envelope)||!hex(envelope.challenge)||
    !plain(registry)||registry.namespace!==beforeAnchor.namespace)
  return deny('INVALID_INPUT');
 const consumed=proposeChallengeConsumption(registry,beforeAnchor.digest,envelope,signerTrust);
 if(!consumed.ok)return deny('CHALLENGE_'+consumed.reason);
 const next=proposeRecoveryAnchor(beforeAnchor,registry,consumed.candidate.registry,envelope.challenge);
 if(!next.ok)return deny('ANCHOR_'+next.reason);
 const plan=Object.freeze({schema:'NEO-021-v1',namespace:beforeAnchor.namespace,
  challenge:envelope.challenge,
  before:Object.freeze({...beforeAnchor}),after:next.candidate,
  proposedRegistry:consumed.candidate.registry});
 return Object.freeze({ok:true,reason:'HANDOFF_PLAN_ONLY',authorized:false,plan});
}

/** Classify BOTH independently observed states. The external anchor MUST be
 * freshly read from authenticated custody; the register must be verified independently.
 * A PENDING result requests human-reviewed CAS, NOT an automatic update.
 */
export function classifyRecoveryHandoff(plan,observedRegistry,externalAnchor) {
 if(!exact(plan,['schema','namespace','challenge','before','after','proposedRegistry'])||
    plan.schema!=='NEO-021-v1'||!id(plan.namespace)||!hex(plan.challenge)||
    !anchor(plan.before)||!anchor(plan.after)||!anchor(externalAnchor)||
    plan.namespace!==plan.before.namespace||plan.namespace!==plan.after.namespace||
    plan.namespace!==externalAnchor.namespace||
    plan.after.revision!==plan.before.revision+1)
  return state('HOLD','INVALID_HANDOFF_INPUT');
 let observedDigest,plannedDigest;
 try {observedDigest=recoveryChallengeDigest(observedRegistry);
      plannedDigest=recoveryChallengeDigest(plan.proposedRegistry);}
 catch{return state('HOLD','INVALID_REGISTER');}
 if(observedRegistry.namespace!==plan.namespace||
    plan.proposedRegistry.namespace!==plan.namespace||
    plannedDigest!==plan.after.digest||
    !plan.proposedRegistry.challenges.some(e=>e.challenge===plan.challenge&&e.status==='CONSUMED'))
  return state('HOLD','PLAN_INTEGRITY_CONFLICT');
 const localBefore=observedDigest===plan.before.digest;
 const localAfter=observedDigest===plan.after.digest;
 const remoteBefore=externalAnchor.revision===plan.before.revision&&
  externalAnchor.digest===plan.before.digest;
 const remoteAfter=externalAnchor.revision===plan.after.revision&&
  externalAnchor.digest===plan.after.digest;
 if(!localBefore&&!localAfter)return state('HOLD','UNKNOWN_LOCAL_STATE');
 if(!remoteBefore&&!remoteAfter)return state('HOLD','UNKNOWN_EXTERNAL_ANCHOR');
 if(localBefore&&remoteBefore)return state('NOT_COMMITTED','BOTH_AT_BEFORE');
 if(localAfter&&remoteBefore)return state('PENDING_ANCHOR_CAS','LOCAL_ADVANCED_EXTERNAL_BEFORE');
 if(localAfter&&remoteAfter)return state('COMMITTED','BOTH_AT_PROPOSED');
 return state('HOLD','EXTERNAL_ADVANCED_LOCAL_BEHIND');
}
