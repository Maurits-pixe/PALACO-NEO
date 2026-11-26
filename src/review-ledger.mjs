import {createHash} from 'node:crypto';
import {verifyDualReview} from './approval-review.mjs';

/**
 * NEO-010: verifier for pinned reviewer policy and append-only review proposals.
 * No authority, writes, clocks, authentication service, or replay-proof storage.
 */
const plain=x=>x!==null && typeof x==='object' && !Array.isArray(x) &&
 (Object.getPrototypeOf(x)===Object.prototype || Object.getPrototypeOf(x)===null);
const exact=(x,keys)=>plain(x)&&Object.keys(x).sort().join(',')===[...keys].sort().join(',');
const hex=x=>typeof x==='string' && /^[0-9a-f]{64}$/.test(x);
const ident=x=>typeof x==='string' && /^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const integer=x=>Number.isSafeInteger(x)&&x>=0;
const reject=reason=>Object.freeze({ok:false,reason,authorized:false,candidate:null});
export const REVIEW_GENESIS='0'.repeat(64);

function policyShape(policy) {
 if(!exact(policy,['version','namespace','reviewers']) ||
    !integer(policy.version)||policy.version<1||!ident(policy.namespace)||
    !Array.isArray(policy.reviewers)||policy.reviewers.length<2||
    policy.reviewers.length>32) return false;
 const seen=new Set();
 for(const r of policy.reviewers) {
  if(!exact(r,['id','role','status','publicKeyPem'])||!ident(r.id)||
     seen.has(r.id)||!['OWNER','SECURITY'].includes(r.role)||
     !['ACTIVE','REVOKED'].includes(r.status)||
     typeof r.publicKeyPem!=='string'||r.publicKeyPem.length>8192) return false;
  seen.add(r.id);
 }
 return true;
}
export function reviewerPolicyDigest(policy) {
 if(!policyShape(policy)) throw new TypeError('INVALID_POLICY');
 const reviewers=[...policy.reviewers].sort((a,b)=>a.id.localeCompare(b.id))
  .map(r=>[r.id,r.role,r.status,r.publicKeyPem]);
 return createHash('sha256').update(JSON.stringify([
  'PALACO-NEO-REVIEWER-POLICY-v1',policy.version,policy.namespace,reviewers
 ])).digest('hex');
}
function entryHash(entry) {
 return createHash('sha256').update(JSON.stringify([
  'PALACO-NEO-REVIEW-LEDGER-v1',entry.sequence,entry.previousHash,
  entry.transitionId,entry.policyDigest,entry.beforeDigest,entry.afterDigest
 ])).digest('hex');
}
export function verifyReviewLedger(entries, trustedHead=undefined) {
 if(!Array.isArray(entries)||entries.length>100000||
    (trustedHead!==undefined && !hex(trustedHead)))
    return Object.freeze({ok:false,reason:'INVALID_INPUT',head:null,count:0});
 let previous=REVIEW_GENESIS;
 const transitions=new Set();
 for(let i=0;i<entries.length;i++) {
  const e=entries[i];
  if(!exact(e,['sequence','previousHash','transitionId','policyDigest',
      'beforeDigest','afterDigest','hash'])||
     e.sequence!==i+1||!hex(e.previousHash)||e.previousHash!==previous||
     !ident(e.transitionId)||transitions.has(e.transitionId)||
     !hex(e.policyDigest)||!hex(e.beforeDigest)||!hex(e.afterDigest)||
     !hex(e.hash)||entryHash(e)!==e.hash)
    return Object.freeze({ok:false,reason:'BROKEN_LEDGER',head:null,count:0});
  transitions.add(e.transitionId);previous=e.hash;
 }
 if(trustedHead!==undefined && previous!==trustedHead)
  return Object.freeze({ok:false,reason:'TRUSTED_HEAD_CONFLICT',head:null,count:0});
 return Object.freeze({ok:true,reason:'STRUCTURALLY_VALID_ONLY',head:previous,count:entries.length});
}
/**
 * Trust anchors (policy pin + prior ledger head) MUST be authenticated outside
 * the mutable documents. An accepted proposal is NOT a permission to commit.
 */
export function proposeReviewedDecision(input) {
 if(!exact(input,['beforeRegistry','afterRegistry','beforePin','afterPin',
   'reviews','policy','trustedPolicyPin','transitionId','ledger','trustedLedgerHead']))
   return reject('INVALID_INPUT');
 const {beforeRegistry,afterRegistry,beforePin,afterPin,reviews,policy,
  trustedPolicyPin,transitionId,ledger,trustedLedgerHead}=input;
 if(!policyShape(policy)||!exact(trustedPolicyPin,['version','digest'])||
    !integer(trustedPolicyPin.version)||trustedPolicyPin.version<1||
    !hex(trustedPolicyPin.digest)||!ident(transitionId))
   return reject('INVALID_TRUST_INPUT');
 if(policy.version!==trustedPolicyPin.version||
    reviewerPolicyDigest(policy)!==trustedPolicyPin.digest)
   return reject('UNTRUSTED_REVIEWER_POLICY');
 const active=policy.reviewers.filter(r=>r.status==='ACTIVE')
  .map(({id,role,publicKeyPem})=>({id,role,publicKeyPem}));
 const verified=verifyDualReview(beforeRegistry,afterRegistry,beforePin,afterPin,
   reviews,active,policy.namespace);
 if(!verified.ok)return reject('REVIEW_'+verified.reason);
 const chain=verifyReviewLedger(ledger,trustedLedgerHead);
 if(!chain.ok)return reject('LEDGER_'+chain.reason);
 if(ledger.some(e=>e.transitionId===transitionId||
      (e.beforeDigest===beforePin.digest && e.afterDigest===afterPin.digest)))
  return reject('REPLAY');
 if(!Number.isSafeInteger(ledger.length+1)) return reject('SEQUENCE_OVERFLOW');
 const body={sequence:ledger.length+1,previousHash:chain.head,transitionId,
  policyDigest:trustedPolicyPin.digest,beforeDigest:beforePin.digest,afterDigest:afterPin.digest};
 const item=Object.freeze({...body,hash:entryHash(body)});
 return Object.freeze({ok:true,reason:'REVIEW_EVIDENCE_PROPOSED_NO_AUTHORITY',
  authorized:false,candidate:Object.freeze({entry:item,head:item.hash})});
}
