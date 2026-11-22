import {createPublicKey, verify as verifySignature} from 'node:crypto';
import {keyRegistryDigest} from './key-registry.mjs';

/**
 * NEO-009: offline, read-only dual-review verifier.
 * The trusted reviewers and their pinned keys come from independent custody.
 * This validates review evidence, NEVER authorizes execution or publication.
 */
const obj=x=>x!==null && typeof x==='object' && !Array.isArray(x) &&
  (Object.getPrototypeOf(x)===Object.prototype || Object.getPrototypeOf(x)===null);
const exact=(x,fields)=>obj(x) && Object.keys(x).sort().join(',')===[...fields].sort().join(',');
const id=x=>typeof x==='string' && /^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const hex=x=>typeof x==='string' && /^[0-9a-f]{64}$/.test(x);
const deny=reason=>Object.freeze({ok:false,reason,authorized:false});
const pin=x=>exact(x,['version','digest']) && Number.isSafeInteger(x.version) &&
  x.version>=1 && hex(x.digest);
const signedBytes=(namespace,before,after)=>
  Buffer.from(JSON.stringify(['PALACO-NEO-REVIEW-v1',namespace,before.version,
    before.digest,after.version,after.digest]),'utf8');
function signatureOK(signature,pem,message) {
  if(typeof signature!=='string' || !/^[A-Za-z0-9+/]{86}==$/.test(signature)) return false;
  try {
    const bytes=Buffer.from(signature,'base64');
    if(bytes.length!==64 || bytes.toString('base64')!==signature) return false;
    const key=createPublicKey(pem);
    return key.asymmetricKeyType==='ed25519' && verifySignature(null,message,key,bytes);
  } catch { return false; }
}
export function reviewPayload(namespace,before,after) {
  if(!id(namespace) || !pin(before) || !pin(after) ||
     after.version!==before.version+1) throw new TypeError('INVALID_REVIEW_PAYLOAD');
  return signedBytes(namespace,before,after);
}
export function verifyDualReview(beforeRegistry,proposedRegistry,beforePin,afterPin,
  reviews,trustedReviewers,namespace) {
  if(!id(namespace) || !pin(beforePin) || !pin(afterPin) ||
     !obj(beforeRegistry) || !obj(proposedRegistry) ||
     beforeRegistry.namespace!==namespace || proposedRegistry.namespace!==namespace ||
     beforeRegistry.version!==beforePin.version ||
     proposedRegistry.version!==afterPin.version ||
     afterPin.version!==beforePin.version+1)
    return deny('INVALID_TRANSITION');
  try {
    if(keyRegistryDigest(beforeRegistry)!==beforePin.digest ||
       keyRegistryDigest(proposedRegistry)!==afterPin.digest) return deny('PIN_MISMATCH');
  } catch {return deny('INVALID_REGISTRY');}
  if(!Array.isArray(reviews) || reviews.length!==2 ||
     !Array.isArray(trustedReviewers) || trustedReviewers.length<2 ||
     trustedReviewers.length>32) return deny('INVALID_REVIEW_SET');
  const byId=new Map();
  for(const reviewer of trustedReviewers) {
    if(!exact(reviewer,['id','publicKeyPem','role']) ||
       !id(reviewer.id) || byId.has(reviewer.id) ||
       typeof reviewer.publicKeyPem!=='string' || reviewer.publicKeyPem.length>8192 ||
       !['OWNER','SECURITY'].includes(reviewer.role)) return deny('INVALID_REVIEWER_TRUST');
    byId.set(reviewer.id,reviewer);
  }
  const seen=new Set();
  const message=signedBytes(namespace,beforePin,afterPin);
  for(const review of reviews) {
    if(!exact(review,['reviewerId','signature']) || !id(review.reviewerId) ||
       seen.has(review.reviewerId)) return deny('DUPLICATE_OR_INVALID_REVIEW');
    seen.add(review.reviewerId);
    const trusted=byId.get(review.reviewerId);
    if(!trusted || !signatureOK(review.signature,trusted.publicKeyPem,message))
      return deny('UNTRUSTED_OR_INVALID_SIGNATURE');
  }
  const roles=new Set([...seen].map(name=>byId.get(name).role));
  if(!roles.has('OWNER') || !roles.has('SECURITY')) return deny('ROLE_SEPARATION_REQUIRED');
  return Object.freeze({ok:true,reason:'DUAL_REVIEW_VERIFIED_NO_AUTHORITY',authorized:false});
}
