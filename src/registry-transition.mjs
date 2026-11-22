import {keyRegistryDigest} from './key-registry.mjs';

/**
 * NEO-008 — pure, fail-closed key-registry change proposals and recovery.
 * Trust pins are externally maintained. No filesystem, signing, or authority.
 */
const isObj = x => x !== null && typeof x === 'object' && !Array.isArray(x) &&
  (Object.getPrototypeOf(x) === Object.prototype || Object.getPrototypeOf(x) === null);
const exact = (x,keys) => isObj(x) && Object.keys(x).sort().join(',') === [...keys].sort().join(',');
const hash = x => typeof x === 'string' && /^[0-9a-f]{64}$/.test(x);
const safeId = x => typeof x === 'string' && /^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const version = n => Number.isSafeInteger(n) && n >= 1;
const hold = reason => Object.freeze({ok:false,status:'HOLD',reason,authorized:false,candidate:null});
const result = (status,reason,candidate=null) => Object.freeze({ok:true,status,reason,authorized:false,candidate});
const safeDigest = registry => {
  try { return keyRegistryDigest(registry); } catch { return null; }
};
const immutableRegistry = registry => Object.freeze({
  version:registry.version,namespace:registry.namespace,
  keys:Object.freeze(registry.keys.map(k=>Object.freeze({...k})))
});
const pinMatches = (registry,pin) => version(registry?.version) &&
  exact(pin,['version','digest']) && version(pin.version) &&
  hash(pin.digest) && registry.version === pin.version &&
  safeDigest(registry) === pin.digest;

/**
 * Proposal never performs revocation. One ACTIVE key is required to remain.
 * Previous public keys and validity windows may not be silently rewritten.
 */
export function proposeRegistryTransition(previous, trustedPin, change) {
  if (!pinMatches(previous,trustedPin)) return hold('UNTRUSTED_BASE');
  if (!exact(change,['type','keyId','replacement']) || !safeId(change.keyId) ||
      !['REVOKE','ROTATE'].includes(change.type) ||
      !Number.isSafeInteger(previous.version + 1)) return hold('INVALID_CHANGE');
  const index=previous.keys.findIndex(k=>k.id===change.keyId);
  if(index < 0 || previous.keys[index].status!=='ACTIVE') return hold('NOT_ACTIVE');
  if(change.type==='REVOKE' && change.replacement!==null) return hold('INVALID_CHANGE');
  if(change.type==='ROTATE' && (
     !exact(change.replacement,['id','publicKeyPem','status','fromCount','throughCount']) ||
     !safeId(change.replacement.id) || change.replacement.id===change.keyId ||
     previous.keys.some(k=>k.id===change.replacement.id) ||
     change.replacement.status!=='ACTIVE' ||
     !Number.isSafeInteger(change.replacement.fromCount) ||
     change.replacement.fromCount<0 ||
     !Number.isSafeInteger(change.replacement.throughCount) ||
     change.replacement.throughCount<change.replacement.fromCount))
     return hold('INVALID_REPLACEMENT');
  const keys=previous.keys.map(k=>({...k}));
  keys[index]={...keys[index],status:'REVOKED'};
  if(change.type==='ROTATE') keys.push({...change.replacement});
  if(!keys.some(k=>k.status==='ACTIVE')) return hold('NO_ACTIVE_KEY');
  const proposed=immutableRegistry({version:previous.version+1,namespace:previous.namespace,keys});
  const digest=safeDigest(proposed);
  if (!digest) return hold('INVALID_PROPOSED_REGISTRY');
  const pin=Object.freeze({version:proposed.version,digest});
  return result('PROPOSED','NO_CUSTODY_UPDATE',Object.freeze({registry:proposed,pin}));
}

/**
 * Distinguishes previous state, approved proposal and unexplained state.
 * Expected proposed pin must be captured in trusted custody BEFORE any write.
 */
export function reconcileRegistryTransition(observed, beforePin, proposedPin) {
  if(!exact(beforePin,['version','digest']) || !version(beforePin.version) ||
     !hash(beforePin.digest) || !exact(proposedPin,['version','digest']) ||
     !version(proposedPin.version) || !hash(proposedPin.digest) ||
     proposedPin.version!==beforePin.version+1) return hold('INVALID_TRUST_INPUT');
  const actual=safeDigest(observed);
  if(!actual || !version(observed.version)) return hold('INVALID_OBSERVED_REGISTRY');
  if(observed.version===beforePin.version && actual===beforePin.digest)
    return result('NOT_COMMITTED','BASE_MATCHES');
  if(observed.version===proposedPin.version && actual===proposedPin.digest)
    return result('COMMITTED','PROPOSAL_MATCHES');
  return hold('CONFLICT_OR_UNKNOWN_STATE');
}
