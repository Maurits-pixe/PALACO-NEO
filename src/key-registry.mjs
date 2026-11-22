import {createHash} from 'node:crypto';
import {verifyAttestedCheckpoint} from './attestation.mjs';
import {GENESIS_HASH} from './audit.mjs';

/**
 * NEO-007 read-only registry validation.
 * Only an independently pinned digest authenticates the supplied registry.
 * No key issuance, revocation mutation, or execution authority.
 */
const plain = x => x !== null && typeof x === 'object' && !Array.isArray(x) &&
  (Object.getPrototypeOf(x) === Object.prototype || Object.getPrototypeOf(x) === null);
const exact = (x, keys) => plain(x) &&
  Object.keys(x).sort().join(',') === [...keys].sort().join(',');
const hex = x => typeof x === 'string' && /^[0-9a-f]{64}$/.test(x);
const id = x => typeof x === 'string' && /^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const count = x => Number.isSafeInteger(x) && x >= 0;
const deny = reason => Object.freeze({ok:false,reason,authorized:false,anchor:null});

function validRegistry(reg) {
  if (!exact(reg,['version','namespace','keys']) || !count(reg.version) ||
      !id(reg.namespace) || !Array.isArray(reg.keys) ||
      reg.keys.length === 0 || reg.keys.length > 128) return false;
  const seen = new Set();
  for (const key of reg.keys) {
    if (!exact(key,['id','publicKeyPem','status','fromCount','throughCount']) ||
        !id(key.id) || seen.has(key.id) ||
        typeof key.publicKeyPem !== 'string' || key.publicKeyPem.length > 8192 ||
        !['ACTIVE','REVOKED'].includes(key.status) ||
        !count(key.fromCount) || !count(key.throughCount) ||
        key.fromCount > key.throughCount) return false;
    seen.add(key.id);
  }
  return true;
}

export function keyRegistryDigest(registry) {
  if (!validRegistry(registry)) throw new TypeError('INVALID_REGISTRY');
  // Sorting by ID ensures a unique digest regardless of presentation order.
  const keys = [...registry.keys].sort((a,b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
  const entries = keys.map(k => [k.id,k.publicKeyPem,k.status,k.fromCount,k.throughCount]);
  const bytes = JSON.stringify(['PALACO-NEO-KEY-REGISTRY-v1',registry.version,registry.namespace,entries]);
  return createHash('sha256').update(bytes,'utf8').digest('hex');
}

/**
 * options.trustedRegistryDigest and options.trustedFloor must be independently
 * anchored. A supplied registry cannot authenticate itself.
 */
export function verifyRegistryAttestation(records, envelope, registry, options) {
  if (!validRegistry(registry) ||
      !exact(envelope,['namespace','anchor','signature','keyId']) ||
      !exact(options,['namespace','trustedRegistryDigest','minimumRegistryVersion','trustedFloor']) ||
      !id(options.namespace) || registry.namespace !== options.namespace ||
      envelope.namespace !== options.namespace || !hex(options.trustedRegistryDigest) ||
      !count(options.minimumRegistryVersion) ||
      !exact(options.trustedFloor,['count','head']) ||
      !count(options.trustedFloor.count) || !hex(options.trustedFloor.head))
    return deny('INVALID_TRUST_INPUT');
  if (registry.version < options.minimumRegistryVersion)
    return deny('STALE_REGISTRY');
  if (keyRegistryDigest(registry) !== options.trustedRegistryDigest)
    return deny('REGISTRY_DIGEST_MISMATCH');
  if (!id(envelope.keyId)) return deny('INVALID_KEY_ID');
  const key = registry.keys.find(k => k.id === envelope.keyId);
  if (!key) return deny('UNKNOWN_KEY');
  if (key.status !== 'ACTIVE') return deny('REVOKED_KEY');
  if (!exact(envelope.anchor,['count','head']) ||
      !count(envelope.anchor.count) || !hex(envelope.anchor.head))
    return deny('INVALID_ANCHOR');
  const currentCount = envelope.anchor.count;
  if (currentCount < key.fromCount || currentCount > key.throughCount)
    return deny('KEY_OUTSIDE_VALIDITY_WINDOW');
  const floor = options.trustedFloor;
  if (currentCount < floor.count) return deny('ROLLBACK_FLOOR');
  if (!Array.isArray(records) || records.length !== currentCount)
    return deny('CHAIN_LENGTH_MISMATCH');
  // Authenticate the historical head at the independently trusted floor.
  const floorHead = floor.count === 0 ? GENESIS_HASH : records[floor.count-1]?.hash;
  if (floorHead !== floor.head) return deny('TRUSTED_FLOOR_CONFLICT');
  const verified = verifyAttestedCheckpoint(records,
    {namespace:envelope.namespace,anchor:envelope.anchor,signature:envelope.signature},
    key.publicKeyPem,{namespace:options.namespace,minimumCount:floor.count});
  if (!verified.ok) return deny(verified.reason);
  return Object.freeze({ok:true,reason:'REGISTRY_ATTESTATION_VERIFIED_NOT_AUTHORIZED',
    authorized:false,anchor:verified.anchor});
}
