import {createPublicKey, verify as verifySignature} from 'node:crypto';
import {verifyCheckpoint} from './audit.mjs';

/**
 * NEO-006 verification-only Ed25519 checkpoint attestation.
 * Never trusts a key supplied by an envelope. Trusted PEM and
 * rollback floor MUST come from independent, authenticated custody.
 */
const plain = v => v !== null && typeof v === 'object' && !Array.isArray(v) &&
  (Object.getPrototypeOf(v) === Object.prototype || Object.getPrototypeOf(v) === null);
const exact = (v, keys) => plain(v) &&
  Object.keys(v).sort().join(',') === [...keys].sort().join(',');
const hex = v => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v);
const denial = reason => Object.freeze({ok:false, reason, authorized:false, anchor:null});

export function checkpointPayload(anchor, namespace) {
  if (!exact(anchor,['count','head']) || !Number.isSafeInteger(anchor.count) ||
      anchor.count < 0 || !hex(anchor.head) ||
      typeof namespace !== 'string' || !/^[A-Za-z0-9_.:-]{3,64}$/.test(namespace))
    throw new TypeError('INVALID_ANCHOR_OR_NAMESPACE');
  return Buffer.from(JSON.stringify(['PALACO-NEO-CHECKPOINT-v1',namespace,anchor.count,anchor.head]),'utf8');
}

export function verifyAttestedCheckpoint(records, envelope, trustedPublicKeyPem, options) {
  if (!exact(envelope,['namespace','anchor','signature']) ||
      !exact(options,['namespace','minimumCount']) ||
      envelope.namespace !== options.namespace ||
      !Number.isSafeInteger(options.minimumCount) || options.minimumCount < 0 ||
      typeof trustedPublicKeyPem !== 'string' || trustedPublicKeyPem.length > 8192)
    return denial('INVALID_TRUST_INPUT');
  let bytes;
  try {
    bytes = checkpointPayload(envelope.anchor,envelope.namespace);
  } catch {
    return denial('INVALID_ANCHOR');
  }
  if (envelope.anchor.count < options.minimumCount) return denial('ROLLBACK_FLOOR');
  if (typeof envelope.signature !== 'string' ||
      !/^[A-Za-z0-9+/]{86}==$/.test(envelope.signature)) return denial('INVALID_SIGNATURE');
  try {
    const signature = Buffer.from(envelope.signature,'base64');
    if (signature.length !== 64 || signature.toString('base64') !== envelope.signature)
      return denial('INVALID_SIGNATURE');
    const key = createPublicKey(trustedPublicKeyPem);
    if (key.asymmetricKeyType !== 'ed25519' || !verifySignature(null,bytes,key,signature))
      return denial('SIGNATURE_MISMATCH');
  } catch {
    return denial('UNTRUSTED_KEY_OR_SIGNATURE');
  }
  if (!verifyCheckpoint(records,envelope.anchor).ok) return denial('CHAIN_MISMATCH');
  return Object.freeze({ok:true,reason:'ATTESTATION_VERIFIED_NOT_AUTHORIZED',
    authorized:false,anchor:Object.freeze({...envelope.anchor})});
}
