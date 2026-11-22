import {createPublicKey,verify as edVerify} from 'node:crypto';
import {compareRecoveryEvidence} from './recovery-evidence.mjs';

/**
 * NEO-018 — offline Ed25519 verification of recovery receipts.
 * The pinned signer, challenge and trusted before-position are EXTERNAL trust.
 * No signing key, durable nonce registry, authorization or execution.
 */
const plain=x=>x!==null && typeof x==='object' && !Array.isArray(x) &&
  (Object.getPrototypeOf(x)===Object.prototype || Object.getPrototypeOf(x)===null);
const exact=(x,keys)=>plain(x) && Object.keys(x).sort().join(',')===[...keys].sort().join(',');
const hex=x=>typeof x==='string' && /^[0-9a-f]{64}$/.test(x);
const ident=x=>typeof x==='string' && /^[A-Za-z0-9_.:-]{3,64}$/.test(x);
const position=x=>exact(x,['count','head']) && Number.isSafeInteger(x.count) &&
 x.count>=0 && x.count<100000 && hex(x.head);
const deny=reason=>Object.freeze({ok:false,reason,authorized:false,receipt:null});
const validReceipt=r=>exact(r,['schema','status','before','proposedHead','observed','receiptDigest']) &&
 r.schema==='NEO-017-v1' && ['COMMITTED','NOT_COMMITTED'].includes(r.status) &&
 position(r.before) && position(r.observed) && hex(r.proposedHead) && hex(r.receiptDigest) &&
 compareRecoveryEvidence({ok:true,authorized:false,receipt:r},
  {ok:true,authorized:false,receipt:r}).status==='STABLE';

export function recoveryAttestationPayload(namespace,challenge,signerId,receipt) {
  if(!ident(namespace) || !hex(challenge) || !ident(signerId) || !validReceipt(receipt))
    throw new TypeError('INVALID_ATTESTATION_PAYLOAD');
  return Buffer.from(JSON.stringify(['PALACO-NEO-RECOVERY-ATTESTATION-v1',
    namespace,challenge,signerId,receipt.schema,receipt.status,
    receipt.before.count,receipt.before.head,receipt.proposedHead,
    receipt.observed.count,receipt.observed.head,receipt.receiptDigest]),'utf8');
}

/**
 * A challenge must be freshly issued and consumed through independently
 * authenticated custody, otherwise an old signed statement can be replayed.
 */
export function verifyRecoveryAttestation(envelope,trust) {
  if(!exact(envelope,['namespace','challenge','signerId','receipt','signature']) ||
     !exact(trust,['namespace','expectedChallenge','signerId','status','publicKeyPem','trustedBefore']) ||
     !ident(trust.namespace) || !ident(trust.signerId) ||
     !hex(trust.expectedChallenge) || !position(trust.trustedBefore) ||
     !['ACTIVE','REVOKED'].includes(trust.status) ||
     typeof trust.publicKeyPem!=='string' || trust.publicKeyPem.length>8192)
    return deny('INVALID_TRUST_INPUT');
  if(envelope.namespace!==trust.namespace || envelope.signerId!==trust.signerId)
    return deny('IDENTITY_OR_NAMESPACE_MISMATCH');
  if(trust.status!=='ACTIVE') return deny('REVOKED_SIGNER');
  if(envelope.challenge!==trust.expectedChallenge) return deny('CHALLENGE_MISMATCH');
  if(!validReceipt(envelope.receipt)) return deny('INVALID_RECEIPT');
  if(envelope.receipt.before.count!==trust.trustedBefore.count ||
     envelope.receipt.before.head!==trust.trustedBefore.head)
    return deny('TRUSTED_BEFORE_CONFLICT');
  if(typeof envelope.signature!=='string' ||
     !/^[A-Za-z0-9+/]{86}==$/.test(envelope.signature))
    return deny('INVALID_SIGNATURE');
  try {
    const signature=Buffer.from(envelope.signature,'base64');
    if(signature.length!==64 || signature.toString('base64')!==envelope.signature)
      return deny('INVALID_SIGNATURE');
    const key=createPublicKey(trust.publicKeyPem);
    const bytes=recoveryAttestationPayload(envelope.namespace,envelope.challenge,
      envelope.signerId,envelope.receipt);
    if(key.asymmetricKeyType!=='ed25519' || !edVerify(null,bytes,key,signature))
      return deny('SIGNATURE_MISMATCH');
  } catch {return deny('SIGNATURE_OR_KEY_FAILURE');}
  return Object.freeze({ok:true,reason:'SIGNED_RECOVERY_EVIDENCE_ONLY',
    authorized:false,receipt:Object.freeze({...envelope.receipt})});
}
