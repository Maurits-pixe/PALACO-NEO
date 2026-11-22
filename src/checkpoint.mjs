import {appendAudit, verifyCheckpoint, GENESIS_HASH} from './audit.mjs';

/**
 * NEO-003: pure compare-and-propose protocol.
 * No disk, network, lock, signature, authorization, or atomic durable commit.
 * The caller MUST supply a separately trusted anchor.
 */
const plain = value => value !== null && typeof value === 'object' &&
  !Array.isArray(value) && (Object.getPrototypeOf(value) === Object.prototype ||
  Object.getPrototypeOf(value) === null);
const validAnchor = anchor => plain(anchor) &&
  Object.keys(anchor).sort().join(',') === 'count,head' &&
  Number.isSafeInteger(anchor.count) && anchor.count >= 0 &&
  typeof anchor.head === 'string' && /^[a-f0-9]{64}$/.test(anchor.head);

const reject = reason => Object.freeze({ok:false, reason, candidate:null});
export const INITIAL_ANCHOR = Object.freeze({count:0,head:GENESIS_HASH});

export function recoverCheckpoint(records, trustedAnchor) {
  if (!validAnchor(trustedAnchor)) return reject('INVALID_TRUSTED_ANCHOR');
  if (!Array.isArray(records)) return reject('INVALID_RECORDS');
  const verification = verifyCheckpoint(records, trustedAnchor);
  if (!verification.ok) return reject('RECOVERY_REFUSED');
  return Object.freeze({ok:true, reason:'VERIFIED_AGAINST_ANCHOR',
    candidate:Object.freeze({count:trustedAnchor.count,head:trustedAnchor.head})});
}

export function proposeCheckpoint(records, trustedAnchor, event) {
  const recovery = recoverCheckpoint(records, trustedAnchor);
  if (!recovery.ok) return recovery;
  let appended;
  try {
    appended = appendAudit(records, event);
  } catch {
    return reject('INVALID_EVENT_OR_CHAIN');
  }
  const candidateRecords = Object.freeze([...records, appended]);
  const candidateAnchor = Object.freeze({count:candidateRecords.length,head:appended.hash});
  return Object.freeze({ok:true, reason:'PROPOSAL_ONLY_NO_AUTHORITY',
    candidate:Object.freeze({records:candidateRecords,anchor:candidateAnchor})});
}

/** Evaluate an externally supplied commit result against a trusted candidate.
 * This never performs persistence or establishes the trustworthiness of the candidate.
 */
export function reconcileCheckpoint(records, independentlyTrustedAnchor, proposedAnchor) {
  if (!validAnchor(proposedAnchor)) return reject('INVALID_PROPOSED_ANCHOR');
  const verified = recoverCheckpoint(records, independentlyTrustedAnchor);
  if (!verified.ok) return verified;
  if (proposedAnchor.count !== independentlyTrustedAnchor.count ||
      proposedAnchor.head !== independentlyTrustedAnchor.head)
    return reject('ANCHOR_CONFLICT');
  return Object.freeze({ok:true,reason:'MATCHED_ONLY',candidate:verified.candidate});
}
