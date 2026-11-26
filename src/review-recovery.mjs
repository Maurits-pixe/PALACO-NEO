import {verifyReviewLedger, REVIEW_GENESIS} from './review-ledger.mjs';

/**
 * NEO-011: pure review-ledger recovery classifier.
 * Expects independently authenticated before-head/count and pre-write proposal.
 * No filesystem operations, retries, lock release, or execution authority.
 */
const object = x => x !== null && typeof x === 'object' && !Array.isArray(x) &&
  (Object.getPrototypeOf(x) === Object.prototype || Object.getPrototypeOf(x) === null);
const exact = (x, keys) => object(x) &&
  Object.keys(x).sort().join(',') === [...keys].sort().join(',');
const digest = x => typeof x === 'string' && /^[0-9a-f]{64}$/.test(x);
const nonnegative = x => Number.isSafeInteger(x) && x >= 0;
const reject = reason => Object.freeze({status:'HOLD', reason, authorized:false});
const status = (s,r) => Object.freeze({status:s,reason:r,authorized:false});

export function classifyReviewRecovery(entries, before, proposal) {
  if (!Array.isArray(entries) || !exact(before,['count','head']) ||
      !nonnegative(before.count) || !digest(before.head) ||
      !exact(proposal,['entry','head']) ||
      !object(proposal.entry) || !digest(proposal.head))
    return reject('INVALID_INPUT');
  if (before.count >= 100000 || proposal.entry.sequence !== before.count + 1 ||
      proposal.entry.previousHash !== before.head ||
      proposal.entry.hash !== proposal.head || proposal.head === before.head)
    return reject('INVALID_PROPOSAL');
  const chain = verifyReviewLedger(entries);
  if (!chain.ok) return reject('BROKEN_LEDGER');
  if (chain.count === before.count && chain.head === before.head)
    return status('NOT_COMMITTED','MATCHES_PREWRITE_HEAD');
  if (chain.count !== before.count + 1 || chain.head !== proposal.head)
    return reject('UNEXPECTED_STATE');
  const prefix = verifyReviewLedger(entries.slice(0,before.count), before.head);
  if (!prefix.ok) return reject('UNTRUSTED_PREWRITE_PREFIX');
  const last = entries[before.count];
  if (!last || last.hash !== proposal.entry.hash ||
      JSON.stringify(last) !== JSON.stringify(proposal.entry))
    return reject('PROPOSAL_MISMATCH');
  return status('COMMITTED','MATCHES_PREWRITE_PROPOSAL');
}

/** Compare-and-swap preflight for cooperative callers only.
 * The actual store MUST atomically compare head/count under an exclusive lock.
 */
export function classifyReviewWritePreflight(entries, trustedBefore) {
  if (!Array.isArray(entries) || !exact(trustedBefore,['count','head']) ||
      !nonnegative(trustedBefore.count) || !digest(trustedBefore.head))
    return reject('INVALID_INPUT');
  const chain = verifyReviewLedger(entries,trustedBefore.head);
  if (!chain.ok || chain.count !== trustedBefore.count)
    return reject('CONCURRENT_CHANGE_OR_CORRUPTION');
  return status('MATCH','PREFLIGHT_ONLY_NOT_ATOMIC');
}

export const REVIEW_INITIAL_POSITION = Object.freeze({count:0,head:REVIEW_GENESIS});
