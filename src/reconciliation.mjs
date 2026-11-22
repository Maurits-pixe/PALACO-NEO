import {verifyAudit} from './audit.mjs';

/**
 * NEO-005 — deterministic post-crash classification. No I/O or authorization.
 * The anchors MUST be supplied from independent, trusted custody.
 * The proposed anchor MUST correspond to a proposal captured BEFORE the write.
 */
const shape = a => a !== null && typeof a === 'object' && !Array.isArray(a) &&
  (Object.getPrototypeOf(a) === Object.prototype || Object.getPrototypeOf(a) === null) &&
  Object.keys(a).sort().join(',') === 'count,head' &&
  Number.isSafeInteger(a.count) && a.count >= 0 &&
  typeof a.head === 'string' && /^[0-9a-f]{64}$/.test(a.head);
const reply = (status, reason) => Object.freeze({status,reason,authorized:false});

export function classifyUncertainCommit(records, before, proposed) {
  if (!shape(before) || !shape(proposed) || !Array.isArray(records))
    return reply('HOLD','INVALID_INPUT');
  if (before.count >= Number.MAX_SAFE_INTEGER || proposed.count !== before.count + 1 ||
      proposed.head === before.head)
    return reply('HOLD','INVALID_TRANSITION');
  const audit = verifyAudit(records);
  if (!audit.ok) return reply('HOLD','CORRUPT_CHAIN');
  if (audit.count === before.count && audit.head === before.head)
    return reply('NOT_COMMITTED','MATCHES_PREVIOUS_ANCHOR');
  if (audit.count === proposed.count && audit.head === proposed.head) {
    // Linkage proves the candidate's immediate predecessor is the trusted old head.
    const added = records.at(-1);
    if (added?.previousHash !== before.head || added.sequence !== proposed.count)
      return reply('HOLD','UNLINKED_PROPOSAL');
    return reply('COMMITTED','MATCHES_PROPOSED_ANCHOR');
  }
  return reply('HOLD','UNEXPLAINED_STATE');
}
