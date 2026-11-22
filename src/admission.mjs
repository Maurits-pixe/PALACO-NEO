/** PALACO NEO — fail-closed, side-effect-free admission evaluator. */
export const GO13 = 'HOLD';
export const AUTHORIZATION = 'DENY';
const actions = new Set(['inspect', 'prepare', 'execute', 'publish']);
const phases = new Set(['DRAFT', 'REVIEW', 'READY']);

export function evaluateAdmission(request, snapshot) {
  const deny = (reason) => Object.freeze({decision: 'DENY', reason, next: null});
  if (!request || typeof request !== 'object' || Array.isArray(request) ||
      !snapshot || typeof snapshot !== 'object' || Array.isArray(snapshot)) return deny('INVALID_INPUT');
  if (!actions.has(request.action) || typeof request.id !== 'string' ||
      !/^[A-Za-z0-9_-]{8,64}$/.test(request.id)) return deny('INVALID_REQUEST');
  if (!phases.has(snapshot.phase) || !Number.isSafeInteger(snapshot.revision) || snapshot.revision < 0 ||
      !Array.isArray(snapshot.seenIds) || snapshot.seenIds.some(id => typeof id !== 'string') ||
      new Set(snapshot.seenIds).size !== snapshot.seenIds.length) return deny('INVALID_SNAPSHOT');
  if (request.expectedRevision !== snapshot.revision) return deny('STALE_REVISION');
  if (snapshot.seenIds.includes(request.id)) return deny('REPLAY');
  if (request.action === 'execute' || request.action === 'publish') return deny('GO13_HOLD');
  if (request.action === 'prepare' && snapshot.phase !== 'REVIEW') return deny('REVIEW_REQUIRED');
  if (request.action === 'inspect') return Object.freeze({decision: 'READ_ONLY', reason: 'INSPECTION', next: null});
  const next = Object.freeze({phase: 'READY', revision: snapshot.revision + 1,
    seenIds: Object.freeze([...snapshot.seenIds, request.id])});
  return Object.freeze({decision: 'PREPARED', reason: 'NO_EXECUTION_AUTHORITY', next});
}
