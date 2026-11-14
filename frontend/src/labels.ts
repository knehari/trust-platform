// Human-readable labels for the codes the API returns. Display only: the raw
// code stays available next to each label, and nothing here changes what is
// recorded or decided.

export type EventCategory = 'certificate' | 'request' | 'signing' | 'crl' | 'profile' | 'authority' | 'policy' | 'other';

const STATUS_WORDS: Record<string, string> = {
  CRL: 'CRL', CSR: 'CSR', CA: 'CA', SAN: 'SAN', DNS: 'DNS', ID: 'ID',
};

const STATUS_OVERRIDES: Record<string, string> = {
  allow: 'Allowed',
  deny: 'Denied',
  NO_CRL: 'No CRL yet',
  RENEWAL_DUE: 'Renewal due',
  RECONCILIATION_REQUIRED: 'Needs reconciliation',
  KEY_ATTESTED: 'Key attested',
  CSR_VALIDATED: 'CSR validated',
  SERIAL_RESERVED: 'Serial reserved',
  REVOCATION_REQUESTED: 'Revocation requested',
};

/** `KEY_ATTESTED` → `Key attested`; `allow` → `Allowed`. */
export function humanizeStatus(code: string): string {
  code = String(code ?? '');
  if (STATUS_OVERRIDES[code]) return STATUS_OVERRIDES[code];
  const words = code.split(/[_\s]+/u).filter(Boolean);
  if (words.length === 0) return code;
  return words.map((word, index) => {
    const upper = word.toUpperCase();
    if (STATUS_WORDS[upper]) return STATUS_WORDS[upper];
    const lower = word.toLowerCase();
    return index === 0 ? lower.charAt(0).toUpperCase() + lower.slice(1) : lower;
  }).join(' ');
}

const CATEGORY_PREFIXES: [string, EventCategory][] = [
  ['certificate.revocation.', 'certificate'], ['certificate.application.', 'request'], ['certificate.', 'certificate'],
  ['application.', 'request'], ['request.', 'request'], ['revocation.', 'certificate'],
  ['signing.', 'signing'], ['crl.', 'crl'],
  ['profile.', 'profile'], ['draft.', 'profile'], ['revision.', 'profile'],
  ['ca.', 'authority'], ['trust.', 'authority'],
  ['policy.', 'policy'], ['cp_cps.', 'policy'],
];

const EVENT_LABELS: Record<string, string> = {
  'request.received': 'Request received',
  'request.transition': 'Request state changed',
  'signing.intent': 'Signing intent recorded',
  'signing.result': 'Signing result recorded',
  'signing.collector.evidence': 'Signing evidence collected',
  'signing.reconciliation.observation': 'Reconciliation observation',
  'signing.reconciliation.proposed': 'Reconciliation proposed',
  'signing.reconciliation.reviewed': 'Reconciliation reviewed',
  'certificate.signed': 'Certificate signed',
  'certificate.revoked': 'Certificate revoked',
  'certificate.revocation.requested': 'Revocation requested',
  'certificate.revocation.rejected': 'Revocation rejected',
  'certificate.application.submitted': 'Application submitted',
  'certificate.application.approved': 'Application approved',
  'certificate.application.rejected': 'Application rejected',
  'certificate.application.issuance_started': 'Issuance started',
  'crl.prepared': 'CRL prepared',
  'crl.published': 'CRL published',
  'crl.reconciliation_required': 'CRL needs reconciliation',
  'ca.proposed': 'CA proposed',
  'ca.certificate_registered': 'CA certificate registered',
  'ca.approval': 'CA approval signed',
  'ca.rejection': 'CA rejection signed',
  'ca.activation': 'CA activated',
  'ca.suspension': 'CA suspended',
  'ca.reactivation': 'CA reactivated',
  'ca.retirement': 'CA retired',
  'ca.change_requested': 'CA change requested',
  'ca.change_approval': 'CA change approved',
  'ca.change_rejection': 'CA change rejected',
  'profile.draft.created': 'Profile draft created',
  'profile.draft.submitted': 'Profile draft submitted',
  'profile.draft.approval': 'Profile approval signed',
  'profile.draft.rejection': 'Profile rejection signed',
  'profile.revision.activation': 'Profile revision activated',
  'profile.revision.retirement': 'Profile revision retired',
};

export interface EventDescription { label: string; category: EventCategory; code: string }

/** A label and a category for an audit event type; unknown types stay readable. */
export function describeEvent(type: string): EventDescription {
  type = String(type ?? '');
  const category = CATEGORY_PREFIXES.find(([prefix]) => type.startsWith(prefix))?.[1] ?? 'other';
  if (EVENT_LABELS[type]) return { label: EVENT_LABELS[type], category, code: type };
  const parts = type.split('.').filter(Boolean);
  const tail = parts.length > 1 ? parts.slice(1) : parts;
  const label = humanizeStatus(tail.join(' ').replaceAll('_', ' ')) || type;
  return { label, category, code: type };
}

export const CATEGORY_LABELS: Record<EventCategory, string> = {
  certificate: 'Certificate', request: 'Request', signing: 'Signing', crl: 'CRL',
  profile: 'Profile', authority: 'Authority', policy: 'Policy', other: 'Other',
};

export type Outcome =
  | { kind: 'decision'; status: 'allow' | 'deny' }
  | { kind: 'transition'; from: string; to: string }
  | { kind: 'reference'; status: string; reference: string }
  | { kind: 'result'; status: string }
  | { kind: 'text'; text: string };

/**
 * The audit `decision` column holds several shapes: an authorization decision
 * (`allow`), a state transition (`SIGNING -> SIGNED`), a result with a
 * reference (`created:<uuid>`) or a single result word (`persisted`).
 */
export function describeOutcome(decision: string): Outcome {
  const value = String(decision ?? '').trim();
  if (value === 'allow' || value === 'deny') return { kind: 'decision', status: value };
  const transition = /^([A-Z][A-Z0-9_]*)\s*->\s*([A-Z][A-Z0-9_]*)$/u.exec(value);
  if (transition) return { kind: 'transition', from: transition[1], to: transition[2] };
  const reference = /^([a-z][a-z0-9_]*):(\S.*)$/u.exec(value);
  if (reference) return { kind: 'reference', status: reference[1], reference: reference[2] };
  if (/^[A-Za-z][A-Za-z0-9_]*$/u.test(value)) return { kind: 'result', status: value };
  return { kind: 'text', text: value };
}

/** `5 min ago`, `in 3 h`, `yesterday`; falls back to the date after a week. */
export function relativeTime(value: string, now: Date): string {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return value;
  const seconds = Math.round((date.valueOf() - now.valueOf()) / 1000);
  const past = seconds <= 0;
  const abs = Math.abs(seconds);
  const say = (amount: number, unit: string) => past ? `${amount} ${unit} ago` : `in ${amount} ${unit}`;
  if (abs < 45) return past ? 'just now' : 'in a moment';
  if (abs < 3600) return say(Math.max(1, Math.round(abs / 60)), 'min');
  if (abs < 86_400) return say(Math.round(abs / 3600), 'h');
  const days = Math.round(abs / 86_400);
  if (days === 1) return past ? 'yesterday' : 'tomorrow';
  if (days < 7) return say(days, 'days');
  return date.toLocaleDateString();
}

export type OutcomeGroup = 'allowed' | 'denied' | 'attention' | 'other';

/** Coarse outcome families used by the audit quick filters. */
export function outcomeGroup(decision: string): OutcomeGroup {
  const outcome = describeOutcome(decision);
  if (outcome.kind === 'decision') return outcome.status === 'allow' ? 'allowed' : 'denied';
  if (outcome.kind === 'transition') return /RECONCILIATION|FAILED|REJECTED/u.test(outcome.to) ? 'attention' : 'other';
  return 'other';
}

/** One plain sentence on what an audit outcome means. */
export function explainOutcome(decision: string): string {
  const outcome = describeOutcome(decision);
  switch (outcome.kind) {
    case 'decision': return outcome.status === 'allow' ? 'The platform authorized this operation under the recorded policy.' : 'The platform refused this operation; nothing was changed by it.';
    case 'transition': return `The request moved from “${humanizeStatus(outcome.from)}” to “${humanizeStatus(outcome.to)}”.${outcome.to === 'RECONCILIATION_REQUIRED' ? ' The signing outcome was ambiguous: reconcile it before signing again.' : ''}`;
    case 'reference': return `Result “${humanizeStatus(outcome.status)}”, referencing ${outcome.reference}.`;
    case 'result': return `Recorded result: “${humanizeStatus(outcome.status)}”.`;
    default: return `Recorded outcome: ${outcome.text || 'none'}.`;
  }
}
