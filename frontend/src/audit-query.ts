import { normalizeLiteralPrefix } from './literal-prefix.ts';

interface AuditQueryInput {
  from: string;
  until: string;
  eventType: string;
  decision: string;
  policyVersion: string;
}

type AuditQueryResult = { query: string; error: null } | { query: null; error: string };

// The API trims Unicode whitespace, then limits exact values by UTF-8 bytes.
export function prepareAuditQuery(input: AuditQueryInput): AuditQueryResult {
  if (input.from && input.until && input.from >= input.until) {
    return { query: null, error: 'The end date must be after the start date.' };
  }
  const params = new URLSearchParams();
  if (input.from) params.set('from', `${input.from}T00:00:00.000Z`);
  if (input.until) params.set('until', `${input.until}T00:00:00.000Z`);
  for (const [name, raw, label] of [
    ['event_type', input.eventType, 'Event type'],
    ['decision', input.decision, 'Decision'],
    ['policy_version', input.policyVersion, 'Policy version'],
  ] as const) {
    const value = normalizeLiteralPrefix(raw);
    if (new TextEncoder().encode(value).length > 128 || [...value].some(char => /\p{Cc}/u.test(char))) {
      return { query: null, error: `${label} must be at most 128 UTF-8 bytes without control characters.` };
    }
    if (value) params.set(name, value);
  }
  return { query: params.toString(), error: null };
}
