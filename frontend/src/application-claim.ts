/** A decision claim on a certificate request (ADR-0028), as the API returns it. */
export interface ApplicationClaim {
  decision: 'approve' | 'reject';
  claim: string;
  key_id: string;
  issued_at: string;
}

export interface ClaimedApplication {
  application_id: string;
  subject_cn: string;
  dns_names: string[];
  validity_days: number;
}

const CLAIM_PATTERN = /^trust-platform\/issuance-authorization\/v1;decision=(approve|reject);[^\r\n]{1,3900}$/u;

/**
 * Checks that a claim names this decision, authority and application with
 * the facts the officer sees, before the officer is asked to sign it.
 */
export function claimMatches(value: Partial<ApplicationClaim>, decision: ApplicationClaim['decision'], caId: string,
  item: ClaimedApplication): value is ApplicationClaim {
  return value.decision === decision && typeof value.claim === 'string' && CLAIM_PATTERN.test(value.claim)
    && value.claim.includes(`;decision=${decision};ca=${caId};application=${item.application_id};`)
    && value.claim.includes(`;subject_cn=${item.subject_cn};dns_names=${item.dns_names.join(',')};validity_days=${item.validity_days};`)
    && typeof value.key_id === 'string' && typeof value.issued_at === 'string'
    && value.claim.endsWith(`;key=${value.key_id};issued_at=${value.issued_at}`);
}
