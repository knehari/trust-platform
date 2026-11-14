/** A claim the server built for an officer to sign (ADR-0028, ADR-0029). */
export interface SignedClaim {
  decision: string;
  claim: string;
  key_id: string;
  issued_at: string;
}

const PREFIXES = {
  revocation: 'trust-platform/revocation-authorization/v1;',
  void: 'trust-platform/void-authorization/v1;',
} as const;

export type ClaimKind = keyof typeof PREFIXES;

/** What the claim must name: the authority, application, record and serial. */
export interface ClaimSubject {
  caId: string;
  applicationId: string;
  /** Revocation request ID, for revocation decisions. */
  revocationId?: string;
  /** Lowercase hex of the serial, when the console knows it. */
  serialHex?: string;
}

/**
 * Checks that a claim is of the expected kind and names exactly this record,
 * before the officer is asked to sign it. The server stays the authority: the
 * signer rebuilds and verifies the claim before it lists anything on a CRL.
 */
export function signedClaimMatches(value: Partial<SignedClaim>, kind: ClaimKind, decision: string,
  subject: ClaimSubject): value is SignedClaim {
  if (typeof value.claim !== 'string' || typeof value.key_id !== 'string' || typeof value.issued_at !== 'string'
    || value.decision !== decision || /[\r\n]/u.test(value.claim) || value.claim.length > 4000) return false;
  const claim = value.claim;
  const head = kind === 'revocation'
    ? `${PREFIXES.revocation}decision=${decision};ca=${subject.caId};application=${subject.applicationId};revocation=${subject.revocationId ?? ''};`
    : `${PREFIXES.void}ca=${subject.caId};application=${subject.applicationId};`;
  return claim.startsWith(head)
    && (!subject.serialHex || claim.includes(`;serial=${subject.serialHex.toLowerCase()};`))
    && claim.endsWith(`;key=${value.key_id};issued_at=${value.issued_at}`);
}
