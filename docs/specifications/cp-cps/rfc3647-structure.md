# CP and CPS generation — RFC 3647 skeleton

Generation is template-driven from verified CA policy data plus explicit human declarations. Publication requires approval; the engine must not invent operational procedures.

## Sections (RFC 3647 framework)
1. Introduction
2. Publication and Repository Responsibilities
3. Identification and Authentication
4. Certificate Life-Cycle Operational Requirements
5. Facility, Management, and Operational Controls
6. Technical Security Controls
7. Certificate, CRL, and OCSP Profiles
8. Compliance Audit and Other Assessments
9. Other Business and Legal Matters

For each provision maintain: `section`, `origin (config|attestation|manual)`, `source_version`, `evidence_uri`, `verified_status`, `owner`, `visibility`, `last_reviewed`.

Draft from CA-configurable profile settings includes cryptographic algorithms, permitted SANs, issuer, validity, revocation endpoints, policy OIDs and audit event categories. Identity-proofing procedures, trusted-role staffing, physical-site controls, contract details and external assessments **must** be explicitly entered and verified by operators.

## Publication invariants
- CP and CPS remain distinct, with a clear mapping and effective dates.
- No automatic publication of unreviewed changes.
- Safe rollback creates a **new published revision**.
- References to policy OIDs are stable, non-default and tied to exact CA issuance profiles.
- Automatic regeneration must not modify archived, previously approved editions.
