# ADR-0004 — Policy documents and audit evidence are governed objects

**Status:** Proposed — 2026-10-11

## Context

Security-sensitive PKI operations must support audit readiness from the first architectural increment. CP/CPS generation must not invent legal, physical or procedural statements from configuration alone. Standards vary with jurisdiction, audit scope and edition.

## Decision

1. Maintain typed, versioned objects: `PolicyDocument`, `PolicyClause`, `PolicyOidBinding`, `Approval`, `Publication`, `ControlRequirement`, `EvidenceReference`, `Finding`, `Attestation`.
2. Treat runtime CA configuration as **observed evidence**, not a complete attestation. Require owner-supplied controls and reviewer approval for external claims.
3. Store semantic change events and signed/digested immutable revision manifests. Publication is a distinct approved state machine (DRAFT -> REVIEW -> APPROVED -> PUBLISHED -> SUPERSEDED), never write in-place.
4. Link each issued certificate to the policy version/OID in force. No automatic retroactive rewriting.
5. Allow private/air-gapped publication destinations with controlled redaction and reproducible archival export.
6. Bind standard IDs to exact editions and applicability sets; report UNKNOWN / NOT_APPLICABLE / GAP / VERIFIED separately.
7. Separate auditor read-only permissions from policy authors, approvers, CA signers and system administrators.
8. Externally anchored integrity and real-world controls are required for meaningful attestations; PostgreSQL triggers alone are not WORM.

## Consequences

Adds governance and audit entities into future migrations. Source code will implement a **lab-only policy OID validation** early, but full CP/CPS and audit engines come with CLM/control plane.

## Security

Information about sensitive internal practices may itself be confidential; exported public CPS must follow disclosure policy and explicit approval. Retain evidence per legal jurisdiction and enterprise retention policies.

## Regulatory boundary

Architecture *supports* eIDAS/ETSI/ISO audit preparation, but software does not grant QTSP status. External accredited conformity-assessment and supervisory steps remain mandatory where applicable.
