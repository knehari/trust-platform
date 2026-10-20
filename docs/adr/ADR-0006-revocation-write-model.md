# ADR-0006 — Least-privilege write model and signed double control for certificate status changes

**Status:** Proposed · 2026-10-20 · requires human security review before any implementation  
**Scope:** Migrations 0014–0017 (revocation lifecycle and CRL pipeline) and any future status-change API. Laboratory only; no production approval, G0 clearance or CA qualification is implied.  
**Related:** ADR-0002 (signing and durable state), ADR-0003 (authenticated identity), ADR-0005 (Rust management control plane), `docs/security/v1-6-approval-challenge-replay-design.md`, spec `docs/superpowers/specs/2026-10-18-revocation-crl-design.md` §6.

## Context

The lab revocation slice enforces maker-checker in PL/pgSQL. Two gaps remain, and both must be closed before a non-ephemeral issuer or an exposed API.

1. **Direct writes bypass maker-checker.** Every function is `SECURITY INVOKER`. A role that can call `approve_certificate_status_change` therefore needs `INSERT`/`UPDATE`/`DELETE` on `revocation` and `certificate_status_change`. With these grants it can insert a revocation row or an `APPROVED` change directly, without a second actor. The guard triggers and CHECKs (irreversibility, encodable dates, legal transitions) still hold; the two-actor rule does not. The same applies to `crl_publication`, where `record_crl_intent` and `store_verified_crl` are the only intended writers.
2. **Double control is textual, not cryptographic.** The database compares `(issuer, subject)` strings and requires them to differ, and to hold a `revocation_officer_grant`. `AGENTS.md` requires double control to rest on *cryptographically distinct signer keys as well as separately authenticated actors, not different textual key IDs alone*. The current slice does not meet that requirement. This is a known deviation from repository policy, recorded here and in spec §6.

Moving functions to `SECURITY DEFINER` alone does not solve (2): whoever may `EXECUTE` the approve function can still pass any checker identity string. The database cannot authenticate an OIDC subject.

## Decision (proposed)

### A. Database privilege model

- A dedicated **owner role** (`NOLOGIN`) owns `revocation`, `certificate_status_change`, `revocation_officer_grant`, `crl_publication`, `crl_entry_snapshot` and the functions of 0014–0017. Migrations run as this owner (or a migration role that is a member of it). No application login is a member.
- Every state-changing function becomes `SECURITY DEFINER`, with `SET search_path = pg_catalog, public` (or a dedicated schema) and schema-qualified references. `EXECUTE` is revoked from `PUBLIC` and granted per role. Functions validate every argument as today; input errors keep their SQLSTATEs.
- Separate **NOLOGIN capability roles**, each granted to a distinct service login:
  - `trust_revocation_officer_api` gets `EXECUTE` on `propose_`, `approve_`, `reject_` and `withdraw_certificate_status_change`, plus `certificate_status`;
  - `trust_crl_signer` gets `EXECUTE` on `reserve_crl`, `crl_snapshot_entries`, `record_crl_intent`, `mark_crl_uncertain` and `store_verified_crl`;
  - `trust_crl_operator` gets `EXECUTE` on `crl_due`, `overdue_status_changes`, `abandon_stale_crl_reservations` and `quarantine_stale_crl_intents`.
  None of them gets table DML. The management reader (`trust_api_reader`, 0012/0013) gets read-only views only.
- `revocation_officer_grant` stays server-owned: no API write path, provisioned by an operator procedure and audited.
- Tests prove the model from each login: direct `INSERT`/`UPDATE`/`DELETE`/`TRUNCATE` on every protected table fails with 42501; each function is callable only by its intended role; and a `search_path` object planted by a caller is not resolved.

### B. Signed, key-distinct double control

- `revocation_officer_grant` gains the officer's pinned **P-256 public key**, normalised to uncompressed SEC1, together with its SHA-256 fingerprint and validity window. A grant without a key cannot sign.
- `propose_` and `approve_` take a **canonical status-change claim**: CA id, serial, action, reason, invalidity date, change id, policy edition, and a one-time challenge. They also take the officer's ECDSA signature over that claim.
- The **Rust CA core** verifies both signatures before calling the database. It reuses `policy_decisions::verify_dual_approval`, which already rejects the same key under another id or another SEC1 encoding.
- The database **cannot verify ECDSA** (as noted in 0009). It records the claim digest, both signatures and both key fingerprints, and enforces through CHECKs and the grant join that:
  - the fingerprints differ;
  - each fingerprint belongs to the signing officer's current grant;
  - the claim digest matches the stored change fields.
  A direct call with a forged signature cannot be ruled out by SQL alone. That is why `EXECUTE` on `approve_` is restricted to the service login (part A), and why the signature is re-verifiable offline from the stored evidence.
- Challenges follow the v1.6 design (CSPRNG nonce, digest persisted, consumed once in the approving transaction), so a signed approval cannot be replayed onto another change.
- Authentication of the officers (OIDC with step-up) remains with the identity adapter (ADR-0003/0005). The key binds the decision; the token binds the session. Both are required.

### C. Housekeeping

`abandon_stale_crl_reservations` and `quarantine_stale_crl_intents` (0016) run from a scheduled job under `trust_crl_operator`, with an alert when either returns a non-zero count. A lab version of the job exists (`crl_housekeeping` example, `docs/operations/lab-crl-housekeeping.md`); it does not yet run under that role. Since 0017 a stale reservation cannot be signed, so the sweep is hygiene and evidence, not a safety control.

## Alternatives considered

- **Per-officer PostgreSQL logins (`session_user` as identity):** strong in-database authentication, but it couples human identity lifecycle to database roles and needs a login per officer and per environment. It also does not fit OIDC step-up. It could be revisited for an air-gapped deployment.
- **`SECURITY DEFINER` only (part A without B):** closes direct DML. It still lets the service, or anyone holding its credentials, assert two textual identities, which violates `AGENTS.md`. It is acceptable only as an intermediate step and must not be described as double control.
- **Verifying signatures inside PostgreSQL (extension):** adds native code to the database trust base and duplicates the Rust verification path. It is rejected for the lab.

## Consequences and verification gates

- Migration 0018+ would change function security and ownership. Existing lab databases need the owner-role migration, which is a breaking change for anyone calling the functions as `trust_ci`. The CI fixtures must create the service logins.
- The revocation API (not yet built) must call through the Rust core so that signatures are verified before the database call.
- Required evidence before implementation is accepted:
  - a threat model update in `docs/security/threat-model.md`;
  - RED/GREEN tests for each privilege and signature rule, including the same key under two ids, compressed versus uncompressed, a replayed challenge, a swapped maker/checker, a revoked grant mid-flow and direct DML as each login. The direct writes found by review that must be impossible from every service login are: `INSERT` into `revocation` (revoke without a change), `DELETE` of a hold (release without a change), `INSERT` into `crl_entry_snapshot` for an existing CRL (fake coverage), and `INSERT` of a `STORED` row into `crl_publication` (skips intent and verification);
  - concurrency tests for challenge consumption;
  - an independent review of the `SECURITY DEFINER` functions (search_path, dynamic SQL, error leakage).
- Until this ADR is accepted and implemented, the lab slice's maker-checker must be described as **textual two-actor control with a single trusted service**, not as cryptographic double control.
