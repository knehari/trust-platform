# ADR-0002 — Durable issuance around external signing

Status: Accepted · 2026-10-13 (supersedes the 2026-10-11 proposal)
Related: ADR-0004, `docs/architecture/issuance-state-machine.md`, `migrations/`

## Context
External signing (HSM or software provider) and PostgreSQL commits cannot be one
atomic transaction. A crash, timeout or session loss can occur after the
provider produced a signature but before the result was persisted.

Two facts constrain recovery:
1. A PKCS#11 HSM keeps no queryable record of what it signed: we cannot ask it
   "did you sign X?".
2. ECDSA (hedged) and ML-DSA (hedged, the default) signatures are not
   deterministic: re-signing and comparing signatures is impossible, and
   re-signing the same TBS produces a **second valid certificate** with the same
   serial number.

## Decision
### Durable intent before signing
Before calling the provider, the core commits a **signing intent** containing:
issuer ID, reserved serial, policy version, authorization ID, idempotency key,
algorithm, the complete DER TBSCertificate and its SHA-256 digest
(`tbs_sha256`). The provider authorization is bound to `tbs_sha256` (ADR-0004).

### Protocol
1. `SERIAL_RESERVED`: insert serial under `UNIQUE (issuer_id, serial)`; the row is
   never deleted.
2. `SIGNING`: commit the intent (TBS + digest), then call `sign`.
3. On success: verify the signature (sign-then-verify), assemble the
   certificate, commit `SIGNED` with the certificate DER in one transaction.
4. On `Rejected` / `Failed` (definitive, nothing signed): `FAILED_RETRYABLE` or
   `FAILED_FINAL`. A retry reserves a **new serial**; the old one is `VOIDED`.
5. On `Indeterminate` or crash while `SIGNING`: `RECONCILIATION_REQUIRED`.

### Reconciliation rule: burn and revoke
For an intent in `RECONCILIATION_REQUIRED`:
1. If a signed certificate matching `tbs_sha256` was persisted by any path
   (e.g. response arrived but the state update failed), verify it and complete
   to `SIGNED`.
2. Otherwise the serial **may have been issued without our knowledge**. The
   intent becomes `VOIDED`, the serial is never reused, and the serial is added
   to the issuer's CRL with reason `cessationOfOperation` (or a dedicated
   policy-defined reason) until the latest possible `notAfter` of the TBS has
   passed. RFC 5280 allows revoking a serial that was never seen.
3. A fresh issuance with a **new serial** may then be attempted if the request
   is still authorized.

Never re-sign the same TBS blindly.

### Idempotency
- Idempotency key scope: `(authenticated requester, issuer, key)`; same key and
  same request digest returns the same outcome/certificate; same key with a
  different request is rejected.
- Retention: at least the maximum certificate validity of the profile.

### Policy time-of-check / time-of-use
- Authorization records the policy version and expires (default 15 minutes).
- Immediately before `SIGNING`, the core re-checks that the policy version is
  still active and the authorization unexpired; otherwise `REJECTED`.
- `notBefore` is set by the core at TBS construction from a trusted clock;
  backdating is limited by profile (default ≤ 5 minutes for clock skew).

## Acceptance
Fault-injection tests (crash/timeout before, during and after `sign`, before and
after the `SIGNED` commit) demonstrate: no serial reuse, no unauthorized
issuance, no duplicate valid certificate without its serial being revoked,
traceability of every intent, and safe recovery.

## Consequences
- Voided serials make the CRL slightly larger; this is the price of correctness.
- The intent table stores TBS data (no secrets) and is part of the audit scope.
