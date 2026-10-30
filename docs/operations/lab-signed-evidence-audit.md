# Laboratory signed-evidence audit

Lab only. ADR-0007 is Proposed.

PostgreSQL cannot verify ECDSA. A holder of `trust_revocation_officer_api` or `trust_ca_admin` could therefore store an assertion the Rust core never verified. The audit re-verifies every stored signature offline, from an account that cannot act.

```
TRUST_DATABASE_URL=postgresql://auditor@db.lab.invalid/trust TRUST_DATABASE_CA_FILE=/etc/trust/db-ca.pem \
TRUST_WEBAUTHN_RP_ID=officer.lab.invalid TRUST_WEBAUTHN_ORIGIN=https://officer.lab.invalid \
  cargo run -p trust-management-api --bin signed_evidence_audit -- <ca-uuid>|--all
```

- **Connection:** verified TLS 1.3 by default (`TRUST_DATABASE_CA_FILE`). `TRUST_DATABASE_TLS=disable-lab` is the explicit, reported lab opt-out.
- **Login:** non-privileged, holding only `trust_audit_verifier` (migration 0041). A superuser or owner-member login is refused.
- **Coverage:** every change of the CA that carries signatures (`signed_evidence_index`). This includes status changes, precautionary holds, signed rejections and withdrawals, CA administration, officer credentials and admin credentials. Since 0045 it also covers break-glass uses and their reviews (`breakglass_evidence`, family `break_glass`).
- **What is checked:** each signature against the enrolled key and the claim rebuilt from its challenge. Complete evidence is required:
  - maker and checker (distinct keys and persons);
  - maker and rejecting checker;
  - maker and own withdrawal;
  - or a single precautionary signature.
  - for a break-glass use, the emergency signature over the enrolled admin key, plus its reviews by admins other than the enrolled one (distinct keys and persons; exactly two once reviewed).
  
  An open proposal is checked on its maker signature alone.
- **All CAs:** `--all` audits every CA carrying signed evidence (`evidence_cas`, migration 0056) in turn, so one scheduled run covers them; a CA that fails to load is reported (`ERROR`) without hiding the others. `tests/signed_evidence_audit_all.sh` runs it after the signed tests.
- **Output:** one line per change, prefixed with its CA, then `ca=… changes=N all_verified=…` per CA.
- **Exit status:** 0 when everything verifies, 3 when at least one change fails, 1 on error (with `--all`, an error on any CA). A scheduler can alert on any non-zero status.

Not covered:
- changes closed without signatures on a CA that did not require them (a closed change with only a maker signature is reported as failed);
- the hash chain of the audit trail itself (`lab-audit-chain.md`);

Tests:
- `auditor_reverifies_every_signed_change` in `crates/pki-core/tests/signed_status_change_postgres.rs`: all evidence verifies, including an open proposal; the auditor cannot issue a challenge; a signature altered in the database is reported for that change alone.
