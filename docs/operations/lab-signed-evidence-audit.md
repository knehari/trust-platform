# Laboratory signed-evidence audit

Lab only. ADR-0007 is Proposed.

PostgreSQL cannot verify ECDSA. A holder of `trust_revocation_officer_api` or `trust_ca_admin` could therefore store an assertion the Rust core never verified. The audit re-verifies every stored signature offline, from an account that cannot act.

```
TRUST_DATABASE_URL=postgresql://auditor@db.lab.invalid/trust \
TRUST_WEBAUTHN_RP_ID=officer.lab.invalid TRUST_WEBAUTHN_ORIGIN=https://officer.lab.invalid \
  cargo run -p trust-pki-core --features postgres-store --example signed_evidence_audit -- <ca-uuid>
```

- **Login:** non-privileged, holding only `trust_audit_verifier` (migration 0041). A superuser or owner-member login is refused.
- **Coverage:** every change of the CA that carries signatures (`signed_evidence_index`). This includes status changes, precautionary holds, signed rejections and withdrawals, CA administration, officer credentials and admin credentials.
- **What is checked:** each signature against the enrolled key and the claim rebuilt from its challenge. Complete evidence is required:
  - maker and checker (distinct keys and persons);
  - maker and rejecting checker;
  - maker and own withdrawal;
  - or a single precautionary signature.
  
  An open proposal is checked on its maker signature alone.
- **Output:** one line per change, then `changes=N all_verified=…`.
- **Exit status:** 0 when everything verifies, 3 when at least one change fails, 1 on error. A scheduler can alert on any non-zero status.

Not covered:
- changes closed without signatures on a CA that did not require them (a closed change with only a maker signature is reported as failed);
- the hash chain of the audit trail itself (`lab-audit-chain.md`);
- TLS for the lab connection (NoTls adapter).

Tests:
- `auditor_reverifies_every_signed_change` in `crates/pki-core/tests/signed_status_change_postgres.rs`: all evidence verifies, including an open proposal; the auditor cannot issue a challenge; a signature altered in the database is reported for that change alone.
