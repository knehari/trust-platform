# v1.1 — Signed evidence receipts and durable replay rejection

**Scope:** independent audit collector *laboratory* evidence, not a real Luna HSM integration. Stacked draft PR #11; no production or eIDAS/ANSSI/ETSI conformity claim.

## What is implemented

1. The v1.0 Rust verifier validates a separate collector ECDSA P-256/SHA-256 signature using a pinned public key, compares issuer, request, immutable CP/CPS revision, operation/key reference, original signed TBS digest, and checks real retrieved certificate DER via independent X.509 verification.
2. v1.1 adds `VerifiedCollectorEvidence` as a privately constructed type; it can only be obtained after these checks succeed. Its getters provide the exact canonical bytes and signature for durable retention, without exposing a public unchecked constructor.
3. The `postgres-store` adapter accepts this verified type, not arbitrary claim strings, through `persist_verified_collector_evidence`.
4. PostgreSQL migration `0006_collector_evidence_receipt.sql` atomically records a quarantined issuer/request's canonical claim and its collector signature, original event identifiers, policy, TBS/log/certificate hashes, observation time, and an audit event. A computed SHA-256 over retained canonical bytes is persisted for later verification.
5. Database constraints ensure one receipt per `(collector_key_id, audit_event_id)` globally, reject same-claim replay per issuer/request, reject mismatched signing intent, and prohibit update/delete by the application via an audit trigger.
6. `NO_MATCHING_EVENT` means *no event was observed*, not that signing did not occur; it never authorizes re-signing. A recovered signed-result claim remains `RECONCILIATION_REQUIRED` without writing/publishing a certificate.

## Stronger acceptance testing

- SQL positive/negative tests: disallow intake before quarantine, reject altered issuer operation/key/CP policy/TBS, duplicate collector event, duplicate claim digest, invalid kind/hash combinations and mutation/deletion.
- Rust live CI integration: create a valid X.509 leaf in the lab, sign with the ephemeral CA, independently verify X.509, sign the canonical evidence statement with a distinct ephemeral collector key, persist the verified receipt, deny replay, and re-read bytes/signature/hash from a new PostgreSQL connection. State stays quarantined and no certificate record is introduced.
- CI carries forward v0.8 SIGKILL after a real ECDSA X.509 signing operation and v0.9 maker/checker negative tests.

## Trust boundaries, explicitly NOT addressed

- PostgreSQL **cannot** authenticate the ECDSA signature itself; calling the SQL function directly with forged bytes is possible for a privileged database actor. Only the Rust typed path performs cryptographic verification in this lab. A production DB role with no direct table/SQL owner access and a strongly authenticated service boundary is mandatory.
- The collector signed statement is NOT a native HSM audit proof. The mock provider/collector can lie about raw provider log contents; hashes only bind bytes once those bytes are genuinely acquired and authenticated.
- Raw provider logs have not been independently ingested, validated against Luna vendor integrity scheme, retained off-host, signed by the HSM or time-stamped by a trusted source.
- Claim event time is a **claimed** timestamp; a real counter/replay window, event retention and collector key lifecycle are still required. Database owner/superuser can bypass triggers.
- The test uses a private/lab CA and an ephemeral collector key. No Thales Luna HSM, PKCS#11 actual key operation, protected trust-store provisioning, key ceremonies, HSM role segregation or hardware attestation has been tested.
- Existing maker/checker identities are caller assertions until end-to-end authentication/RBAC is implemented.
- Signed audit receipts are only investigation artifacts; even a retrieved DER candidate must not cause automatic re-signing, state transition to SIGNED or publication.

## Thales Luna audit PoC — must be carried out on authorized independent hardware

Verify target Luna device model, firmware, Luna client revision and audit configuration. Demonstrate whether a completed operation emits verifiable raw HSM log entries with expected key/algorithm/issuer correlation and **prove** whether original signature bytes can be retrieved by a durable operation reference. Do not equate a `LUNA_SIGN` audit event with retrievability of a signature.

Test read-only privileged separation, protected log chain/integrity validation, dropouts, SIGKILL, network partition, log rotation and key rollover. If native operation ID binding or result retrieval is absent, record **UNSUPPORTED** and preserve quarantine. No automatic retry.

## Traceability

- Draft [PR #11](https://github.com/knehari/trust-platform/pull/11) stacked on PR #10; `main` unchanged.
- [TRUST-86](https://knehari.atlassian.net/browse/TRUST-86): vendor proof-of-capability remains pending, not completed by this lab code.
- [v1.0 official documentation capability matrix](v1-0-hsm-evidence-capability-assessment.md)
- [v1.0 evidence threat model](../security/v1-0-provider-evidence-threat-model.md)

## Next gates

Independent vendor lab PoC, externally anchored signed log source, trusted clock, real anti-replay event ledger with authenticated collectors, separate runtime DB roles, cryptographically verified certificate recovery with dual approval, G0 IP/legal and security assessment.
