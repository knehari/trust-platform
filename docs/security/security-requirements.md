# Security requirements

SEC-01 Deny by default for CA operations.
SEC-02 Authenticate requester and bind identity to issuance policy.
SEC-03 Authorize subject, SAN, EKU, key usage, CA profile, validity and algorithm server-side.
SEC-04 Do not store CA private keys in source, application DB or logs.
SEC-05 Tamper-evident audit with actor, decision, policy version and operation ID.
SEC-06 Reject unsupported/weak algorithms; no silent downgrade.
SEC-07 Fuzz ASN.1/DER and CSR parsing; negative security tests in CI.
SEC-08 Test backup/restore and reconciliation.
SEC-09 Protect CRL integrity and publication freshness.
SEC-10 Review dependency provenance and release artifacts.

Status: proposed requirements; implementation and verification pending.