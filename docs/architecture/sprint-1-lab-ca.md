# Sprint 1 — Lab CA and standards governance

Status: implementation in [draft PR #2](https://github.com/knehari/trust-platform/pull/2), stacked upon Sprint 0 PR #1.

## Technical increment
- Validate RFC 2986 PKCS#10 and proof of possession using strict DER and ECDSA P-256/SHA-256.
- Implement an independent native Rust X.509 v3 issuer using mature encoding/signature libraries.
- Require server-side policy decisions for subject/CN, DNS SANs, issuer signature algorithm, validity.
- Root and leaf certificate test generation entirely in ephemeral lab process memory.
- Verify issuer chain and TLS server profile via OpenSSL using public output.
- Keep the lab signing provider behind an explicit compile-time feature.

## Jira stories
TRUST-16, TRUST-17, TRUST-18, TRUST-19, TRUST-20, TRUST-24. Sprint 1 id 37 on TRUST board.

## Product governance increment
- PRD v0.2 defines CP/CPS governance FR-013..FR-019 under TRUST-52 and audit readiness FR-020..FR-026 under TRUST-53.
- CP/CPS publication and evidence collection are later control-plane/CLM milestones, not part of this Rust lab slice.

## Evidence gates
GitHub Actions quality gates and independent OpenSSL check required before developer review. PR must remain draft pending G0 IP review, owner signoff, missing X.509 profile checks and branch-protection setup.

## Non-goals and limitations
No client production certificates, eIDAS qualified certificate claim, operational root, HSM, CRL, ACME, external audit result or end-to-end qualification.
