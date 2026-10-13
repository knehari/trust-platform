# Release security gates

- **G0** Legal/IP/confidentiality review before commercial activity, including the **licence decision** (intended: commercial licence for the core, Apache-2.0 for connectors). Blocking: no LICENSE file yet.
- **G1** Lab CA: signed and independently validated X.509, no secrets in Git.
  - Linting: zlint, pkilint.
  - Parsing/validation by independent stacks: OpenSSL, Go `crypto/x509`, Bouncy Castle, NSS; path validation with the x509-limbo suite.
  - Crypto vectors: Wycheproof (classical), NIST ACVP vectors for ML-DSA.
  - CI green: fmt, clippy, tests, cargo-deny, gitleaks, fuzz smoke.
- **G2** Revocation, CRL, state machine, backups and restore tested; ADR-0002 fault-injection suite passes; SBOM and signed releases.
- **G3** Authorization negative tests, authenticated requester binding, audit traceability and tamper detection.
- **G4** Independent security review, CA key compromise exercise, and controlled non-critical pilot.

Every story must define testable acceptance criteria, evidence and relevant security controls, and update `docs/security/traceability.md`. No production-readiness claim until G4.
