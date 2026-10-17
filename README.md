# Sovereign Trust Platform

**Private founder project: architecture and engineering prototype, not an operating CA.**

Sovereign PKI / certificate lifecycle management / post-quantum crypto-agility platform designed for on-premises and offline operation. The product is planned to have its **own Rust CA engine** built using proven cryptographic primitives, without embedding another CA product.

## Sprint 0 implementation

- Rust workspace with three crates: trust-pki-core, trust-pki-policy and trust-pki-crypto.
- Default-deny authorization separating trusted actors from untrusted certificate request fields.
- Strict lab DNS allowlist, validity and issuer-signature algorithm policy.
- RFC 5280 positive serial constraints and duplicate detection in an in-memory **test double**.
- Restricted issuance-state transition mapping and fail-closed unconfigured signing provider.
- PostgreSQL schema proposal with disposable-database constraint tests.
- CI running Rustfmt, unit and negative tests, Clippy and SQL checks.

**Not implemented:** parsing or verification of PKCS#10 CSRs, X.509 certificate issuance and signing, CRLs, HSM, production authentication API or persistent runtime CA storage.

## Quick start

Install the toolchain configured in rust-toolchain.toml, then run:

    cargo fmt --all -- --check
    cargo test --workspace --all-targets --locked
    cargo clippy --workspace --all-targets --locked -- -D warnings
    cargo run -p trust-pki-core --example authorize_lab

The example demonstrates a permitted policy decision and a denied unauthorized SAN. It does not generate a certificate.

## Repository map

- crates/pki-core: CA orchestration contracts and serial constraints.
- crates/pki-policy: authorization with default deny.
- crates/pki-crypto: software/HSM signing provider interface.
- docs/architecture: state machine and conceptual data model.
- docs/adr: engineering decisions.
- docs/security: threat model and security requirements.
- docs/specifications: X.509 and PKCS#10 requirements.
- migrations: uninstalled PostgreSQL schema, tested in CI.
- tests: SQL invariants and future integration checks.
- .github/workflows: GitHub Actions quality gates.

## Delivery

- Jira: https://knehari.atlassian.net/jira/software/projects/TRUST
- Notion: https://app.notion.com/p/3f6e759bb68e8106b499e58596a4d797
- Sprint 0 scope: docs/architecture/sprint-0-foundation.md
- Security limitations: docs/security/sprint-0-assurance.md

## Non-negotiable constraints

Private PKI MVP only; not a public WebPKI CA or a qualified trust service. No unreviewed cryptographic primitives, no employer proprietary code and no secrets in source. Legal/IP review and independent security assessment are mandatory before real-world use.
