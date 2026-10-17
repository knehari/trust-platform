# Sovereign Trust Platform

> **Status (2026-10-17): private laboratory PKI implementation; not a deployed CA or production release.** The default branch `main` contains the documentation baseline only. Development is held in a stack of **41 draft pull requests** (#1–#41). This recovery branch is based on [PR #41](https://github.com/knehari/trust-platform/pull/41); the independent [recovery audit is PR #42](https://github.com/knehari/trust-platform/pull/42). Do not infer product maturity from `v3.x` or `v4.0` feature branch names.

## Goal

Develop a sovereign, crypto-agile private PKI and future CLM platform with a native Rust CA core using reviewed cryptographic libraries, PostgreSQL durable state, separate authentication/management APIs, operator UI and HSM signing adapters. The production architecture must support on-premises/offline operations, fail-closed security and independently verifiable audit evidence.

## Implemented as laboratory code (not production-qualified)

- Rust workspace: `trust-pki-core`, `trust-pki-policy`, `trust-pki-crypto`.
- CSR parsing, signature verification and selected X.509 certificate issuance/verification paths.
- P-256 and classical RSA/ECDSA/EdDSA laboratory paths; **the implemented algorithms, profiles, providers and evidence differ**. A catalogue entry is never proof that full end-to-end issuance is available.
- PostgreSQL migrations 0001–0011 covering issuer-scoped idempotency, serials, signing intents, recovery, evidence and draft governance; disposable CI tests.
- Fail-closed authorization/policy contracts and controls against unsafe automatic re-sign after uncertain signing.
- CP/CPS draft generation and laboratory dual-approval receipts; no real authenticated reviewer service.
- Unit tests and a Rust CI workflow with PostgreSQL and OpenSSL interoperability checks.

## Important gaps

No network-facing authenticated PKI management API, no React interface, no production IAM adapter, no real HSM/PKCS#11 custody, no integrated CRL/OCSP/revocation service, no deployed CLM or post-quantum signer, and no qualified trust-service capability. The lab OpenSSL provider handles temporary private keys; never treat it as production custody. Some standalone Rust domain contracts are not wired to runtime services.

## How to inspect the laboratory workspace

See [`rust-toolchain.toml`](rust-toolchain.toml) for the pinned toolchain. Prerequisites include Rust/Cargo, OpenSSL CLI and PostgreSQL for DB integration tests.

```sh
cargo fmt --all -- --check
cargo test --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

**Database evidence:** Set `TRUST_REQUIRE_DATABASE=1` together with `TRUST_CI_DATABASE_URL` to require PostgreSQL tests. Missing configuration then fails explicitly. Without strict mode, the workspace command alone does not prove DB paths ran. Consult `.github/workflows/rust-ci.yml` for disposable DB migrations and integration checks; never point this lab harness at a real CA database.

## Recovery and next work

See the [execution record](docs/recovery/EXECUTION_STATUS.md) for exact PR heads, inspected CI runs, C-01 and remaining acceptance criteria.

- [Technical audit and feature matrix (PR #42)](https://github.com/knehari/trust-platform/pull/42)
- [R1 integration notes](docs/recovery/R1_CONSOLIDATION_NOTES.md)
- [Roadmap (historical statuses explicitly noted)](ROADMAP.md)
- [Crypto-agility requirements](docs/architecture/crypto-agility-by-design.md)
- [Management control-plane decision](docs/adr/ADR-0005-rust-management-control-plane.md)
- [Security gates](docs/testing/acceptance-gates.md)
- [Engineering instructions](AGENTS.md)

Preserve existing security tests, migrations and public interfaces. Resolve the audit findings, consolidate source in reviewed steps, establish reproducible CI and a trusted identity boundary before adding operational APIs and UI.

## Non-negotiable gates

**G0: legal/employment/IP separation** and independent security review are outstanding gates before integration/commercial use. Never bulk-merge the stacked draft PRs or claim eIDAS/ETSI/ANSSI qualification without an actual assessment. Never put CA private keys or employer proprietary information in source code.
