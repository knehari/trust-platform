# Sovereign Trust Platform

> **Status (2026-10-17): private laboratory PKI implementation; not a deployed CA or production release.** The default branch `main` contains the documentation baseline only. Development is held in a stack of **70 draft pull requests** (#1–#70, none merged). This integration branch starts from [PR #70](https://github.com/knehari/trust-platform/pull/70), the top of that stack; the independent [recovery audit is PR #42](https://github.com/knehari/trust-platform/pull/42). Do not infer product maturity from `v3.x` or `v4.0` feature branch names.

## Goal

Develop a sovereign, crypto-agile private PKI and future CLM platform with a native Rust CA core using reviewed cryptographic libraries, PostgreSQL durable state, separate authentication/management APIs, operator UI and HSM signing adapters. The production architecture must support on-premises/offline operations, fail-closed security and independently verifiable audit evidence.

## Implemented as laboratory code (not production-qualified)

- Rust workspace: `trust-pki-core`, `trust-pki-policy`, `trust-pki-crypto`, plus a read-only laboratory management API.
- CSR parsing, signature verification and selected X.509 certificate issuance/verification paths.
- P-256 and classical RSA/ECDSA/EdDSA laboratory paths; **the implemented algorithms, profiles, providers and evidence differ**. A catalogue entry is never proof that full end-to-end issuance is available.
- PostgreSQL migrations 0001–0017 covering issuer-scoped idempotency, serials, signing intents, recovery, evidence, draft governance, read-only API views and server-owned reader grants; disposable CI tests.
- Lab-only revocation and CRL slice (migrations 0014–0017): maker-checker suspend/release/revoke (textual two-actor control through one trusted service, not yet key-distinct double control; see ADR-0006) with irreversible definitive revocation, and a CRL pipeline (intent before signing, independent verification, quarantine of ambiguous outcomes) with OpenSSL interoperability tests; ephemeral lab CA key, no CRL publication/HTTP distribution, no OCSP, no delta CRLs. See [design](docs/superpowers/specs/2026-10-18-revocation-crl-design.md).
- Executable authenticated Rust management API for scoped CA, certificate and audit metadata reads; see its [scope and setup](docs/architecture/management-api-readonly.md).
- Fail-closed authorization/policy contracts and controls against unsafe automatic re-sign after uncertain signing.
- CP/CPS draft generation and laboratory dual-approval receipts; no real authenticated reviewer service.
- Unit tests and a Rust CI workflow with PostgreSQL and OpenSSL interoperability checks.

## Important gaps

No deployed management application or production IAM adapter, no HTTP issuance, no real HSM/PKCS#11 custody, no OCSP and no CRL publication or HTTP distribution (a lab-only, maker-checker certificate status lifecycle and signed-CRL pipeline exist, see [revocation and CRL design](docs/superpowers/specs/2026-10-18-revocation-crl-design.md): ephemeral lab CA key, no delta CRLs, `keep_expired_on_crl` fixed to true), no deployed CLM or post-quantum signer, and no qualified trust-service capability. The [React console](frontend/README.md) is a laboratory read-only client with a disposable OIDC fixture, not a production login. The lab OpenSSL provider handles temporary private keys; never treat it as production custody. Fifteen standalone Rust domain contracts (from the `v2.5`–`v4.0` branches) are not called by anything; see [unintegrated contracts](docs/architecture/unintegrated-contracts.md) before citing any of them.

## How to inspect the laboratory workspace

See [`rust-toolchain.toml`](rust-toolchain.toml) for the pinned toolchain. Prerequisites include Rust/Cargo, OpenSSL CLI and PostgreSQL for DB integration tests.

```sh
cargo fmt --all -- --check
cargo test --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

**Supply chain and fuzzing:** `cargo deny check` (policy in [`deny.toml`](deny.toml)) and a gitleaks history scan run in [`supply-chain.yml`](.github/workflows/supply-chain.yml); CSR and CA-certificate DER parsers are fuzzed by [`fuzz/`](fuzz/README.md).

**Database evidence:** Set `TRUST_REQUIRE_DATABASE=1` together with `TRUST_CI_DATABASE_URL` to require PostgreSQL tests. Missing configuration then fails explicitly. Without strict mode, the workspace command alone does not prove DB paths ran. Consult `.github/workflows/rust-ci.yml` for disposable DB migrations and integration checks; never point this lab harness at a real CA database.

## Recovery and next work

See the [execution record](docs/recovery/EXECUTION_STATUS.md) for exact PR heads, inspected CI runs, C-01 and remaining acceptance criteria.

- [Technical audit and feature matrix (PR #42)](https://github.com/knehari/trust-platform/pull/42)
- [R1 integration notes](docs/recovery/R1_CONSOLIDATION_NOTES.md)
- [Roadmap (historical statuses explicitly noted)](ROADMAP.md)
- [Crypto-agility requirements](docs/architecture/crypto-agility-by-design.md)
- [Management control-plane decision](docs/adr/ADR-0005-rust-management-control-plane.md)
- [Proposed revocation write model and signed double control](docs/adr/ADR-0006-revocation-write-model.md) (not accepted)
- [Read-only management API and OpenAPI contract](docs/architecture/management-api-readonly.md)
- [React management console laboratory setup](frontend/README.md)
- [Disposable Docker Compose laboratory stack](docs/development/lab-compose.md)
- [Security gates](docs/testing/acceptance-gates.md)
- [Engineering instructions](AGENTS.md)

Preserve existing security tests, migrations and public interfaces. Resolve the audit findings, consolidate source in reviewed steps, establish reproducible CI and a trusted identity boundary before adding operational APIs and UI.

## Non-negotiable gates

**G0: legal/employment/IP separation** and independent security review are outstanding gates before integration/commercial use. Never bulk-merge the stacked draft PRs or claim eIDAS/ETSI/ANSSI qualification without an actual assessment. Never put CA private keys or employer proprietary information in source code.
