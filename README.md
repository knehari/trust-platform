# trust-platform
Sovereign PKI, Certificate Lifecycle Management and Post-Quantum Cryptography Platform

**Status: pre-implementation / lab skeleton. Not for production use** (see `docs/testing/acceptance-gates.md`).

## Layout
| Path | Content |
|---|---|
| `docs/adr/` | Architecture decisions (ADR-0001 Rust CA core, ADR-0002 durable issuance, ADR-0003 PQC hybrid strategy, ADR-0004 crypto provider contract) |
| `docs/architecture/` | System overview, issuance state machine, crypto provider |
| `docs/security/` | Threat model, security requirements, traceability matrix |
| `crates/crypto-provider` | Signing provider contract: typed algorithms, explicit input, bound authorization, sign-then-verify |
| `crates/ca-core` | Strict CSR parsing, serial numbers, issuance state machine |
| `crates/store` | Durable issuance persistence contract + in-memory reference |
| `migrations/` | PostgreSQL schema |
| `fuzz/` | cargo-fuzz targets |
| `testdata/` | Public test vectors only |

## Development
```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check                       # cargo install cargo-deny --locked
pre-commit install                     # gitleaks + rustfmt hooks
```

## Licence
Not decided yet (intended: commercial licence for the core, Apache-2.0 for connectors). Until a LICENSE file is added, all rights are reserved.

## Security
See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.
