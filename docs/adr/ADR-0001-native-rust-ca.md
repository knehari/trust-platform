# ADR-0001 — Native Rust CA Core

Status: Accepted · 2026-10-13 (proposed 2026-10-11)

## Context
Sovereign product requires an independently maintained native X.509 CA engine, secure parsing, controlled policies and reproducible builds.

## Decision
Implement a modular-monolith CA Core in Rust using established cryptographic libraries, not homegrown cryptographic primitives. Go and React are future control/UX planes.

Implementation rules:
- Cargo workspace (`crates/`): `ca-core` (CSR/X.509/policy/issuance), `crypto-provider` (ADR-0004 contract), `store` (PostgreSQL persistence, ADR-0002). Adapters (PKCS#11, software) are separate crates.
- `#![forbid(unsafe_code)]` in core crates; any `unsafe` is confined to adapter crates and requires security review.
- Strict DER with RustCrypto `der` / `x509-cert`; lenient parsers are not used on untrusted input.
- Toolchain pinned (`rust-toolchain.toml`), `Cargo.lock` committed, dependencies gated by `cargo-deny` (licences, sources, advisories).
- Fuzz targets for every parser of untrusted input (`fuzz/`).

## Consequences
More implementation and assurance effort than wrapping an existing CA; strict standards/interoperability testing and external audit required before pilots.
