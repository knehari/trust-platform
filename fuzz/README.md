# Fuzzing (SEC-07)

Coverage-guided fuzzers for parsers that receive untrusted DER. Each must
return an error, never panic, hang or abort.

| Target | Entry point |
| --- | --- |
| `csr_p256` | `trust_pki_core::csr::verify_pkcs10_p256` |
| `csr_rsa_pkcs1_lab` | `trust_pki_core::csr::verify_pkcs10_rsa_pkcs1_lab` (lab feature) |
| `ca_certificate` | `trust_pki_core::ca_observation::observe_pinned_lab_ca` (pin = SHA-256 of the input, so parsing behind the pin is reached) |
| `crl_verify` | `trust_pki_core::crl::LabCrlVerifier::verify` against an ephemeral lab CA and a fixed empty reservation (lab feature); foreign CRLs must be rejected, never panic |

Run locally (nightly toolchain and `cargo install cargo-fuzz --version 0.13.2 --locked`):

```sh
bash fuzz/seed-corpus.sh fuzz/corpus
cd fuzz && cargo +nightly-2026-10-17 fuzz run csr_p256 corpus/csr_p256 -- -max_total_time=60
```

CI (`.github/workflows/fuzz.yml`) runs each target for 60 s on pull requests
and 30 min weekly; a crash uploads its reproducer as an artifact. A reproducer
becomes a regression test in the crate that owns the parser.

This crate has its own workspace and lockfile so the nightly-only fuzzing
dependencies stay out of the product workspace, its SBOM and cargo-deny scope.
