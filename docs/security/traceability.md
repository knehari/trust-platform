# Traceability matrix — requirement ↔ threat ↔ verification

Status legend: ✅ implemented and tested in the lab skeleton · 🟡 partially / designed · ⬜ not started.

| Req | Threats | Design reference | Verification | Status |
|---|---|---|---|---|
| SEC-01 | T02 | system-overview | Negative policy tests | ⬜ |
| SEC-02 | T01 | system-overview | Integration tests | ⬜ |
| SEC-03 | T02, T08 | x509 requirements | Policy test matrix | ⬜ |
| SEC-04 | T09, T18, T20 | ADR-0004 §6, `migrations/0001_init.sql` | gitleaks CI job; schema has only `key_ref` | 🟡 |
| SEC-05 | T03, T17, T18, T24 | `migrations/0001_init.sql` (hash chain, checkpoints, append-only triggers) | Tamper test | 🟡 |
| SEC-06 | T11, T22, T26 | ADR-0003, ADR-0004 §1–2 | `crypto-provider`: `input_compatibility_table`, `unsupported_algorithm_is_rejected_without_fallback`, `oid_round_trip_and_lab_only`; `ca-core::csr::unknown_algorithm_is_rejected` | 🟡 |
| SEC-07 | T06 | ADR-0001 | `ca-core::csr` tests (size, trailing data, truncation, params); `fuzz/csr_parse` in CI | ✅ |
| SEC-08 | T12, T21 | ADR-0002 | `store` tests (reconciliation, burn + revoke); restore drill | 🟡 |
| SEC-09 | T16 | — | CRL tests, monitoring | ⬜ |
| SEC-10 | T20, T23 | CI, `deny.toml`, `.gitleaks.toml`, dependabot | CI jobs `deny`, `secrets`; actions pinned by SHA | 🟡 (SBOM, signed releases pending) |
| SEC-11 | T04, T05, T12 | ADR-0002, ADR-0004 §3 | `crypto-provider`: `authorization_for_other_*`; `store`: `idempotent_replay_*` | 🟡 (policy re-check pending) |
| SEC-12 | T07 | x509 requirements | `ca-core::csr`: `pop_is_checked_*`, `ca_key_reuse_is_rejected` | 🟡 (weak-key checks pending) |
| SEC-13 | T08 | x509 requirements | Name test vectors | ⬜ |
| SEC-14 | T10, T22 | ADR-0004 §5 | `crypto-provider::invalid_signature_is_never_returned` | ✅ (contract) |
| SEC-15 | T13, T14 | ADR-0002 | `ca-core::serial` tests; `store::serial_is_never_reused_even_after_failure` | ✅ |
| SEC-16 | T15 | ADR-0002 (notBefore) | — | ⬜ |
| SEC-17 | T01 | — | — | ⬜ |
| SEC-18 | T03 | — | — | ⬜ |
| SEC-19 | T19 | — | — | ⬜ |
| SEC-20 | T24, T25 | ADR-0004 §6 | Ceremony records | ⬜ |

Update this matrix in the same PR as any change to a requirement, threat or test.
