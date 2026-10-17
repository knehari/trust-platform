# Recovery execution — 17 October 2026

This is an execution record, not a release announcement. All historical PRs remain open Draft; no merge, close, G0 approval or production qualification was performed.

## Reverified PRs

| PR | Exact head | Tree confirmed equal to CI checkout | Rust/schema evidence |
|---|---|---|---|
| #43 | `005f82ab37e8bd49abb71f1fad16faa2d95c7eca` | `edf403fd3e7d6f53a46329628951d521d5c7e73b` | [39026076475](https://github.com/knehari/trust-platform/actions/runs/39026076475), both success |
| #44 | `f1864ba9519f9a6da364d507011a89d1fb7dd6a3` | `af7ad1f8077f583a3d305956879f3db91df092a5` | [39026089411](https://github.com/knehari/trust-platform/actions/runs/39026089411), both success |
| #45 | `3f291763f2027f540a134919e7dec80faae5e1ed` | `16ef062a0987f2275f3ed9d8fa628d0f0aa41e3b` | [39026237530](https://github.com/knehari/trust-platform/actions/runs/39026237530), both success |

The logs show synthetic merge checkouts `c544a4c57efbee0f1ed2603a8a292b7b1ed04ac3`, `75d5839a6f254f95eee46ae80d885d792c452a9f`, and `dbe730c54d10e26ff293632cedd54db310628b97`; GitHub commit-tree queries and local head trees match above. These are inspected existing runs, not new executions on these historical heads.

#43 executes the restored capacity/manifest tests and retains the corrected recovery-budget cases. #44 executes rejection of one P-256 key encoded compressed/uncompressed, acceptance of distinct compressed keys, malformed pin rejection, substituted keys and invalid signatures. Separate independently authenticated humans remain unimplemented. #45 proves missing URL fails in strict mode, then executes configured PostgreSQL integration, ordered migrations, 12-client request/serial idempotence, recovery concurrency and SIGKILL with zero re-signs. All three run Rustfmt, Clippy and existing OpenSSL interoperability. Non-DB workspace results must not be counted as DB evidence.

## New work

- [#46](https://github.com/knehari/trust-platform/pull/46), TRUST-89: reproduced C-01 on historical schema, added migration 0011 and synchronized regression tests. See [C01_GATE_SERIALIZATION](C01_GATE_SERIALIZATION.md). Final-head CI and independent human review remain acceptance gates.
- Consolidated laboratory branch carries exactly the three-file S-01 diff from #44 on top of strict #45 and C-01. The original branches are not rewritten or merged. Dependencies: #43 → #45 → #46, plus #44's patch; the next Draft PR targets #46.
- `HISTORICAL_HEADS.json` freezes all 41 commit/tree identities. `scripts/recovery/inventory.py` indexes every historical file hash, Rust public declaration and test name. Initial run: no missing path, public name or test name across the 41 heads. This is a lexical omission check, **not** proof of behavioral or signature compatibility.
- The four audit reports are preserved with a pointer to this record. README, architecture and roadmap distinguish existing laboratory crypto/DB behavior from missing application services.
- CI is being aligned on repository Rust 1.99.0 in both jobs, including default-feature tests; final CI results must validate this change. MSRV 1.82 remains unverified.

## Remaining recovery acceptance

R0/R1 are partial: frozen inventory and restored assertions exist; independent semantic review of all changed declarations/fixtures and missing PRD v0.1 requirements remain. No historical source path was removed. Original migrations 0001–0010 are untouched. R2 is partial: strict DB tests are demonstrated; least-privilege roles, migration ledger/retry, general populated upgrades, restore and supply-chain assurance remain. R3's key-identity defect is corrected in #44 and carried into consolidation; identity provisioning and authenticated two-person review remain separate work.

The architecture still contains three Rust crates and PostgreSQL laboratory adapters. Authenticated network API, React frontend, OIDC, operational CA inventory, service-role DB access, production custody, CRL/OCSP and complete application E2E remain **not implemented** at this checkpoint. Crypto-agility models still require reconciliation; enumerated suites do not imply qualification.

## Environment and decisions

Cargo and psql are absent locally; Docker Desktop startup did not produce a responsive daemon. Executable PostgreSQL and Rust validation uses disposable GitHub Actions services, with local Git/Python checks only. A requested agent patch-review attempt failed on usage limits, so it supplies no independent-review evidence. Human G0/security approvals, HSM hardware, independent audit and qualification are not substituted by CI.

Next dependency order: finish exact-head validation and semantic consolidation; reliable migrations/roles and crypto capability truth; document Go-versus-Rust ADR; authenticated read-only vertical slice; only then policy-controlled issuance and further operational services.
