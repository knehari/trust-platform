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

- [#46](https://github.com/knehari/trust-platform/pull/46), TRUST-89: reproduced C-01 on historical schema, added migration 0011 and synchronized regression tests. See [C01_GATE_SERIALIZATION](C01_GATE_SERIALIZATION.md). Final head `1de8f0a73505b1a8327c77a5d8373a0051aba017` passes [Rust/schema 39031246943](https://github.com/knehari/trust-platform/actions/runs/39031246943) and [race matrix 39031246961](https://github.com/knehari/trust-platform/actions/runs/39031246961), including independent issuers, rollback, replay and quarantine. Independent human review remains outstanding.
- Consolidated laboratory branch carries exactly the three-file S-01 diff from #44 on top of strict #45 and C-01. The original branches are not rewritten or merged. Dependencies: #43 → #45 → #46, plus #44's patch; the next Draft PR targets #46.
- `HISTORICAL_HEADS.json` freezes all 41 commit/tree identities. `scripts/recovery/inventory.py` indexes every historical file hash, Rust public declaration and test name. Initial run: no missing path, public name or test name across the 41 heads. This is a lexical omission check, **not** proof of behavioral or signature compatibility.
- The four audit reports are preserved with a pointer to this record. README, architecture and roadmap distinguish existing laboratory crypto/DB behavior from missing application services.
- CI is being aligned on repository Rust 1.99.0 in both jobs, including default-feature tests; final CI results must validate this change. MSRV 1.82 remains unverified.

## Remaining recovery acceptance

R0/R1 are partial: frozen inventory and restored assertions exist; independent semantic review of all changed declarations/fixtures and missing PRD v0.1 requirements remain. No historical source path was removed. Original migrations 0001–0010 are untouched. R2 is partial: strict DB tests are demonstrated; least-privilege roles, migration ledger/retry, general populated upgrades, restore and supply-chain assurance remain. R3's key-identity defect is corrected in #44 and carried into consolidation; identity provisioning and authenticated two-person review remain separate work.

The architecture still contains three Rust crates and PostgreSQL laboratory adapters. Authenticated network API, React frontend, OIDC, operational CA inventory, service-role DB access, production custody, CRL/OCSP and complete application E2E remain **not implemented** at this checkpoint. Crypto-agility models still require reconciliation; enumerated suites do not imply qualification.

## Environment and decisions

Rust 1.99.0 was installed under `/private/tmp/trust-tooling` without changing the global PATH. Local default-feature workspace tests now pass (71 core, 30 crypto, 13 policy, 3 integration assertions); Rustfmt passes. The new default matrix exposed missing Cargo example feature declarations and a feature-dependent negative-test expectation; both were corrected without enabling lab features by default. A disposable PostgreSQL 16.15 instance now runs locally on port 55432: migrations 0001–0011, ten SQL fixture scripts and the 24-case C-01 concurrency harness passed. Full-feature workspace Rust tests and Clippy also passed locally. GitHub Actions on the latest consolidation commit cannot start jobs because of the account's billing/spending setting, so those checks do not supply fresh remote evidence. A requested agent patch-review attempt failed on usage limits, so it supplies no independent-review evidence. Human G0/security approvals, HSM hardware, independent audit and qualification are not substituted by CI.

Next dependency order: finish exact-head validation and semantic consolidation; reliable migrations/roles and crypto capability truth; document Go-versus-Rust ADR; authenticated read-only vertical slice; only then policy-controlled issuance and further operational services.

## Crypto registry increment

The next branch adds shared typed implementation routing used by concrete-key discovery and the laboratory dispatcher, and corrects legacy RSA-PSS discovery. Exact suite policy/key binding and default-build isolation remain. Local crypto tests passed with default and all features; workspace all-feature tests and Clippy passed without a database URL. Against a fresh local PostgreSQL 16.15 database with migrations 0001–0011 and the exact CI CA fixture, the five ordered Rust integration test binaries (`postgres_store`, `lab_verified_issuance`, `lab_rsa_pss_postgres`, `lab_policy_gate`, `policy_decisions`) all passed with `TRUST_REQUIRE_DATABASE=1`. See [registry scope](../architecture/crypto-registry-recovery.md); this does not complete phase 3 or promote any algorithm to production.

## First management service increment

- [Draft #48](https://github.com/knehari/trust-platform/pull/48) adds the laboratory capability route; local evidence is above. [Draft #49](https://github.com/knehari/trust-platform/pull/49) records [ADR-0005](../adr/ADR-0005-rust-management-control-plane.md): a Rust control plane for the first read-only application slice, superseding the tentative Go direction.
- The dependent API branch adds a running Rust service, [OpenAPI v1](../../openapi/management-v1.yaml), migration 0012 and SQL role fixture. Five API tests passed locally, including ephemeral RS256 token acceptance and rejection of wrong audience, expiry, type and tampering. A fresh PostgreSQL 16.15 database accepted migrations 0001–0012; the SQL privilege fixture passed. The HTTP test using a restricted login returned exactly one authorized CA while rejecting missing role and other CA scope. `cargo clippy -p trust-management-api --all-targets --locked -- -D warnings` passed.
- This is not a completed frontend-to-Core vertical slice: no React UI or live OIDC login provider has been integrated, and the read-only API does not call the Rust CA Core. The PostgreSQL driver is lab-only `NoTls`; JWKS refresh, structured security logging, production IAM/transport, role provisioning, release review and HTTP issuance remain open. See [exact boundary](../architecture/management-api-readonly.md). GitHub Actions evidence on this branch remains pending account billing repair.

## Laboratory console increment

The dependent React/TypeScript branch adds a [management console](../../frontend/README.md) backed by the real `/v1` API, not a hard-coded CA dataset. `npm ci`, `npm run build`, `npm run typecheck` and npm audit passed locally (zero reported vulnerabilities at this checkpoint). A loopback-only, auto-approved OIDC fixture produces ephemeral RS256 `at+jwt` tokens for one fixed lab operator and CA; it is **not** human authentication. An actual browser completed Authorization Code + PKCE, read one allowed CA from a PostgreSQL database containing two CAs, navigated its detail/certificate/audit views, and completed logout and a fresh login. Empty certificate/audit views reflect the database's real absence of those records. Rust Core is not called by this read-only path; controlled CSR issuance, real IAM, Docker Compose, protected database transport and production review remain open. Frontend CI is added, but GitHub Actions cannot be counted green until the account billing/spending issue is resolved.
