> **Execution checkpoint — 2026-10-17:** PRs #43–#45 reverified green on exact trees; C-01 reproduced and corrected in Draft #46; consolidation and crypto registry in Draft #47–#48; control-plane decision in Draft #49; read-only Rust API in Draft #50 and React laboratory console in Draft #51. Draft #52 bounds management database requests after a focused security diff scan. Draft #53's disposable Docker Compose stack passed image build, startup and scoped OIDC/API/PostgreSQL smoke in CI; diagnostic request logging is the next increment. The console exercises a disposable OIDC code/PKCE fixture and real API/PostgreSQL reads, but no production IAM, persistent audit or policy-controlled HTTP issuance is delivered. See [execution status](docs/recovery/EXECUTION_STATUS.md).

> **Later laboratory checkpoint:** Draft #54 adds diagnostic request IDs, Draft #55 a lockfile SBOM, [Draft #56](https://github.com/knehari/trust-platform/pull/56) requires server-owned CA reader grants, [Draft #57](https://github.com/knehari/trust-platform/pull/57) adds bounded OIDC signing-key rotation, [Draft #58](https://github.com/knehari/trust-platform/pull/58) bounds management SQL statements, [Draft #59](https://github.com/knehari/trust-platform/pull/59) separates database readiness from process liveness, and [Draft #60](https://github.com/knehari/trust-platform/pull/60) bounds in-flight data requests before OIDC verification. #57–#60 passed exact-head CI and targeted Codex Security diff scans with no reportable findings. The dependent migration branch tests 0012–0013 against populated disposable data. These Drafts do not satisfy G0, human IAM, independent review or policy-controlled HTTP issuance.

> **Management database checkpoint — 18 October 2026:** Drafts [#61–#68](https://github.com/knehari/trust-platform/pulls) exercise populated management migration, logical restore within and across disposable PostgreSQL clusters, rollback after injected restore/migration failures, a restricted reader login, a transactional 0012–0013 migration ledger, and ledger continuity after restore. #67 and #68 passed CI on their code commits. These tests do not establish production backup, online upgrade, CA key recovery, RTO/RPO, or permission to merge the Draft stack.

> **Read-only application checkpoint:** Draft #69 adds bounded cursor pagination to certificate and audit history in the Rust API and React console. A local restricted PostgreSQL fixture proves two pages with equal timestamps and CA-scope denial. Its CI status is recorded on the PR; it does not add issuance, human IAM or a production history snapshot.

> **CA inventory checkpoint:** Draft #70 removes the silent 100-CA ceiling from the read-only API and console. A separate 102-CA fixture checks stable pages and exclusion of a CA named in the token but lacking a server-managed grant. Review and production data benchmarks remain open.

> **Revocation and CRL lab slice (this branch; not a release):** migrations 0014-0053 add a maker-checker certificate status lifecycle (suspend, release, revoke; definitive revocation irreversible; textual two-actor control by default, opt-in WebAuthn-signed key- and person-distinct double control per CA in 0028-0029 (ADR-0007, Proposed); EXECUTE-only service roles and dual-controlled CA administration (ADR-0006) in 0023-0024) and a CRL pipeline (reserve, intent before signing, sign, independent verification, store; ambiguous outcomes quarantined as `RECONCILIATION_REQUIRED`), with a CRL verifier fuzz target and OpenSSL interoperability checks. LAB-PROTOTYPE only: ephemeral lab CA key, a lab-only read-only HTTP distribution point (0030) named by an opt-in CDP extension in issued lab certificates, no OCSP, no delta CRLs, expired entries kept by default (opt-in RFC 5280 pruning since 0031, never for ETSI EN 319 411-2). It does not complete the planned v2.9 revocation and validation milestone, G0 or independent review. See [design](docs/superpowers/specs/2026-10-18-revocation-crl-design.md).

> **Recovery update — 2026-10-17:** This roadmap was originally written on 2026-10-14 and is preserved from `main` on the R1 consolidation branch. Its status through PR #24 and its subsequent *planned* version labels are **historical**, not a current release state. Draft PRs #25–#41 contain additional laboratory contracts and classical crypto lab code; see the [technical audit (PR #42)](https://github.com/knehari/trust-platform/pull/42) and its [feature matrix](https://github.com/knehari/trust-platform/blob/codex/technical-recovery-audit/docs/recovery/FEATURE_MATRIX.md). **No version is released, no deployed PKI is claimed, and G0/security gates remain pending.**

# Trust Platform — Product & Engineering Roadmap

> Status date: 2026-10-14 · Owner: Trust Platform · Repository: `knehari/trust-platform`
> **This is a technical roadmap, not a release announcement.** Versions below label laboratory increments and proposed future milestones, not published production releases.

## Status conventions

- **LAB-VALIDATED**: code and relevant tests evidenced in a draft PR; not merged, deployed or production approved.
- **LAB-PROTOTYPE**: scoped code/contract and tests available; full integration, CI and independent review may remain open.
- **PLANNED**: proposed scope, no implementation claim. Future version numbers are planning labels, subject to architecture review.
- **G0 BLOCKED**: legal/employment/IP separation and independent security review required before merge or commercialization.

## Current baseline and release hygiene

- **`main` is documentation/baseline, not a shipped CA.** Implementation is spread across sequential, stacked draft PRs #1–#41 and recovery Draft PRs, with explicit no-merge restrictions. The version history below records **development milestones**, not GitHub releases.
- Technical test success is not production readiness; no eIDAS/ETSI/ANSSI qualification, no QTSP certification, no audited production HSM custody or network-facing production CA claimed.
- Do not bulk-merge stacked work. Resolve G0, review each diff and migration in dependency order, assess security and cryptographic algorithms, validate isolated CI, then merge through authorized review gates.

## Implemented laboratory versions (not released)

| Version | Increment delivered | Evidence | Maturity |
| --- | --- | --- | --- |
| Sprint 0 / v0.1 | Rust workspace, CA core/policy/provider contracts, default-deny checks, CI foundation | [PR #1](https://github.com/knehari/trust-platform/pull/1) | LAB-VALIDATED / G0 BLOCKED |
| v0.2 | PRD audit-by-design traceability and PKCS#10 CSR validation in lab | [PR #2](https://github.com/knehari/trust-platform/pull/2) | LAB-VALIDATED / G0 BLOCKED |
| v0.3 | X.509 SKI/AKI, controlled certificatePolicies OID in lab | [PR #3](https://github.com/knehari/trust-platform/pull/3) | LAB-VALIDATED / G0 BLOCKED |
| v0.4 | PostgreSQL issuer-scoped idempotency, serial reservation and durable issuance states | [PR #4](https://github.com/knehari/trust-platform/pull/4) | LAB-VALIDATED / G0 BLOCKED |
| v0.5 | Durable signing intents, cryptographic TBS binding and ambiguity-safe journal | [PR #5](https://github.com/knehari/trust-platform/pull/5) | LAB-VALIDATED / G0 BLOCKED |
| v0.6 | Rust issuance orchestration, single-attempt signing and fault injection | [PR #6](https://github.com/knehari/trust-platform/pull/6) | LAB-VALIDATED / G0 BLOCKED |
| v0.7 | Real P-256 X.509 signature verification before durable certificate persistence | [PR #7](https://github.com/knehari/trust-platform/pull/7) | LAB-VALIDATED / G0 BLOCKED |
| v0.8 | Crash quarantine, SIGKILL recovery, no blind re-sign, reconciliation-required state | [PR #8](https://github.com/knehari/trust-platform/pull/8) | LAB-VALIDATED / G0 BLOCKED |
| v0.9 | Read-only provider reconciliation and maker-checker evidence review | [PR #9](https://github.com/knehari/trust-platform/pull/9) | LAB-VALIDATED / G0 BLOCKED |
| v1.0 | HSM capability matrix and signed collector evidence **prototype** (not a real HSM adapter) | [PR #10](https://github.com/knehari/trust-platform/pull/10) | LAB-PROTOTYPE / G0 BLOCKED |
| v1.1 | Durable signed collector receipts, evidence linkage and anti-replay | [PR #11](https://github.com/knehari/trust-platform/pull/11) | LAB-VALIDATED / G0 BLOCKED |
| v1.2 | Deterministic RFC 3647 CP/CPS **draft** generation and drift detection | [PR #12](https://github.com/knehari/trust-platform/pull/12) | LAB-PROTOTYPE / G0 BLOCKED |
| v1.3 | Pinned public CA observation and immutable CP/CPS draft trace, retrospective only | [PR #13](https://github.com/knehari/trust-platform/pull/13) | LAB-VALIDATED / G0 BLOCKED |
| v1.4 | Lab separate-actor policy approvals, issuer-scoped optional pre-sign policy gate; actors not authenticated | [PR #14](https://github.com/knehari/trust-platform/pull/14) | LAB-VALIDATED / G0 BLOCKED |
| v1.5 | Two distinct P-256 signed CP/CPS decision receipts, anti-replay and optional gated issuance | [PR #15](https://github.com/knehari/trust-platform/pull/15) | LAB-VALIDATED / G0 BLOCKED |
| v1.6 | Fail-closed identity-bound dual-approval **trusted adapter contract**; no actual IdP integration | [PR #16](https://github.com/knehari/trust-platform/pull/16) | LAB-PROTOTYPE / G0 BLOCKED |
| v1.7 | Crypto-agility capability catalogue and software RSA-PSS X.509 lab interoperability; PQC not implemented | [PR #17](https://github.com/knehari/trust-platform/pull/17) | LAB-VALIDATED / G0 BLOCKED |
| v1.8 | PostgreSQL-backed RSA-PSS X.509 server issuance in lab, independent verification, replay and fault tests | [PR #18](https://github.com/knehari/trust-platform/pull/18) | LAB-VALIDATED / G0 BLOCKED |
| v1.9 | Fail-closed issuance identifier checks, 64 KiB DER bounds, no signer invocation on invalid metadata | [PR #19](https://github.com/knehari/trust-platform/pull/19) | LAB-VALIDATED / G0 BLOCKED |
| v2.0 | Deterministic domain-separated SHA-256 issuance evidence commitment (not signed audit proof) | [PR #20](https://github.com/knehari/trust-platform/pull/20) | LAB-VALIDATED / G0 BLOCKED |
| v2.1 | Pure Rust chained audit-event commitment contract | [PR #21](https://github.com/knehari/trust-platform/pull/21) | LAB-PROTOTYPE / G0 BLOCKED |
| v2.2 | Pure Rust fail-closed signer capability policy contract | [PR #22](https://github.com/knehari/trust-platform/pull/22) | LAB-PROTOTYPE / G0 BLOCKED |
| v2.3 | Pure Rust issuance capacity and overload policy contract | [PR #23](https://github.com/knehari/trust-platform/pull/23) | LAB-PROTOTYPE / G0 BLOCKED |
| v2.4 | Pure Rust verifiable audit evidence manifest contract | [PR #24](https://github.com/knehari/trust-platform/pull/24) | LAB-PROTOTYPE / G0 BLOCKED |

**Caveat for v2.1–v2.4:** unit-tested domain contracts are not end-to-end integrated, externally attested, or deployment-ready; full CI and independent assurance remain gates.

## Historical proposed engineering versions — not current delivery statuses

| Proposed version | Theme | Exit criteria / deliverable | Dependencies |
| --- | --- | --- | --- |
| v2.5 | Consolidate evidence pipeline | Persisted authenticated audit chain, integrity checks, exportable manifest, negative tamper/replay tests | v2.0–v2.4; trust anchor, time & DB security review |
| v2.6 | Secure service boundary | Authenticated Rust issuance API, verified workload identity, request authorization and rate limits; threat-modelled mTLS | IdP, PKI service identity, secrets management |
| v2.7 | HSM / PKCS#11 integration | Real vendor-backed signer adapter, protected keys, capability probing, timeouts, safe retry/reconciliation, test ceremonies | Approved HSM design, vendor lab, two-person control |
| v2.8 | Production-grade issuance | End-to-end serial/intent/signature/persistence/recovery tests with least privilege, secure migrations and operational runbooks | v2.5–v2.7 |
| v2.9 | Revocation & validation | Verified CRL generation/publication, revocation audit, OCSP architecture and comprehensive RFC 5280 path validation test suite | CA profiles, trusted time, publication design |
| v3.0 | PKI MVP release candidate | Single-tenant controlled pilot, independent security test, backup/restore, HA/SLO measurements, production gating | G0 clearance; v2.8–v2.9 |
| v3.1 | Rust control plane & IAM | Authenticated management API, RBAC, separation of duties, CA lifecycle and tenant authorization model | ADR-0005; stable Rust policy boundary |
| v3.2 | Operator experience | React/TypeScript console, audit views, API clients/CLI, usability and access testing | v3.1 |
| v3.3 | Automated enrollment protocols | ACME first, followed by scoped EST/SCEP profiles; interoperable renewal/revocation and authz | v3.0–v3.2, protocol threat models |
| v3.4 | CLM foundation | Inventory, ownership, discovery, renewal jobs, notification, connectors and CMDB labels | v3.3; discovery source validation |
| v3.5 | CP/CPS lifecycle | Governed CP/CPS change proposal, multi-party verified approval, versioning, controlled publication and documented policy drift workflow | v1.2–v1.6 integrated; trusted IAM |
| v3.6 | Key Ceremony as Code | Ceremony workflow, dual control, evidence capture, signed minutes, artifact export and reviewable custody trail | Real HSM, identity, trusted timestamps |
| v3.7 | Audit-by-design | Independent evidence verification, auditor workspace, signed export packs and mapped controls for ETSI/eIDAS/ISO assessment support | Actual deployed-control attestations |
| v3.8 | Capacity / HA / DR | Load, search latency, signing throughput, observability, capacity forecasts, HA failure drills, tested RTO/RPO | v2.3 integrated; infrastructure testbed |
| v4.0 | Sovereign platform GA candidate | Deployment reference for private/on-prem/air-gapped environments, multi-CA and tenant boundary proofs, upgrade/rollback, operational hardening | Entire prior pilot and independent assurance |
| v4.1+ | PQC readiness & crypto-agility | Algorithm negotiation/capability inventory, ML-DSA lab paths, HSM interoperability and migration tests; rollout only where profiles and policies support it | Updated standards, vendor and client readiness |
| Later | Advanced trust services | Optional signing/TSP modules, richer CLM ecosystem, qualified-service enabling controls subject to separate gap analysis | Commercial and regulatory decisions |

**Scheduling:** version order is indicative. No dates or delivery commitments have been approved; prioritize dependencies, release gates and actual engineering capacity over calendar promises.

## Cross-cutting quality gates before any production claim

The unmerged laboratory stack now includes a reproducible Rust/npm lockfile
SBOM in [Draft #55](https://github.com/knehari/trust-platform/pull/55). This
addresses source dependency inventory only; container contents, provenance,
secret scanning, SAST and independent review remain open gates.

The next management increment requires a server-owned issuer/subject/CA read
grant in addition to the signed OIDC role and CA scope. It narrows read access
for the laboratory console; authenticated issuance still needs its own policy
and actor authorization design before any HTTP route is added.

1. **G0 legal and IP:** confirm ownership, employment/contractual separation and release authorization before integrating or commercializing work.
2. **Cryptographic design review:** independent PKI review including keys, algorithms, HSM boundary, certificate profile, CP/CPS authority and secure defaults.
3. **Security controls:** IAM/mTLS, RBAC, maker-checker, least-privilege PostgreSQL grants, secrets, rate limiting, logging, anti-replay, tenant isolation.
4. **Test evidence:** strict CI on final merged commit, PostgreSQL integration, OpenSSL interop, negative/fault tests, fuzzing, SAST/dependency scans, independent pentest.
5. **Operations:** safe DB migration/rollback, protected key backup, CA restore, publication availability, reconciliation runbooks, capacity/SLO and incident response.
6. **Regulatory discipline:** audit-by-design features can facilitate future assessments; never advertise eIDAS/ETSI/ANSSI certification or QTSP status without actual qualification.

## References

- [Architecture](docs/architecture/system-overview.md)
- [Issuance state machine](docs/architecture/issuance-state-machine.md)
- [Security threat model](docs/security/threat-model.md)
- [Security acceptance gates](docs/testing/acceptance-gates.md)
- [GitHub pull requests](https://github.com/knehari/trust-platform/pulls)
- [Jira TRUST](https://knehari.atlassian.net/jira/software/projects/TRUST)

## Maintenance rules

- Update this file whenever a PR lands or scope changes; record actual status, test evidence, reviewer and merged commit.
- A version is **released** only after the release checklist, approved tag and documentation are published; draft PR numbers alone do not imply release.
- Keep roadmap features, design proposals and implementation evidence separately traceable.
