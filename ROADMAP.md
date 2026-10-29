# Trust Platform — Product & Engineering Roadmap

> Status date: 2026-10-26 · Owner: Trust Platform · Repository: `knehari/trust-platform`
> **This is a technical roadmap, not a release announcement.** Versions below label laboratory increments and proposed future milestones, not published production releases.

## Status conventions

- **LAB-VALIDATED**: code and relevant tests evidenced on an exact laboratory tree; the change may still be in a Draft PR and is not production approved.
- **LAB-PROTOTYPE**: scoped code/contract and tests available; full integration, CI and independent review may remain open.
- **PLANNED**: proposed scope, no implementation claim. Future version numbers are planning labels, subject to architecture review.
- **G0 BLOCKED**: legal/employment/IP separation and independent security review required before merge or commercialization.

## Current baseline and release hygiene

- **`main` is not a shipped CA.** Part of the laboratory application stack has been merged, while later work through [Draft #163](https://github.com/knehari/trust-platform/pull/163) remains in stacked PRs. The version history below records **development milestones**, not GitHub releases.
- Technical test success is not production readiness; no eIDAS/ETSI/ANSSI qualification, no QTSP certification, no audited production HSM custody or network-facing production CA claimed.
- Do not bulk-merge stacked work. Resolve G0, review each diff and migration in dependency order, assess security and cryptographic algorithms, validate isolated CI, then merge through authorized review gates.

## MVP: controlled single-tenant PKI pilot

The first viable version means an authorized operator can create a CA and a certificate profile, issue and revoke a certificate through authenticated application routes, inspect durable evidence, and recover the service and its protected keys in a controlled pilot. It is **not** a qualified trust service or a general-availability release.

**Progression: 4/12 criteria evidenced (33%)** · `████░░░░░░░░` · **MVP not reached**.

Each checkbox is one criterion, so the bar is `completed / 12`, rounded to the nearest whole percent. A checked foundation means implemented and tested **in the laboratory**, including code still in a Draft PR; it does not mean merged, independently reviewed or production-approved. An unchecked criterion may have partial prototypes, but its full MVP acceptance condition remains open.

- [x] **CA core and safe issuance foundations:** policy checks, issuer-scoped serial/idempotency, durable intent, independent signature verification and ambiguity-safe recovery in laboratory paths ([PRs #1–#9](https://github.com/knehari/trust-platform/pulls), [recovery status](docs/recovery/EXECUTION_STATUS.md)).
- [x] **Scoped read API:** OIDC-token and server-owned CA-grant checks, bounded reads, readiness and cursor pagination are exercised against disposable PostgreSQL ([Drafts #50–#70](https://github.com/knehari/trust-platform/pulls)). The test issuer is not human IAM.
- [x] **Read-only operator console:** CA/certificate/audit consultation, detail dialogs, search, export and recorded-date filters are exercised in the laboratory; profile-draft consultation is proposed through [Draft #140](https://github.com/knehari/trust-platform/pull/140). These views do not issue or revoke certificates.
- [x] **Reproducible laboratory stack and data checks:** disposable Compose/browser flow, restricted database role, migrations and logical restore regressions ([Drafts #53, #61–#69 and PR #129](https://github.com/knehari/trust-platform/pulls)). This is not operational disaster recovery.
- [ ] **Human IAM and authorization:** real IdP, workload identity, least-privilege roles and independently authenticated maker/checker actors, with negative access tests.
- [ ] **CA and profile lifecycle:** policy-controlled API and console workflows to create, approve, activate and retire CAs and versioned certificate profiles; no direct database bypass.
- [ ] **Application issuance:** authenticated CSR submission and approval, profile enforcement, Core orchestration, idempotent API result and end-to-end negative/fault tests.
- [ ] **Revocation and publication:** authorized revocation with durable audit evidence and verifiable CRL publication; OCSP and broader path validation require a separate design decision.
- [ ] **Protected signing keys:** real HSM/PKCS#11 integration, key ceremony, custody and tested ambiguous-outcome reconciliation; software laboratory keys do not meet this criterion.
- [ ] **Durable audit evidence:** persisted authenticated event chain, integrity/tamper checks, exportable verification manifest and governed retention.
- [ ] **Operational recovery:** protected database and key backup/restore, migration rollback, incident runbooks and measured pilot RTO/RPO.
- [ ] **Release gates:** G0 legal/IP clearance, independent PKI/security review, final-commit CI and an explicitly approved controlled-pilot release decision.

### Next implementation sequence

- [x] Add an exclusive server-side filter on recorded certificate validity end, keep it across pages and exercise it in the browser ([Draft #135](https://github.com/knehari/trust-platform/pull/135); all six checks green on `9a640193b7e67d77b0770a3516a8ae369afeed82`).
- [x] Capture a reproducible 10k-row filtered-history query-plan rehearsal ([Draft #136](https://github.com/knehari/trust-platform/pull/136)); further load and index decisions remain open.
- [x] Specify CA and profile lifecycle, actor permissions, approval states and immutable policy/version binding before adding write routes ([Draft #137](https://github.com/knehari/trust-platform/pull/137)).
- [x] Add an inert immutable profile-draft catalogue, scoped read API and read-only console ([Drafts #138–#140](https://github.com/knehari/trust-platform/pulls)); these do not activate profiles or issue certificates.
- [x] Add advisory syntax warnings, deterministic draft snapshot digests, exact revision reads, a detail dialog and local revision comparison ([Drafts #141–#145](https://github.com/knehari/trust-platform/pulls)). These remain inert read-only laboratory proposals.
- [x] Preserve an exact profile proposal revision in a scoped console link and restore it after sign-in ([Draft #146](https://github.com/knehari/trust-platform/pull/146)); the server reauthorizes each read.
- [x] Find a proposal by exact profile ID and revision from the console, independent of loaded list pages ([Draft #147](https://github.com/knehari/trust-platform/pull/147)); the read remains CA scoped.
- [x] Filter the scoped proposal list by exact profile ID across cursor pages to browse its recorded revisions ([Draft #148](https://github.com/knehari/trust-platform/pull/148)); no profile becomes active.
- [x] Show a filtered profile's revisions newest or oldest first across cursor pages ([Draft #149](https://github.com/knehari/trust-platform/pull/149)); ordering is by revision number, not an approval state.
- [x] Compare two exact proposal revisions even when neither is loaded in the current page ([Draft #150](https://github.com/knehari/trust-platform/pull/150)); each detail read is reauthorized.
- [x] Share a comparison link that reloads and reauthorizes both exact revisions after sign-in ([Draft #151](https://github.com/knehari/trust-platform/pull/151)); the URL carries no token or approval evidence.
- [x] Validate the shape, authority, revision and digest format of proposal responses before display or comparison ([Draft #152](https://github.com/knehari/trust-platform/pull/152)); this is defensive client validation, not proof of authenticity.
- [x] Toggle a proposal comparison between all fields and changed fields only ([Draft #153](https://github.com/knehari/trust-platform/pull/153)); unchanged fields remain available in the full view.
- [x] Export the visible comparison fields as a locally generated, formula-safe CSV ([Draft #154](https://github.com/knehari/trust-platform/pull/154)); the export contains no approval evidence or raw private data.
- [x] Search the full authorized profile-draft history by profile ID, display-name or policy prefix while preserving cursor scope ([Draft #155](https://github.com/knehari/trust-platform/pull/155)).
- [x] Export 1–100 explicitly selected loaded proposals as formula-safe metadata CSV without actor identity ([Draft #156](https://github.com/knehari/trust-platform/pull/156)).
- [x] Copy an exact proposal's allowlisted metadata and digest as JSON for offline review, without actor identity or approval evidence ([Draft #157](https://github.com/knehari/trust-platform/pull/157)).
- [x] Copy the visible comparison fields as scoped JSON with both revision digests and no actor identity ([Draft #158](https://github.com/knehari/trust-platform/pull/158)).
- [x] Triage advisory syntax warnings among already loaded proposal revisions, with an explicit loaded-only count ([Draft #159](https://github.com/knehari/trust-platform/pull/159)).
- [x] Filter the complete authorized proposal history by exact policy version with cursor continuity ([Draft #160](https://github.com/knehari/trust-platform/pull/160)).
- [x] Filter proposal history by inclusive/exclusive UTC recorded dates while retaining CA scope and pagination ([Draft #161](https://github.com/knehari/trust-platform/pull/161)).
- [x] Triage proposed maximum-validity lifetimes by a server-side minimum-days filter across authorized history ([Draft #162](https://github.com/knehari/trust-platform/pull/162)).
- [x] Triage proposed DNS SAN count limits by a server-side minimum threshold across authorized history ([Draft #163](https://github.com/knehari/trust-platform/pull/163)).
- [ ] Implement authenticated profile approval/activation and CA creation with denial, concurrency and recovery tests.
- [ ] Expose policy-controlled issuance through the Rust Core, with a real identity boundary before pilot use.
- [ ] Add revocation, publication and durable evidence paths, then complete custody/recovery and independent release gates.

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

## Archived version proposals — not the active checklist

The labels below are retained for traceability. Some read-only parts of v3.1/v3.2 exist in the laboratory, but neither version's full exit criteria are met. Use the checked MVP criteria and next implementation sequence above for current status.

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

- [x] Source dependency inventory from Rust/npm lockfiles is reproducible in [Draft #55](https://github.com/knehari/trust-platform/pull/55); image contents and provenance are outside its scope.
- [x] Laboratory reads require a signed role/CA scope and a server-owned issuer/subject/CA grant ([Draft #56](https://github.com/knehari/trust-platform/pull/56)); issuance needs separate policy and actor authorization.
- [ ] G0 legal/IP ownership, contractual separation and release authorization.
- [ ] Independent PKI/security review of keys, algorithms, profiles, HSM boundary, CP/CPS authority and secure defaults.
- [ ] Production IAM/mTLS, RBAC, maker/checker, secrets, rate limits, logging, anti-replay and tenant isolation.
- [ ] Final merged-commit CI, PostgreSQL and OpenSSL integration, negative/fault tests, fuzzing, SAST/dependency/secret scans and independent penetration test.
- [ ] Protected key and database recovery, safe migrations, publication availability, reconciliation, capacity/SLO and incident response.
- [ ] Actual regulatory qualification before any eIDAS/ETSI/ANSSI or QTSP claim; laboratory evidence alone is insufficient.

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

## Historical execution notes (archive)

> **Execution checkpoint — 2026-10-17:** PRs #43–#45 reverified green on exact trees; C-01 reproduced and corrected in Draft #46; consolidation and crypto registry in Draft #47–#48; control-plane decision in Draft #49; read-only Rust API in Draft #50 and React laboratory console in Draft #51. Draft #52 bounds management database requests after a focused security diff scan. Draft #53's disposable Docker Compose stack passed image build, startup and scoped OIDC/API/PostgreSQL smoke in CI; diagnostic request logging is the next increment. The console exercises a disposable OIDC code/PKCE fixture and real API/PostgreSQL reads, but no production IAM, persistent audit or policy-controlled HTTP issuance is delivered. See [execution status](docs/recovery/EXECUTION_STATUS.md).

> **Later laboratory checkpoint:** Draft #54 adds diagnostic request IDs, Draft #55 a lockfile SBOM, [Draft #56](https://github.com/knehari/trust-platform/pull/56) requires server-owned CA reader grants, [Draft #57](https://github.com/knehari/trust-platform/pull/57) adds bounded OIDC signing-key rotation, [Draft #58](https://github.com/knehari/trust-platform/pull/58) bounds management SQL statements, [Draft #59](https://github.com/knehari/trust-platform/pull/59) separates database readiness from process liveness, and [Draft #60](https://github.com/knehari/trust-platform/pull/60) bounds in-flight data requests before OIDC verification. #57–#60 passed exact-head CI and targeted Codex Security diff scans with no reportable findings. The dependent migration branch tests 0012–0013 against populated disposable data. These Drafts do not satisfy G0, human IAM, independent review or policy-controlled HTTP issuance.

> **Management database checkpoint — 18 October 2026:** Drafts [#61–#68](https://github.com/knehari/trust-platform/pulls) exercise populated management migration, logical restore within and across disposable PostgreSQL clusters, rollback after injected restore/migration failures, a restricted reader login, a transactional 0012–0013 migration ledger, and ledger continuity after restore. #67 and #68 passed CI on their code commits. These tests do not establish production backup, online upgrade, CA key recovery, RTO/RPO, or permission to merge the Draft stack.

> **Read-only application checkpoint:** Draft #69 adds bounded cursor pagination to certificate and audit history in the Rust API and React console. A local restricted PostgreSQL fixture proves two pages with equal timestamps and CA-scope denial. Its CI status is recorded on the PR; it does not add issuance, human IAM or a production history snapshot.

> **CA inventory checkpoint:** Draft #70 removes the silent 100-CA ceiling from the read-only API and console. A separate 102-CA fixture checks stable pages and exclusion of a CA named in the token but lacking a server-managed grant. Review and production data benchmarks remain open.

> **Read-only console checkpoint — 19 October 2026:** Drafts #71–#93 add scoped certificate/audit detail routes, metadata modals, independent loading/retry, filters over loaded rows, stale-inventory clearing and a local API route preflight. All seven checks passed on [Draft #93](https://github.com/knehari/trust-platform/pull/93) at `bb6c6b569bad5ec3134aa54f967fbefd2a4872c2`. These unmerged changes improve the laboratory consultation path only; HTTP issuance, real IAM, independent security review and G0 remain open.

> **Read-only console continuation — 20 October 2026:** Stacked Drafts #95–#106 add exact CA/certificate/audit ID lookups, page deduplication, independent history pagination, stale-request cancellation, request-ID error correlation and API route preflight. All seven checks passed on [Draft #106](https://github.com/knehari/trust-platform/pull/106) at `64d6bce4de728cfd792507e97b7fdf25f0e9b531` after GitHub Actions resumed scheduling. Earlier Drafts affected by the billing block are not retroactively validated. This remains a read-only laboratory console; see [execution status](docs/recovery/EXECUTION_STATUS.md) for tested paths and remaining limits.

> **Recovery update — 2026-10-17:** This roadmap was originally written on 2026-10-14 and is preserved from `main` on the R1 consolidation branch. Its status through PR #24 and its subsequent *planned* version labels are **historical**, not a current release state. Draft PRs #25–#41 contain additional laboratory contracts and classical crypto lab code; see the [technical audit (PR #42)](https://github.com/knehari/trust-platform/pull/42) and its [feature matrix](https://github.com/knehari/trust-platform/blob/codex/technical-recovery-audit/docs/recovery/FEATURE_MATRIX.md). **No version is released, no deployed PKI is claimed, and G0/security gates remain pending.**
