# Trust Platform — Product & Engineering Roadmap

> Status date: 2026-10-22 · Owner: Trust Platform · Repository: `knehari/trust-platform`
> **This is a technical roadmap, not a release announcement.** Versions below label laboratory increments and proposed future milestones, not published production releases.

## Status conventions

- **LAB-VALIDATED**: code and relevant tests evidenced on an exact laboratory tree; the change may still be in a Draft PR and is not production approved.
- **LAB-PROTOTYPE**: scoped code/contract and tests available; full integration, CI and independent review may remain open.
- **PLANNED**: proposed scope, no implementation claim. Future version numbers are planning labels, subject to architecture review.
- **G0 BLOCKED**: legal/employment/IP separation and independent security review required before merge or commercialization.

## Current baseline and release hygiene

- **`main` remains a documentation baseline, not a shipped CA.** Laboratory implementation lives across historical and stacked PR branches; [Draft #135](https://github.com/knehari/trust-platform/pull/135) is not merged into `main`. The revocation, CRL and signed-administration lab slice lives in the integration [Draft #94](https://github.com/knehari/trust-platform/pull/94) (stack #1–#70 plus the slice; marked do-not-merge), described [below](#revocation-crl-and-signed-administration-lab-slice-draft-94). The version history below records **development milestones**, not GitHub releases.
- Technical test success is not production readiness; no eIDAS/ETSI/ANSSI qualification, no QTSP certification, no audited production HSM custody or network-facing production CA claimed.
- Do not bulk-merge stacked work. Resolve G0, review each diff and migration in dependency order, assess security and cryptographic algorithms, validate isolated CI, then merge through authorized review gates.

## MVP: controlled single-tenant PKI pilot

The first viable version means an authorized operator can create a CA and a certificate profile, issue and revoke a certificate through authenticated application routes, inspect durable evidence, and recover the service and its protected keys in a controlled pilot. It is **not** a qualified trust service or a general-availability release.

**Progression: 4/12 criteria evidenced (33%)** · `████░░░░░░░░` · **MVP not reached**.

Each checkbox is one criterion, so the bar is `completed / 12`, rounded to the nearest whole percent. A checked foundation means implemented and tested **in the laboratory**, including code still in a Draft PR; it does not mean merged, independently reviewed or production-approved. An unchecked criterion may have partial prototypes, but its full MVP acceptance condition remains open.

- [x] **CA core and safe issuance foundations:** policy checks, issuer-scoped serial/idempotency, durable intent, independent signature verification and ambiguity-safe recovery in laboratory paths ([PRs #1–#9](https://github.com/knehari/trust-platform/pulls), [recovery status](https://github.com/knehari/trust-platform/blob/0d0697d28945a8acb8891f7bef6e3da495a82563/docs/recovery/EXECUTION_STATUS.md)).
- [x] **Scoped read API:** OIDC-token and server-owned CA-grant checks, bounded reads, readiness and cursor pagination are exercised against disposable PostgreSQL ([Drafts #50–#70](https://github.com/knehari/trust-platform/pulls)). The test issuer is not human IAM.
- [x] **Read-only operator console:** CA/certificate/audit consultation, detail dialogs, search, export and recorded-date filters are exercised in the laboratory; the latest increment is [Draft #135](https://github.com/knehari/trust-platform/pull/135). These views do not issue or revoke certificates.
- [x] **Reproducible laboratory stack and data checks:** disposable Compose/browser flow, restricted database role, migrations and logical restore regressions ([Drafts #53, #61–#69 and PR #129](https://github.com/knehari/trust-platform/pulls)). This is not operational disaster recovery.
- [ ] **Human IAM and authorization:** real IdP, workload identity, least-privilege roles and independently authenticated maker/checker actors, with negative access tests.
- [ ] **CA and profile lifecycle:** policy-controlled API and console workflows to create, approve, activate and retire CAs and versioned certificate profiles; no direct database bypass.
- [ ] **Application issuance:** authenticated CSR submission and approval, profile enforcement, Core orchestration, idempotent API result and end-to-end negative/fault tests.
- [ ] **Revocation and publication:** authorized revocation with durable audit evidence and verifiable CRL publication; OCSP and broader path validation require a separate design decision.
- [ ] **Protected signing keys:** real HSM/PKCS#11 integration, key ceremony, custody and tested ambiguous-outcome reconciliation; software laboratory keys do not meet this criterion.
- [ ] **Durable audit evidence:** persisted authenticated event chain, integrity/tamper checks, exportable verification manifest and governed retention.
- [ ] **Operational recovery:** protected database and key backup/restore, migration rollback, incident runbooks and measured pilot RTO/RPO.
- [ ] **Release gates:** G0 legal/IP clearance, independent PKI/security review, final-commit CI and an explicitly approved controlled-pilot release decision.

Laboratory parts of the *revocation and publication*, *durable audit evidence* and *operational recovery* criteria exist in [Draft #94](#revocation-crl-and-signed-administration-lab-slice-draft-94) (maker-checker and WebAuthn-signed revocation, verified CRL publication, sealed audit chain with external checkpoints, a logical restore rehearsal). None of these criteria is checked: each still needs human IAM, a real HSM, independent review or a designed recovery exercise.

### Next implementation sequence

- [x] Add an exclusive server-side filter on recorded certificate validity end, keep it across pages and exercise it in the browser ([Draft #135](https://github.com/knehari/trust-platform/pull/135); all six checks green on `9a640193b7e67d77b0770a3516a8ae369afeed82`).
- [ ] Measure filtered-history query plans and load through the security-barrier views; add only justified indexes or query changes.
- [ ] Specify CA and profile lifecycle, actor permissions, approval states and immutable policy/version binding before adding write routes.
- [ ] Implement versioned profile management and then CA creation with denial, concurrency and recovery tests.
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

## Revocation, CRL and signed administration lab slice (Draft #94)

Status on 22 October 2026: full CI green at `b349e56` (migrations up to 0058, restore rehearsal, scheduled lab jobs); later commits verified locally (`claude/friendly-hopper-3l9y56`).
Integration Draft [#94](https://github.com/knehari/trust-platform/pull/94) is marked
do-not-merge and only runs CI. Maturity: **LAB-PROTOTYPE / G0 BLOCKED**. Nothing
below is released, deployed or accepted. ADR-0006 and ADR-0007 are **Proposed**:
the lab implementation was made at the repository owner's request, and that is
not an acceptance of either ADR.

**Evidence at `b76bbcd`**
- GitHub Actions: all 15 jobs green: rust, schema, compose-smoke, six fuzz
  targets, cargo-deny, gitleaks, lockfile-sbom, build, gate-race and
  preservation.
- Local run (Rust 1.99.0, PostgreSQL 16):
  - `cargo fmt`; clippy with `-D warnings`, with all features and with default
    features;
  - workspace tests: 360 passed, 0 failed;
  - every SQL suite, and the PostgreSQL integration and API tests with
    `TRUST_REQUIRE_DATABASE=1`;
  - OpenSSL interoperability;
  - populated upgrade from 0013 to 0054;
  - verified TLS 1.3 to PostgreSQL in Docker.
- Each security change since migration 0035 has a RED test, failing on the
  previous schema or code, or a mutation that the test detects.

### Done (lab)

| Area | Migrations / code | What it enforces in the lab |
| --- | --- | --- |
| Status lifecycle | 0014, 0018–0019, 0025, 0034 | Maker-checker suspend, release and revoke (RFC 5280 reasons). Definitive revocation is irreversible. Invalidity dates are bounded. Lock order is fixed (deadlock test). Pending changes can be read. |
| CRL pipeline | 0015–0017, 0020–0022, 0031–0033, 0055, 0058–0060 | The CRL number is reserved before signing and never reused. The signing intent is bound to entries, number and times. The CRL is verified independently before it is stored. Ambiguous outcomes are quarantined, and a held DER can be reconciled. One issuer certificate per CA. After a restore from an older backup, a superuser raises a CRL number floor so no published number is reused (0058). Delta CRLs (0059) list what changed since the latest complete CRL, including released holds as removeFromCRL. They share the numbering, are served only at a separate `/delta` path, and never count as a complete CRL for publication deadlines; OpenSSL applies them with `-extended_crl -use_deltas`. After a restore from an older backup, `crl_restore_revocations` (0060) re-applies the revocations listed on the last published CRL, once the CRL verifies against the registered issuer. Expired entries can be pruned (opt-in, refused for ETSI EN 319 411-2); housekeeping backfills `notAfter` from the stored DER for certificates stored before 0031. Operator CA list. OpenSSL interop and a fuzz target. |
| CRL distribution | 0030 | Lab read-only HTTP distribution point; it re-verifies each CRL before serving it. Issued lab certificates can carry an opt-in CDP extension. |
| Least privilege | 0023, 0035, 0043 | Tables are owned by NOLOGIN roles. Service functions are `SECURITY DEFINER` with a pinned `search_path`. Capability roles are EXECUTE-only (officer API, CRL signer and operator, CA admin, issuance, policy admin, reconciliation, audit). Service connections refuse privileged logins. |
| CA administration | 0024, 0037, 0040, 0042, 0044, 0050, 0052, 0054 | Issuer registration, officer grants and credential changes need two admins. Once a CA opts in, they are WebAuthn-signed with distinct keys and persons, and so are admin keys and rejections. Checkers see the signed content (digest recomputed in Rust) and whether the maker's stored signature re-verifies; an approval is never written, and no approval challenge is issued, for a proposal whose maker signature does not re-verify. Proposals expire after 7 days by default: the API flags them and issues no approval challenge, and housekeeping alerts on them. |
| Signed status changes (ADR-0007) | 0028–0029, 0036, 0038–0039, 0047 | Officer WebAuthn registry and canonical claim. The assertion is verified in Rust before any write, and the database re-checks everything but ECDSA. Rejection and withdrawal are signed. The maker's stored signature is re-verified before an approval is written (and shown to checkers), and signed submissions are refused while the database clock is untrusted. A single officer can apply a precautionary hold, with a deadline, a per-officer cap and a per-CA cap. |
| Break-glass (minimal) | 0045–0046, 0048, 0051 | A DBA-enrolled emergency key whose custodian person never signs on the CA. It can only re-enrol admin keys, and only while the CA has fewer than two. Every use is audited and alerted until two other admins review it. Reviews require evidence that re-verifies, when the challenge is issued and again when the review is written, and a key from a use whose evidence does not re-verify signs nothing through the Rust core. Registry enrolments are serialised. |
| Challenges | 0049, 0053 | At most 16 open challenges per actor and CA. Challenges that expired unused are purged after 30 days; consumed ones are kept as evidence. Concurrent consumption is tested. |
| Audit and evidence | 0026–0027, 0041 | DDL and grants are audited by event triggers. A sealed hash chain with signed checkpoints is anchored outside the database (lab); the anchoring job uses verified TLS and refuses privileged logins. Offline re-verification of every signature (`signed_evidence_audit`, one CA or `--all`, exit 3 on failure). Database clock skew is checked against the Rust core. |
| Backup and restore | `tests/revocation_backup_restore.sh` | A logical backup of the populated revocation database restores into an empty database in the same cluster. Rows, sequences, owners, ACLs, definer settings and triggers are identical. Privilege invariants hold, and the offline evidence audit gives the same result. The audit chain verifies against the checkpoint taken before the backup, and a stale backup is refused against a later checkpoint. |
| Lab services and jobs | management-api binaries | `revocation_api` and `ca_admin_api` take OIDC tokens and enforce CA scope before any write. Per identity, they allow 60 requests per minute across all replicas (0062; the read API 300 per process) and 64 KiB bodies; responses carry `no-store` and `nosniff`. They serve TLS 1.3 when given a certificate, and plain HTTP only on loopback or with a logged lab opt-out. The CRL distribution point reuses a verified CRL for 30 s. `crl_distribution`, `crl_housekeeping` and `signed_evidence_audit` are also lab binaries. The lab Compose stack runs housekeeping, the evidence audit and audit chain sealing and verification on a schedule, each under its own login. All use verified TLS 1.3 to PostgreSQL by default. OpenAPI contracts: `openapi/revocation-v1.yaml`, `openapi/ca-admin-v1.yaml`. |

Progress against the historical proposed versions (labels only):
- **v2.5:** partial (audit chain, checkpoints, offline evidence audit).
- **v2.6:** partial (authenticated lab APIs, rate limits; no mTLS or workload
  identity).
- **v2.9:** partial (complete and delta CRLs with lab publication, a 17-case
  path-validation suite; no OCSP, no multi-level path validation).
- **v3.1:** partial (signed CA administration and separation of duties for
  revocation only).

### Remaining before any non-lab use

Human gates (not self-approvable):
- G0 legal and IP clearance.
- Independent security and cryptographic review, including every
  `SECURITY DEFINER` function.
- Acceptance of ADR-0006: its conditions 1–6, including runtime without
  superuser, external audit anchor storage and authenticated time.
- Acceptance of ADR-0007.
- An IAM decision on person identifiers, the authenticator and attestation
  policy, and allowed models.
- CPS text for suspension, precautionary holds and break-glass.
- An on-call rota.

Engineering backlog:
- **Signing:** a real HSM/PKCS#11 signer with key custody and ceremonies (lab
  CA keys are ephemeral). CA key rollover (several issuer certificates per CA)
  is not modelled.
- **Validation services:** OCSP, scheduled delta CRL issuance (deltas are
  reserved, signed, stored and served on demand), highly available CRL
  publication, and path validation beyond one level (intermediates, name
  and policy constraints, PKITS). The platform's certificates and CRLs pass
  a 17-case RFC 5280 suite under webpki and OpenSSL
  (`docs/testing/rfc5280-path-validation.md`) (v2.9).
- **Identity:** production IAM integration. Person identifiers are
  caller-supplied, so one human under two identifiers is not detected.
  WebAuthn attestation is not checked.
- **Runtime:**
  - dedicated service logins and secrets management;
  - scheduled deployment outside the lab (the lab Compose stack runs
    `crl_housekeeping`, `signed_evidence_audit` and the audit chain jobs
    under dedicated logins; nothing pages anyone);
  - mTLS and certificate management for the HTTP side (the token APIs
    serve TLS 1.3 when given a certificate and refuse plain HTTP off
    loopback unless the logged lab opt-out is set);
  - a per-IP or per-client limit (the per-identity budget is shared across
    replicas in the database since 0062; the read API's stays per process).
- **Database assurance:**
  - server-side logging of role changes (pgaudit);
  - storage of the external audit anchor;
  - authenticated time (NTS);
  - online upgrade and RTO/RPO (logical restores into the same cluster and
    into a fresh cluster are rehearsed; re-applying revocations from the
    last published CRL after an older backup has a tool and a runbook);
  - recovering certificates issued after the backup a database was
    restored from (reported by the restore tool, not recovered).
- **Residual lab risks:**
  - The database cannot verify ECDSA, so a holder of a service role could
    store a forged assertion. Re-verification exposes it; a forged break-glass
    use cannot be reviewed, and its admin key signs nothing through the Rust
    core, but stays enrolled until two admins remove it.
  - The challenge table keeps consumed challenges and 30 days of unused ones.
  - `reconcile_crl` needs the caller to still hold the DER.
  - Certificates stored before 0031 whose stored DER does not parse stay
    without `notAfter` (reported by housekeeping, never pruned).
- **Hygiene:**
  - Migrations copy whole function bodies, and the audit-decision helpers
    are duplicated (the CRL entries digest has one definition since 0061,
    guarded by `tests/crl_entries_digest.sql`).
  - Migration-retry and ledger scripts stop at 0013; `scripts/lab/migrate.sh`
    upgrades an existing database from 0026 on, without checksums of the
    applied files.
  - Four historical issuance suites are not idempotent on a reused database
    (they rely on the CI-seeded CA; CI runs them on a fresh one).
  - See `docs/superpowers/plans/2026-10-18-revocation-crl-followups.md`.
- **Integration path:**
  - Review and merge the stacked Drafts #1–#70 in dependency order.
  - Split Draft #94 into reviewable PRs.
  - Rerun CI on the final merged commit.

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

- [Architecture](https://github.com/knehari/trust-platform/blob/0d0697d28945a8acb8891f7bef6e3da495a82563/docs/architecture/system-overview.md)
- [Issuance state machine](https://github.com/knehari/trust-platform/blob/0d0697d28945a8acb8891f7bef6e3da495a82563/docs/architecture/issuance-state-machine.md)
- [Security threat model](https://github.com/knehari/trust-platform/blob/0d0697d28945a8acb8891f7bef6e3da495a82563/docs/security/threat-model.md)
- [Security acceptance gates](https://github.com/knehari/trust-platform/blob/0d0697d28945a8acb8891f7bef6e3da495a82563/docs/testing/acceptance-gates.md)
- On the Draft #94 branch: [ADR-0006 revocation write model](docs/adr/ADR-0006-revocation-write-model.md) and [ADR-0007 signed double control](docs/adr/ADR-0007-signed-double-control.md) (both Proposed), [revocation/CRL follow-ups](docs/superpowers/plans/2026-10-18-revocation-crl-followups.md), [lab break-glass](docs/operations/lab-break-glass.md), [CRL housekeeping](docs/operations/lab-crl-housekeeping.md), [revocation restore rehearsal](docs/operations/lab-revocation-backup-restore.md)
- [GitHub pull requests](https://github.com/knehari/trust-platform/pulls)
- [Jira TRUST](https://knehari.atlassian.net/jira/software/projects/TRUST)

## Maintenance rules

- Update this file whenever a PR lands or scope changes; record actual status, test evidence, reviewer and merged commit.
- A version is **released** only after the release checklist, approved tag and documentation are published; draft PR numbers alone do not imply release.
- Keep roadmap features, design proposals and implementation evidence separately traceable.

## Historical execution notes (archive)

> **Revocation, CRL and signed-administration lab slice — 22 October 2026 (integration Draft [#94](https://github.com/knehari/trust-platform/pull/94); not a release):** migrations 0014–0062 add a maker-checker certificate status lifecycle, a CRL pipeline with a lab distribution point, least-privilege service roles, WebAuthn-signed double control for status changes and CA administration (ADR-0007, Proposed), a minimal break-glass path, an audit chain with external checkpoints, and four lab HTTP services and jobs. CI was green on all workflows at `b349e56`. LAB-PROTOTYPE only: ephemeral lab CA key, no OCSP, no delta CRLs, no production IAM or HSM; G0, independent review and ADR-0006/0007 acceptance are open. Done and remaining work: [section below](#revocation-crl-and-signed-administration-lab-slice-draft-94).

> **Execution checkpoint — 2026-10-17:** PRs #43–#45 reverified green on exact trees; C-01 reproduced and corrected in Draft #46; consolidation and crypto registry in Draft #47–#48; control-plane decision in Draft #49; read-only Rust API in Draft #50 and React laboratory console in Draft #51. Draft #52 bounds management database requests after a focused security diff scan. Draft #53's disposable Docker Compose stack passed image build, startup and scoped OIDC/API/PostgreSQL smoke in CI; diagnostic request logging is the next increment. The console exercises a disposable OIDC code/PKCE fixture and real API/PostgreSQL reads, but no production IAM, persistent audit or policy-controlled HTTP issuance is delivered. See [execution status](https://github.com/knehari/trust-platform/blob/0d0697d28945a8acb8891f7bef6e3da495a82563/docs/recovery/EXECUTION_STATUS.md).

> **Later laboratory checkpoint:** Draft #54 adds diagnostic request IDs, Draft #55 a lockfile SBOM, [Draft #56](https://github.com/knehari/trust-platform/pull/56) requires server-owned CA reader grants, [Draft #57](https://github.com/knehari/trust-platform/pull/57) adds bounded OIDC signing-key rotation, [Draft #58](https://github.com/knehari/trust-platform/pull/58) bounds management SQL statements, [Draft #59](https://github.com/knehari/trust-platform/pull/59) separates database readiness from process liveness, and [Draft #60](https://github.com/knehari/trust-platform/pull/60) bounds in-flight data requests before OIDC verification. #57–#60 passed exact-head CI and targeted Codex Security diff scans with no reportable findings. The dependent migration branch tests 0012–0013 against populated disposable data. These Drafts do not satisfy G0, human IAM, independent review or policy-controlled HTTP issuance.

> **Management database checkpoint — 18 October 2026:** Drafts [#61–#68](https://github.com/knehari/trust-platform/pulls) exercise populated management migration, logical restore within and across disposable PostgreSQL clusters, rollback after injected restore/migration failures, a restricted reader login, a transactional 0012–0013 migration ledger, and ledger continuity after restore. #67 and #68 passed CI on their code commits. These tests do not establish production backup, online upgrade, CA key recovery, RTO/RPO, or permission to merge the Draft stack.

> **Read-only application checkpoint:** Draft #69 adds bounded cursor pagination to certificate and audit history in the Rust API and React console. A local restricted PostgreSQL fixture proves two pages with equal timestamps and CA-scope denial. Its CI status is recorded on the PR; it does not add issuance, human IAM or a production history snapshot.

> **CA inventory checkpoint:** Draft #70 removes the silent 100-CA ceiling from the read-only API and console. A separate 102-CA fixture checks stable pages and exclusion of a CA named in the token but lacking a server-managed grant. Review and production data benchmarks remain open.

> **Read-only console checkpoint — 19 October 2026:** Drafts #71–#93 add scoped certificate/audit detail routes, metadata modals, independent loading/retry, filters over loaded rows, stale-inventory clearing and a local API route preflight. All seven checks passed on [Draft #93](https://github.com/knehari/trust-platform/pull/93) at `bb6c6b569bad5ec3134aa54f967fbefd2a4872c2`. These unmerged changes improve the laboratory consultation path only; HTTP issuance, real IAM, independent security review and G0 remain open.

> **Read-only console continuation — 20 October 2026:** Stacked Drafts #95–#106 add exact CA/certificate/audit ID lookups, page deduplication, independent history pagination, stale-request cancellation, request-ID error correlation and API route preflight. All seven checks passed on [Draft #106](https://github.com/knehari/trust-platform/pull/106) at `64d6bce4de728cfd792507e97b7fdf25f0e9b531` after GitHub Actions resumed scheduling. Earlier Drafts affected by the billing block are not retroactively validated. This remains a read-only laboratory console; see [execution status](https://github.com/knehari/trust-platform/blob/0d0697d28945a8acb8891f7bef6e3da495a82563/docs/recovery/EXECUTION_STATUS.md) for tested paths and remaining limits.

> **Recovery update — 2026-10-17:** This roadmap was originally written on 2026-10-14 and is preserved from `main` on the R1 consolidation branch. Its status through PR #24 and its subsequent *planned* version labels are **historical**, not a current release state. Draft PRs #25–#41 contain additional laboratory contracts and classical crypto lab code; see the [technical audit (PR #42)](https://github.com/knehari/trust-platform/pull/42) and its [feature matrix](https://github.com/knehari/trust-platform/blob/codex/technical-recovery-audit/docs/recovery/FEATURE_MATRIX.md). **No version is released, no deployed PKI is claimed, and G0/security gates remain pending.**
