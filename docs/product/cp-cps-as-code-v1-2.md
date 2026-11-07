# CP/CPS as Code — RFC 3647 draft engine, v1.2 laboratory increment

**Status: implementation in draft PR #12. No automatically approved, published or qualified CP/CPS.** This increment implements a small part of the existing [PRD v0.2 — CP/CPS Automation & Audit Readiness](https://app.notion.com/p/3f6e759bb68e81cc8892f0154b928d6c), specifically FR-013, FR-014 and the deterministic-diff foundation for FR-015.

## Product goal

Reduce PKI operators' repetitive work when authoring and maintaining **distinct** Certificate Policies (CPs) and Certification Practice Statements (CPSs). Build a controlled correspondence between **requested CA policy configuration**, administrative declarations, unresolved organizational controls, evidence requirements and the appropriate edition of approved documents.

A CP states requirements; a CPS states practices by which a CA is operated. An automatically generated CPS **must never assert** that a key ceremony, HSM control, vetting procedure, CRL/OCSP service or independent audit is implemented without an authenticated observation and relevant owner/assessor attestation.

## Technical increment delivered

- Pure, deterministic Rust module `crates/pki-core/src/cp_cps.rs` (no network or writing/publishing side effects).
- RFC 3647 main outline: 1 Introduction, 2 Publication, 3 Identification & Authentication, 4 Certificate Life Cycle, 5 Facility & Operational Controls, 6 Technical Security, 7 Certificate/CRL/OCSP, 8 Compliance Audit, 9 Business & Legal Matters. Selected core subsections are included, **not the full RFC 3647 detailed template**.
- Distinct CP and CPS **drafts** generated from a constrained policy configuration snapshot. Extracts requested policy OID, edition, configured DNS zones, profile, CA signing algorithm(s), maximum validity and SAN count; no disclosure of private actor allowlist.
- Exactly identifiable provenance per provision: Configuration / AdministrativeDeclaration / HumanEvidenceRequired.
- Missing organizational and operational information remains `PENDING HUMAN VALIDATION`; a published or compliant state is never generated.
- SHA-256 of canonical configuration input and of each generated Markdown document; no automatic document timestamps that would destroy reproducibility. Zone and algorithm order sorted and deduplicated before rendering.
- `compare` reports changed RFC section identifiers and mandatory reapproval when a generated document hash changes.
- Laboratory CLI example `draft_cp_cps` produces two `*.DRAFT.md` previews, uses file `create_new` to prevent silently overwriting previous output and explicitly does not provide publishing.
- Test suite checks repeatability, 9 main sections, limits/diff, zone ordering, no private actor leakage, hard publication blockers, invalid policy OIDs and metadata injection, invalid issuance profile and unsupported PQC claims.
- GitHub Actions CI checks both produced draft files, required warnings, RFC tests, rustfmt, Clippy and previous PKI database/HSM-simulation regressions.

## Explicit current limitations

**Source is a policy configuration, NOT the deployed CA configuration.** Provenance labels make this difference explicit. Actual deployed config attestation and HSM/CRL verification require other interfaces. The OID syntax is validated, but legal control/ownership is not; the example `1.3.6.1.4.1.55555.1.1` is an unassigned **fixture**, NOT a registered product policy OID.

Drafted clauses are short prompts/technical descriptions, **not an approved or comprehensive CP/CPS**, and intentionally contain unresolved evidence placeholders. No legal warranties, full RFC 3647 granular crosswalk, enforceable document approvals, signatures, document repository, operator identities, automatic drift notification or live publication exist.

Neither the documents nor the module imply ISO/IEC 27099, ETSI EN 319 401, EN 319 411-1/2, ANSSI or eIDAS conformity or qualification. A PKI architecture may facilitate relevant assessment processes, but a qualified certificate or QTSP status requires assessment against applicable provider, policy, cryptographic, governance and organizational controls and formal decisions by competent actors.

## Acceptance coverage and planned increments

| PRD requirement | v1.2 status | Remaining work |
|---|---|---|
| FR-013 RFC 3647 CP generation | Partial implementation | Complete subsections, approved text/organizational clauses and OID ownership records |
| FR-014 CPS generation from verified practices | Partial skeleton only | Read verified runtime configuration plus HSM, CA, CRL/OCSP and identity control evidence |
| FR-015 drift/change impact | Manual function tests | Durable policy history, event notifications, proposed revision workflow and affected-CA impact |
| FR-016 review/publish approval | Not implemented | Authenticated CP/CPS owners, four-eyes workflow, signatures/effective dates |
| FR-017 immutable document-to-certificate binding | Not implemented | Connect final approved policy document SHA and OID to X.509 issuance journal |
| FR-018 publication | Not implemented | Post-approval publisher, version archive, integrity monitors; may integrate with CLM |
| FR-020–026 audit/eIDAS readiness | Architecture only | Versioned controls catalog, verified evidence, qualified readiness profile, independent review |

## Security acceptance gates

G0 employer/IP separation, reviewed legal usage and independent code/security review before merging or production exposure. Real business data, real policy OIDs and real operational claims require approved sources. Never publish a generated draft automatically or mark a missing evidence control 'compliant'.

### How to run in the isolated CI/lab

```bash
cargo test -p trust-pki-core --locked
cargo run --locked -p trust-pki-core --example draft_cp_cps -- target/cp-cps-preview
```

The output directory is for **private previews**. Use a fresh directory for each run (the CLI deliberately refuses to overwrite previous drafts).

### Sources
- [RFC 3647 — CP and CPS Framework, Section 6](https://www.rfc-editor.org/rfc/rfc3647.html#section-6)
- [ETSI](https://www.etsi.org/), edition-specific security/CA requirements to be assessed only when in scope.
- Existing Notion PRD v0.2 FR-013 to FR-026 (planning baseline).
