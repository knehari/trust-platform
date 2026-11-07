# PRD v0.2 — CP/CPS automation and audit readiness

**Status:** accepted product requirement intent; not implemented.

Authoritative full PRD: [Notion v0.2](https://app.notion.com/p/3f6e759bb68e81cc8892f0154b928d6c). This engineering index augments, **does not replace**, original PRD v0.1 FR-001…FR-012 and NFR-01…NFR-06.

## New capabilities and backlog

| ID | Feature | Jira | Priority | Target |
|---|---|---|---|---|
| FR-013 | CP drafts based on RFC 3647 and approved technical + organizational facts | TRUST-54 | P1 | CA Beta |
| FR-014 | CPS drafts linked to verified practices/evidence | TRUST-55 | P1 | CA Beta |
| FR-015 | CP/CPS drift detection, proposed revision and diff | TRUST-56 | P1 | Platform |
| FR-016 | Four-eyes approval/controlled effective date | TRUST-57 | P1 | Platform |
| FR-017 | Immutable versioned CP/CPS-to-CA/profile/policy-OID mapping | TRUST-58 | P1 | Platform |
| FR-018 | Controlled automatic publication and availability monitoring | TRUST-59 | P2 | CLM |
| FR-019 | Multiple policies/CAs, reusable clauses and public/private disclosure | TRUST-60 | P2 | CLM |
| FR-020 | Applicable controls catalog pinned to standard editions | TRUST-61 | P1 | Platform |
| FR-021 | Provenance-linked, tamper-evident evidence collection | TRUST-62 | P1 | Architecture -> Platform |
| FR-022 | Control owners, evidence state, gaps and exceptions | TRUST-63 | P1 | Platform |
| FR-023 | Reproducible offline auditor evidence bundle | TRUST-64 | P2 | Enterprise |
| FR-024 | Auditable maker-checker controls and key ceremony records | TRUST-65 | P1 | Architecture -> Platform |
| FR-025 | Optional eIDAS qualified-certificate readiness profiles | TRUST-66 | P2 | Enterprise |
| FR-026 | Continuous reassessment following standard/CA/crypto changes | TRUST-67 | P2 | Enterprise |

**NFR-07…NFR-11:** audit integrity and retention, controlled CP/CPS publication, version-pinned standards, offline evidence export, least-privilege auditor access.

## CP vs CPS

- **CP:** the requirements and permitted uses under a certificate policy (with an OID).
- **CPS:** documented practices for implementing one or more CPs, including human/operational procedures.
- Deriving a draft from the CA config is useful but **cannot prove** physical, identity-proofing, HR, legal, or organizational practices. The generator must label gaps *unverified* and obtain attestation and approval; no silent auto-approval.

## Standards versioning and classification

- [RFC 3647](https://www.rfc-editor.org/info/rfc3647/) — CP/CPS content framework.
- [ISO/IEC 27099:2022](https://www.iso.org/standard/56590.html) — PKI practices and policy framework.
- ETSI EN 319 401, ETSI EN 319 411-1 and EN 319 411-2 — standard editions must be selected by applicability and effective date.
- ANSSI/eIDAS: mapping for preparation and evidence collection; **not automatic qualification**.
- Reproduce only standards text that is legally licensed. Store control IDs and proprietary analyst-authored paraphrases, references, version and applicable scope.

**Important:** A CA software product is not a qualified trust-service provider (QTSP). Qualified certificates and services depend on the *operating organization*, process controls, conformity assessment, supervisory decision and relevant trusted-list status.

## Strategic positioning

**English:** Audit-ready PKI by design — built to support ETSI, ISO/IEC 27099 and eIDAS readiness with traceable evidence and automated CP/CPS governance.

**French:** Une PKI conçue pour faciliter l'audit : politiques et pratiques documentées, contrôles traçables et preuves exploitables pour les référentiels ETSI, ISO/IEC 27099 et eIDAS, selon leur applicabilité.

No promise of certification, qualified status, ANSSI audit success or 100% automatic compliance.
