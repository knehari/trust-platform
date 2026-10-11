# Sprint 0 — Engineering foundation

Status: proposed in draft PR; not merged or independently audited.

## Deliverables
- Cargo workspace with separate CA orchestration, policy and signing contracts.
- Default-deny policy and unconfigured signing provider.
- Pure issuance-state transition guard; no external signing or persistence.
- Rustfmt, Clippy and tests in CI.
- ADRs, threat model and data model.

## Deliberate exclusions
No X.509 issuance, ASN.1 parser, production key storage, HSM access, PostgreSQL migrations, ACME, OCSP or operational CA.

## Exit criteria
- CI passes on GitHub with locked dependency resolution.
- Security negative tests pass.
- ADRs reviewed.
- Legal/IP G0 confirmed.
- PR reviewed before merge.

## Traceability
Jira TRUST-11 through TRUST-15, TRUST-23, TRUST-27.
