# Development status — integration checkpoint

**Checked 2026-11-07.** The `codex/main-all-prs-integration` branch combines the Claude profile lifecycle stack, the distinct approval-key fix, the recovery audit, repository instructions and the local filter/revision work. It is a laboratory integration branch. **MVP progress remains 5/12 (42%)**: the CA half of criterion 6, authenticated issuance, revocation, custody, recovery and release gates remain open.

## Implemented in the combined tree

- The management API and console can record, submit, approve/reject and activate/retire profile revisions in the laboratory. Activation binds an exact digest and declared CA capability; issuance does not consume an active profile. The CA itself has no protected key and certificate lifecycle in this stack.
- Migrations 0012–0024 provide scoped management reads and profile lifecycle operations. Migration 0025 adds a database trigger that rejects non-contiguous draft revisions, including bulk owner writes, without activating any profile.
- The isolated Keycloak lab exercises human and workload tokens. Read access intersects signed CA scope with server-owned grants; profile writes require the lifecycle role and a separate writer login. This remains a loopback laboratory configuration without production MFA, TLS transport or key custody.
- The console and OpenAPI contract include the local filter validation and cursor checks. The API's no-principal readiness gate checks all seven management views.

## Verification and remaining integration

The combined frontend has 57 passing tests and builds. Rust format and the management API tests pass (34 tests without database variables). A fresh disposable PostgreSQL 16 database accepts migrations 0001–0025, and the profile revision, lifecycle, decision and activation SQL suites pass. A populated 0011→0025 upgrade preserves rows and reader grants; the 0025 migration rejects a pre-existing gap and serializes concurrent revision writes. Complete CI and database-backed HTTP tests remain open on the final integrated head. The 5173 instance still runs the earlier local integration, not this branch.

The separate experimental PR #94 contains revocation, CRL and signed administration on an incompatible migration history beginning at 0014. It has not been ported to this tree. Its roles, views, APIs and recovery tests need integration and exact-head verification before `main` can represent all requested PRs. The user confirmed completion of G0 legal/IP clearance and independent security review on 2026-11-07; the review artifacts have not been linked in this repository checkpoint.
