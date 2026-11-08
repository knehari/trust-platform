# Development status — first integration phase

**Checked 2026-11-07.** This tree combines the Claude profile lifecycle stack, the distinct approval-key fix, the recovery audit, repository instructions and the local filter/revision work. It is laboratory code. **MVP progress remains 5/12 (42%)**: the CA half of criterion 6, authenticated issuance, revocation, custody, recovery and release gates remain open.

## Implemented in the combined tree

- The management API and console can record, submit, approve/reject and activate/retire profile revisions in the laboratory. Activation binds an exact digest and declared CA capability; issuance does not consume an active profile. The CA itself has no protected key and certificate lifecycle in this stack.
- Migrations 0012–0024 provide scoped management reads and profile lifecycle operations. Migration 0025 adds a database trigger that rejects non-contiguous draft revisions, including bulk owner writes, without activating any profile.
- The isolated Keycloak lab exercises human and workload tokens. Read access intersects signed CA scope with server-owned grants; profile writes require the lifecycle role and a separate writer login. This remains a loopback laboratory configuration without production MFA, TLS transport or key custody.
- The console and OpenAPI contract include the local filter validation and cursor checks. The API's no-principal readiness gate checks all seven management views.

## Verification and remaining integration

The combined frontend has 57 passing tests and builds. Rust format, full workspace tests with and without all features, and management API tests pass (34 management tests without database variables). A fresh disposable PostgreSQL 16 database accepts migrations 0001–0025, and the profile revision, lifecycle, decision and activation SQL suites pass. A populated 0011→0025 upgrade preserves rows and reader grants; the 0025 migration rejects a pre-existing gap and serializes concurrent revision writes. Complete CI and database-backed HTTP tests remain open on the final integrated head. The 5173 instance still runs the earlier local integration, not this tree.

The separate experimental PR #94 contains revocation, CRL and signed administration on an incompatible migration history beginning at 0014. An incomplete port is published on [`codex/revocation-port-onto-profile`](https://github.com/knehari/trust-platform/tree/codex/revocation-port-onto-profile); its roles, views, APIs, migration runner and recovery tests still need integration and exact-head verification before `main` can represent all requested PRs. The user confirmed completion of G0 legal/IP clearance and independent security review on 2026-11-07; the review artifacts have not been linked in this repository checkpoint.

## Console redesign (2026-11-08, display only)

The laboratory console was reorganised by task: separate **Requests** (tabs by status, row actions, persistent notices) and **Revocation & CRLs** (status, distribution point, publication, published CRLs) sections; CA lifecycle moved to **Authorities**; compact tables with select-all, select-filtered and indeterminate header checkboxes for certificates, audit events and profile proposals; one SVG icon set, badges, buttons and notices that stay until dismissed. Navigation follows token roles, but the API stays the authority for every decision. No API, migration or authorization change. Verified locally on a fresh laboratory stack: 61 frontend tests, typecheck, build, and the browser, profile-lifecycle, CA-proposal and certificate-application suites. Known gap: the certificate inventory shows the issuance state (`SIGNED`) even for revoked certificates; showing revocation there needs a management view change.

Second console pass (2026-11-08, display only): every audit event type now shows a readable label, a category icon and its raw code. Every outcome is a badge, including state transitions (`SIGNING → SIGNED`) and references (`created:<id>`). Statuses read as words, with the raw code kept as a tooltip. Times are relative, with the exact time beneath. A Ctrl/⌘ K palette jumps to sections and authorities; loading uses skeleton rows; long tables keep their header visible; focus rings and motion respect `prefers-reduced-motion`. Verified on a fresh laboratory stack with 65 frontend tests and the four browser/API e2e suites.
