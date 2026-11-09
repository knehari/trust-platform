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

Third console pass (2026-11-08, display only): the overview is now a dashboard for the selected authority. It shows a role-aware "Needs attention" queue (requests to decide or issue, pending revocations, CRL renewal, expiring certificates, reconciliations, denials) with direct actions; KPI tiles; and two single-series bar charts (upcoming expiries, audit activity) with hover tooltips and a screen-reader table. Figures come from loaded rows and the API's status routes and say when they are partial. The audit trail gains outcome and category quick-filter chips with counts, plus day-group rows. Certificates show a recorded-lifetime bar. Every detail dialog opens as a slide-over panel. Verified on a fresh laboratory stack: 72 frontend tests and the four e2e suites.

Detail panels (2026-11-08, display only): certificate, audit event and profile revision details open as slide-over panels. Each has a coloured header with state badges and a summary: the recorded-validity timeline with days remaining; the audit outcome explained in one sentence; the profile lifecycle stepper. Facts are grouped, with one-click copy and in-place confirmation, and previous/next navigation works with ↑/↓ or j/k. An error boundary replaces a blank page with the error and a reload button. Verified on a fresh laboratory stack: 73 frontend tests and the four e2e suites.

Dark mode and toasts (2026-11-09, display only): `src/theme-dark.css` is generated from the two stylesheets by `frontend/dev/dark-theme.mjs`, which mirrors lightness and keeps hue. Dark-by-design surfaces (sidebar, tooltips, code blocks, toasts, backdrops) are left as they are. `dev/dark-theme.test.mjs` fails when the generated file is stale. A topbar control cycles system/light/dark; the choice stays in this browser only. CRL publication and request decisions confirm with a short toast; errors stay as notices in the page. Verified on a fresh laboratory stack: 76 frontend tests and the four e2e suites.

Revocation in the inventory (2026-11-09): migration 0033 appends `revoked_at` and `revocation_reason` to `management_certificate`, read from the core revocation table under the 0021 reader filter. The API returns both on certificate list and detail routes. OpenAPI documents them. The console shows "Revoked" with the reason and date in the inventory and the detail panel, counts revoked certificates apart on the dashboard, excludes them from upcoming expiries, and exports both fields in CSV and JSON. Verified locally: the new SQL suite and the existing management suites, the populated 0011→0033 upgrade, retry, ledger and restores, API unit tests and Clippy, 77 frontend tests, and the four e2e suites (the certificate-application suite checks the inventory after an approved revocation). CI has not yet run on this branch.

Issuance reconciliation (2026-11-09, ADR-0020 Proposed): migration 0034 lets two registration officers void an issuance left `RECONCILIATION_REQUIRED`. Neither may be the requester, and the confirmer is not the proposer. The proposal records whether the signer had claimed the intent. Confirmation takes the CA's CRL lock. The application becomes `VOIDED`; the serial is never reused and is listed, without reason code, on every CRL fixed afterwards. The CRL entry function, the signer's entry view and the readers' entry count all include it, so the API, the signer and the audit tool agree. Two API routes, OpenAPI, the console's "Needs reconciliation" tab and a dashboard item are added, plus a second laboratory officer (`lab-ra-officer-2`, uid 17). Verified locally:
- the new SQL suite and the existing management suites;
- the 0011→0034 upgrade, retry, ledger and restores;
- Rust unit tests and the database-backed HTTP test (a wrong-key signer, then propose, confirm and a CRL whose entry has no reason extension);
- `lab_verify_issued_certificates`;
- 78 frontend tests;
- the four e2e suites; the certificate-application suite voids a simulated timeout and OpenSSL finds the serial in the verified CRL.

Recovering a certificate that was signed but not stored remains open. CI has not yet run on this branch.

Automatic CRL renewal (2026-11-09, ADR-0021 Proposed): migration 0035 adds a per-CA `crl-publisher` role. Held by the system principal `urn:trust-platform:system`/`crl-renewer`, it may run the CRL publication functions only for a due CRL. The API runs a renewal pass every `TRUST_CRL_RENEWAL_INTERVAL_SECONDS` (Compose: hourly). Each pass goes through the unchanged journaled path. `crl-status` reports `auto_renewal`, and the console shows it. Verified locally:
- the new SQL suite and the existing CRL suites;
- the database-backed HTTP test, where the renewer publishes CRL 1 with the real signer and then does nothing;
- `lab_verify_issued_certificates`;
- 78 frontend tests;
- the four e2e suites on a lab with the renewer enabled.

CI has not yet run on this branch.
