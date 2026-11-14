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

Revocation in the inventory (2026-11-09): migration 0033 appends `revoked_at` and `revocation_reason` to `management_certificate`, read from the core revocation table under the 0021 reader filter. The API returns both on certificate list and detail routes. OpenAPI documents them. The console shows "Revoked" with the reason and date in the inventory and the detail panel, counts revoked certificates apart on the dashboard, excludes them from upcoming expiries, and exports both fields in CSV and JSON. Verified locally: the new SQL suite and the existing management suites, the populated 0011→0033 upgrade, retry, ledger and restores, API unit tests and Clippy, 77 frontend tests, and the four e2e suites (the certificate-application suite checks the inventory after an approved revocation). CI passed on Draft #194.

Issuance reconciliation (2026-11-09, ADR-0020 Proposed): migration 0034 lets two registration officers void an issuance left `RECONCILIATION_REQUIRED`. Neither may be the requester, and the confirmer is not the proposer. The proposal records whether the signer had claimed the intent. Confirmation takes the CA's CRL lock. The application becomes `VOIDED`; the serial is never reused and is listed, without reason code, on every CRL fixed afterwards. The CRL entry function, the signer's entry view and the readers' entry count all include it, so the API, the signer and the audit tool agree. Two API routes, OpenAPI, the console's "Needs reconciliation" tab and a dashboard item are added, plus a second laboratory officer (`lab-ra-officer-2`, uid 17). Verified locally:
- the new SQL suite and the existing management suites;
- the 0011→0034 upgrade, retry, ledger and restores;
- Rust unit tests and the database-backed HTTP test (a wrong-key signer, then propose, confirm and a CRL whose entry has no reason extension);
- `lab_verify_issued_certificates`;
- 78 frontend tests;
- the four e2e suites; the certificate-application suite voids a simulated timeout and OpenSSL finds the serial in the verified CRL.

Recovering a certificate that was signed but not stored remains open. CI passed on Draft #196 (`dfd0ef6`).

Automatic CRL renewal (2026-11-09, ADR-0021 Proposed): migration 0035 adds a per-CA `crl-publisher` role. Held by the system principal `urn:trust-platform:system`/`crl-renewer`, it may run the CRL publication functions only for a due CRL. The API runs a renewal pass every `TRUST_CRL_RENEWAL_INTERVAL_SECONDS` (Compose: hourly). Each pass goes through the unchanged journaled path. `crl-status` reports `auto_renewal`, and the console shows it. Verified locally:
- the new SQL suite and the existing CRL suites;
- the database-backed HTTP test, where the renewer publishes CRL 1 with the real signer and then does nothing;
- `lab_verify_issued_certificates`;
- 78 frontend tests;
- the four e2e suites on a lab with the renewer enabled.

CI passed on Draft #197 (`eb8ab75`, all seven jobs).

Tamper-evident audit chain (2026-11-09, ADR-0022 Proposed): migration 0036 seals committed audit events, after commit and oldest first, into an append-only SHA-256 chain (`audit_chain_link`) over a canonical encoding of every `audit_event` column. Triggers refuse UPDATE, DELETE and TRUNCATE on links, and TRUNCATE on events. The API runs a sealing pass every `TRUST_AUDIT_SEAL_INTERVAL_SECONDS` (Compose: 60 s) through the writer login. Readers see only `chain_sealed` per event (API, OpenAPI, console detail, CSV and JSON copy), looked up for the returned page through a separate filtered view, `management_audit_seal`, so history plans are unchanged. `lab_verify_audit_chain` recomputes every digest and link in Rust from the raw rows, prints a JSON manifest, and checks a head exported earlier (`TRUST_AUDIT_EXPECTED_HEAD`). Verified locally:
- the new SQL suite (Rust/SQL digest vectors, privileges, batches, contiguity, reader flag, refused changes);
- the tamper script: an altered event, a removed link and a renumbered chain are reported; a chain rebuilt by the owner passes on its own but fails against the exported head;
- the 0011→0036 upgrade, retry, ledger (25 migrations) and restores, and the history pagination, window and load-plan steps;
- 62 Rust tests, including the HTTP test that seals the renewal's event, plus Clippy and fmt;
- the four audit tools; on the API test database the chain of 116 events, and on the fresh lab 187 events, verify with no unsealed event;
- 78 frontend tests and the build;
- the four e2e suites; the certificate-application suite waits for the API's own pass to seal the void.

Open: a signed or externally anchored head, authenticated actor claims, automated export of the manifest, governed retention. CI passed on Draft #198 (`2ffed3c`, all seven jobs).

Signed audit checkpoints (2026-11-09, ADR-0023 Proposed): migration 0037 adds the append-only `audit_chain_checkpoint` table and three functions for the signer role. The lab signer gains an `audit_checkpoint` request:
- it uses a P-256 audit key distinct from the CA key (`TRUST_SIGNER_AUDIT_KEY_FILE`, generated by `init-env.sh`);
- it keeps a state file outside the database (`TRUST_SIGNER_AUDIT_STATE_FILE`);
- it recomputes the links since its last checkpoint from the raw events;
- it refuses a database that no longer extends what it signed (`AuditRollback`);
- it signs the new head and records it.

The API requests a checkpoint every `TRUST_AUDIT_CHECKPOINT_INTERVAL_SECONDS` (Compose: 60 s) and logs a refusal as an alert. `lab_verify_audit_chain` verifies checkpoints against the recomputed chain and, with `TRUST_AUDIT_CHECKPOINT_PUBLIC_KEY`, their signatures. Verified locally:
- the new SQL suite and the 0036 suite (its TRUNCATE check now cascades);
- 14 signer unit tests, including rollback, rebuilt history, lost state, changed key and damaged state;
- the HTTP test with the real signer (signed, then unchanged; the signature verifies under the audit key);
- the tamper script with an OpenSSL key and signature (verified, missing key, other key, rebuilt chain, moved signature);
- the 0011→0037 upgrade, retry, ledger (26 migrations) and restores;
- 62 API tests, Clippy and fmt; 78 frontend tests;
- the four e2e suites (the certificate-application suite waits for a checkpoint);
- on the fresh lab, the tool verifies the signer's three checkpoints with the OpenSSL public key; after an owner rebuild, the signer refuses (`AuditRollback`) and the tool fails.

Open: hardware-protected audit key and rotation, a restored database together with the signer's state (not detected), an external log, retention. CI passed on Draft #199 (`5ea224d`, all seven jobs).

CA/RA boundary (2026-11-09, ADR-0024 Proposed, documentation only): following the owner's direction, the CA and the PKI sign the certificate requests an authorized RA or CLM submits, and the CRLs. Identity proofing and domain-control validation belong to a light RA or the CLM (ACME later), never to the CA, which still enforces its profiles (zones, key policy, validity, fixed extensions). Domain-control validation leaves the CA's open items. The laboratory's requester and officer flow is reclassified as a stand-in for a light RA. The CA's next interface is an authenticated RA/CLM issuance channel with machine identity, to be designed in its own ADR. No code change. CI passed on Draft #200.

RA issuance channel (2026-11-09, ADR-0025 Proposed): migration 0038 adds the owner-registered `ra_system` (P-256 public key, enabled flag), `ra_profile_grant` and the append-only `ra_issuance_request`. `POST /v1/ra/cas/{ca_id}/certificates` takes no user token: the RA signs the request (CA, profile, request id, CSR digest, names, validity, `signed_at`), and the API checks freshness (300 s) and the signature with the registered key. It then verifies the CSR. `submit_ra_issuance_lab` records the application as submitted and approved by the RA, under the profile's rules, with the signed bytes. The API issues once as the RA through the signer; replays return the same certificate. `lab_verify_issued_certificates` re-verifies every RA signature and the stored bytes. Verified locally:
- the new SQL suite (vector, constraints, privileges, refusals, replay, conflict, attribution, append-only);
- 63 API tests, including the HTTP RA scenario (another key, stale or tampered request gives 401; outside the zones gives 422; issued 201; replay 200; conflict 409);
- the four audit tools (one RA request verified);
- the four e2e suites; the certificate-application suite acts as an RA, signs with Node's crypto, and OpenSSL verifies the issued certificate.

Open: revocation through the channel, RA key rotation, production transport. CI passed on Draft #201 (all seven jobs).

RA revocation channel (2026-11-10, ADR-0026 Proposed): migration 0039 adds the append-only `ra_revocation_request` and `submit_ra_revocation_lab`. `POST /v1/ra/cas/{ca_id}/revocations` is authenticated like RA issuance (freshness, registered key, signature over the serial, reason code, reason and identifiers). The RA can revoke only certificates it obtained through the channel. Its signed request is both the revocation request and its approval, under the rules of migration 0031 and the CRL lock. `lab_verify_issued_certificates` accepts that self-approval only for RA-signed revocations, and verifies their bytes and signatures. Verified locally:
- the new SQL suite;
- 63 API tests, including the HTTP scenario (401, 404, 201, replay, 409, and the serial on the next verified CRL);
- the four audit tools (one RA-signed revocation);
- the four e2e suites; the certificate-application suite revokes as the RA, and `openssl verify -crl_check` reports the certificate revoked after the next CRL.

Open: on-revocation CRL publication or OCSP, RA key rotation, production transport. CI has not yet run on this branch.
