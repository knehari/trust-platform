# Development status

**Checked 2026-11-07.** The local integration branch combines the recent management reader isolation work with the Keycloak IAM laboratory. **MVP progress: 5/12 criteria evidenced (42%)** in a laboratory; seven criteria remain open. This is not a production release.

## Integrated laboratory boundary

- The Rust Core has laboratory policy, signing, recovery and idempotency paths. The management API remains read-only; no HTTP route creates a CA or profile, issues or revokes a certificate, or activates a draft.
- Migrations 0012–0021 provide scoped management reads, metadata search and database reader isolation. The API readiness gate checks all seven views with no declared principal. Migration 0022 enforces contiguous immutable draft revisions. It does not approve or activate a draft.
- The separate Keycloak lab authenticates two human subjects through Authorization Code + PKCE and a workload through client credentials. The API binds client IDs to separate human and workload reader roles and intersects token scope with server-owned CA grants. The original automatic OIDC fixture is only for the disposable Compose demo.
- The console and OpenAPI contract share read-only filter rules for proposals, audit, authority search and CN prefixes, including Unicode and cursor behavior.

## Evidence and open work

The IAM branch previously passed 52 frontend tests, a frontend build, 19 database-backed API tests, Keycloak sign-in and denial smoke, and profile revision migration tests on its own tree. The reader-isolation branch previously passed its targeted seven-view database test and 22 API tests without database variables on its own tree. These are **pre-integration results**. On the combined tree, all 52 console tests, its production build, 24 Rust API tests without database variables, and the seven-view gate with a restricted database login pass. Fresh migrations 0001–0022, a populated 0011→0022 upgrade, refusal of a gapped profile history and concurrent revision insertion also pass on disposable PostgreSQL 16 databases. Rust lint passes; remote CI on the integrated head remains to be checked. The local 5173 laboratory database was backed up and migration 0022 was rehearsed on a restored copy before application; its three draft rows and revision sum of four were preserved. After rebuilding the API, console and OIDC fixture, the API contract check and full Compose smoke passed with code + PKCE, scoped list/detail reads and access denials. The separate Keycloak instance was not changed.

The next milestone is criterion 6: authenticated CA and profile lifecycle with independent approval, exact revision/digest binding and protected signer custody. Application issuance, revocation/publication, durable audit, protected restore and independent release gates follow. Pilot deployment still needs TLS peer validation, MFA/secret operations and security review. G0 legal/IP clearance remains open.

The integrated changes remain local and are running only on the 5173 laboratory instance. They have not been pushed to GitHub or merged into `main`.
