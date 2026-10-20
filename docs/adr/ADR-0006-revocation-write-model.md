# ADR-0006 — Least-privilege write model for revocation, CRLs and CA administration

**Status:** Proposed · 2026-10-20 · requires human security review. Implemented in the lab (migrations 0023–0027) at the repository owner's request; that implementation is not an acceptance of this ADR. Acceptance conditions are listed below.  
**Scope:** Revocation lifecycle, CRL pipeline and CA administration (migrations 0014–0027) and any future status-change API. Laboratory only; no production approval, G0 clearance or CA qualification is implied.  
**Related:** ADR-0007 (signed, key-distinct double control, split out of this ADR on 2026-10-20), ADR-0002 (signing and durable state), ADR-0003 (authenticated identity), ADR-0005 (Rust management control plane), `docs/security/threat-model.md` (revocation and CRL write path), spec `docs/superpowers/specs/2026-10-18-revocation-crl-design.md` §6.

## Context

The lab revocation slice enforced maker-checker in PL/pgSQL functions that were all `SECURITY INVOKER`. A service able to call them therefore needed `INSERT`/`UPDATE`/`DELETE` on the underlying tables. With those grants it could revoke, release or suspend directly, without a second actor. It could also add rows to a CRL snapshot (fake coverage) or insert a `STORED` publication that skipped the signing intent and independent verification. Review evidence: on migration 0022, one role holding the required DML inserted a revocation with no status change (`rows=1, changes=0`).

Two administrative operations were also single-actor:
- registering a CA's issuer certificate (0022), which decides whose CRLs count;
- maintaining revocation officer grants, which decides who may revoke.

Signing the decisions with distinct officer keys is a separate, larger design. It depends on IAM, officer hardware and procedures, and is now ADR-0007. This ADR covers only what the database and the service connections must enforce.

## Decision (proposed)

### A. Database privilege model (migration 0023)

- The **owner role** `trust_revocation_owner` (`NOLOGIN`) owns the revocation, CRL and CA-administration tables and functions. No login is a member. Migrations run as a superuser or a dedicated migration role. The owner holds `SELECT`/`UPDATE` on `ca` and `certificate` (row locks) and `INSERT` on `audit_event`.
- Every function a service calls is `SECURITY DEFINER` with `search_path = pg_catalog, public, pg_temp`. Temporary objects are looked up last, so a caller cannot shadow a table. `EXECUTE` is revoked from `PUBLIC`. Helpers and trigger functions are owned by the same role and are never granted to a service.
- **Capability roles** (`NOLOGIN`), each granted to a distinct service login, get `EXECUTE` only and no table DML:
  - `trust_revocation_officer_api`: status lifecycle, plus `SELECT` on `ca_revocation_policy`;
  - `trust_crl_signer`: reserve, snapshot, intent, store, reconcile, plus `SELECT` on `crl_publication`;
  - `trust_crl_operator`: due/overdue reports and housekeeping;
  - `trust_ca_admin`: CA-administration proposals and decisions (0024).
- The management reader (`trust_api_reader`, 0012/0013) keeps read-only views only.

### B. Dual control of CA administration (migration 0024)

- `ca_admin_grant` lists the CA admins. The DBA bootstraps it under change control; no service can write it.
- Registering the issuer certificate and granting or removing a revocation officer go through `ca_admin_change`:
  - one CA admin proposes;
  - a second, distinct CA admin approves the exact content digest it reviewed: the certificate's SHA-256, or the length-prefixed kind and officer identity;
  - every step is audited, and the history is append-only.
- A CA admin can never grant an officer role to themselves, as maker or as checker, so administration and revocation stay separate duties.
- `register_ca_issuer` is no longer granted to any service. It remains for superuser bootstrap only.

### C. Service connections refuse privileged logins

`PgRevocationStore::connect_lab_service` refuses (`PrivilegedSession`) a session whose login is a superuser, can create roles, bypasses row-level security or is a member of `trust_revocation_owner`. The check uses `session_user`, so setting a role does not hide a privileged login. Services, and the `crl_housekeeping` job, connect through it.

### D. Housekeeping

`abandon_stale_crl_reservations` and `quarantine_stale_crl_intents` run from a scheduled job as `trust_crl_operator`, which alerts through its exit status (`crl_housekeeping` example, `docs/operations/lab-crl-housekeeping.md`). Since 0017/0020 a stale reservation cannot be signed, so the sweep is hygiene and evidence, not a safety control.

### E. Schema-change audit (migration 0026, lab answer to condition 3)

- Event triggers on `ddl_command_end` and `sql_drop`, `ENABLE ALWAYS`, append every DDL command and object grant to `schema_change_audit`: command tag, object type and identity, session user, transaction id. No SQL text is stored, since it can carry credentials. Temporary objects are skipped.
- `schema_change_audit` and the review ledger `schema_change_review` are owned by the NOLOGIN `trust_schema_audit_owner` and are append-only (row and TRUNCATE guards, also `ENABLE ALWAYS`). No service can read or write them.
- Every reviewed migration ends with `acknowledge_schema_changes('<ref>')` (superuser only). `unreviewed_schema_changes()` (granted to `trust_crl_operator`) counts later changes, and `crl_housekeeping` exits with status 2 when it is above zero.
- PostgreSQL fires no event trigger for roles, role membership, databases, `ALTER SYSTEM` or event triggers themselves, and a superuser can drop the triggers. Server logging (pgaudit) and external anchoring (condition 5) remain required, so condition 3 is only partly met.

### F. Audit chain anchored outside the database (migration 0027, lab answer to condition 5)

- `seal_audit_chain`, run by a scheduled job as `trust_audit_sealer`, links every `audit_event` and `schema_change_audit` row into `audit_chain_entry`. This is the SHA-256 chain of `audit_chain::next_audit_hash`, over a canonical, length-prefixed encoding of each row. The table is append-only and owned by the NOLOGIN `trust_audit_owner`.
- The `audit_chain_anchor` job, running as `trust_audit_verifier` on another host, re-encodes every record in Rust and checks the links. It compares the result with the checkpoints it appended to a file outside the database, then appends the new head.
- A superuser who rewrites, deletes or truncates history, or recomputes the whole chain, is detected at the next verification against the exported checkpoints (`docs/operations/lab-audit-chain.md`).
- Open:
  - records and entries newer than the last checkpoint are not protected;
  - checkpoints are neither signed nor timestamped (RFC 3161);
  - the anchor's storage is a deployment decision.

### G. Database clock cross-check (lab answer to condition 6)

- The Rust core reads the database clock between two readings of its own (`clock::ClockReading`, `PgRevocationStore::database_clock`).
- `reserve_crl` refuses (`RevocationStoreError::ClockSkew`), before any intent or signature, when the thisUpdate the database chose is not within the bound (default 2 s) of the host-clock interval that brackets the call. The reservation stays `RESERVED` and housekeeping retires it.
- `crl_housekeeping` reports skew and uncertainty, and alerts when they exceed the bound.
- The clock source is injectable (`set_clock_source`), for an authenticated time adapter or for tests.
- Open: this detects disagreement between two clocks, not wrong time on both. Authenticated time (NTS or a trusted time-stamping service) with drift alerting remains a deployment requirement.

## Alternatives considered

- **Per-officer PostgreSQL logins (`session_user` as identity):** strong in-database authentication, but it couples human identity lifecycle to database roles and does not fit OIDC step-up. It could be revisited for an air-gapped deployment.
- **Table grants plus triggers only:** triggers already guard transitions and immutability. They cannot express "this write must come from the maker-checker function", and a service holding DML can still bypass them.

## Consequences

- Identities are still asserted by the calling service as `(issuer, subject)` text. This is **textual two-actor control with EXECUTE-only service roles**, not cryptographic double control, and it remains a known deviation from `AGENTS.md` until ADR-0007 is implemented.
- Superusers and the owner role bypass the model, as does anyone who can `SET ROLE` to the owner. Operations must keep service logins away from them; the service connection check enforces this on the service side only.
- Bootstrap of the first CA admins and of the issuer certificate is a DBA action outside dual control.

## Acceptance conditions (to be confirmed by a human reviewer)

1. Independent review of every `SECURITY DEFINER` function: search_path, dynamic SQL, error-message leakage, lock order, and that every input is validated before use.
2. Runtime without superuser: deployment evidence that each service uses a dedicated non-superuser login with exactly one capability role, `NOINHERIT` where possible, no `CREATEROLE`, no owner membership, and `connect_lab_service` (or its production successor).
3. Schema-change control: DDL and role changes on this database only through reviewed migrations, monitored (pgaudit or event triggers) and alerted. Lab: section E covers DDL and object grants; role changes still need server logging.
4. Evidence kept up to date in CI: `tests/revocation_privileges.sql`, `tests/ca_admin_dual_control.sql`, `least_privilege_roles_run_the_whole_pipeline`, `service_connections_refuse_privileged_sessions`.
5. Audit trail anchored outside the database (append-only external log or timestamped hash chain), so that a superuser cannot rewrite `audit_event` unnoticed (open item D-04). Lab: section F; signed or timestamped checkpoints and the anchor's storage remain open.
6. Authenticated time source (NTP with drift alerting) for the database, since deadlines, thisUpdate and intent ordering use its clock. Lab: section G cross-checks the database clock against the Rust core's; authenticating either remains open.
