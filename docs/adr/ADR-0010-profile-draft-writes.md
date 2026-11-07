# ADR-0010 — Record and submit certificate-profile drafts

**Status:** Proposed · 2026-11-02. It is not accepted; acceptance needs the
owner's decision and an independent security review (AGENTS.md).

**Scope:** The first write routes of the management API, migration 0022 and
the console. It approves, activates and issues nothing.

**Roadmap:** first slice of MVP criterion 6, *CA and profile lifecycle*. The
criterion stays unchecked.

**Builds on:**
- the [lifecycle contract](../architecture/ca-profile-lifecycle-boundary.md);
- ADR-0005 (Rust management control plane);
- ADR-0008 (reader isolation);
- ADR-0009 (laboratory identity provider).

## Context

The lifecycle contract defines profile revisions as immutable snapshots that
move through `DRAFT → SUBMITTED → APPROVED → ACTIVE → RETIRED`.

It sets three preconditions for any mutating route:
- a real identity provider;
- separately authenticated actors;
- a write-specific database role.

ADR-0009 now provides the first two in the laboratory. The owner chose to
deliver the lifecycle in three slices (decision of 2026-11-02):
1. authoring and submission (this change);
2. signed approval with the v1.5 P-256 decision receipts;
3. activation and retirement.

## Decision

1. **Separate write login.**
   - A new NOLOGIN role, `trust_profile_writer`, has USAGE on the schema and
     EXECUTE on two functions only. It holds no privilege on any table or
     view.
   - The API reads it from an optional second URL, `TRUST_WRITER_DATABASE_URL`.
   - **At startup**, the API refuses a writer login that:
     - holds any table or view privilege;
     - is also a reader;
     - has elevated attributes;
     - or runs on a database without the 0022 marker.
   - **The reader check is tightened:** the reader login must not be a member
     of the writer role.
   - **Without a writer URL**, the write routes answer 503.
2. **Server-owned role grants.** `management_role_grant` records which
   issuer-qualified subject holds which lifecycle role for which CA:
   `profile-editor`, `policy-approver` or `ca-operator`. The database owner
   writes it.
   A write needs three things:
   - the `trust-profile-editor` token role;
   - the CA in the token scope;
   - this grant.

   The reader role is not needed to write. An editor without it can record
   and submit, but not read.
3. **Two `SECURITY DEFINER` functions** hold the whole decision. They run with
   a fixed `search_path` and re-check the grant.
   - **`create_profile_draft_lab`** records the next revision. It takes a
     per-profile advisory lock, so revision numbers are dense under
     concurrency.
   - **`submit_profile_draft_lab`** submits a revision. It accepts only the
     latest revision of the profile, only once, and only when the caller's
     digest equals the digest the database computes itself.

   Each recorded operation writes three rows in one transaction:
   - the draft revision, for creation, or a submission row, for submission;
   - an append-only `profile_lifecycle_event`, with actor issuer and subject,
     action, revision, digest, policy version and operation id;
   - an `audit_event` carrying the same id.

   The audit event's actor stays hidden from readers.
4. **The digest is computed twice and pinned.**
   - `profile_draft_snapshot_sha256` rebuilds, in SQL with pgcrypto's
     SHA-256, the same v1 envelope as the API (`profile_proposal.rs`). No
     primitive is defined.
   - A Rust unit test and the SQL test assert the same two pinned vectors,
     one of which has UTF-8 text and two-element lists. A change to either
     implementation breaks one of the tests.
5. **Idempotency.**
   - Every write needs an `Idempotency-Key` UUID.
   - The same request with the same key returns the recorded result: 200,
     with header `Idempotent-Replayed: true`.
   - Any other use of the key gives 409: another body, actor, profile or
     action.
   - The request digest is the SHA-256 of the exact body bytes.
6. **Request bounds.**
   - Bodies: JSON only, 16 KiB at most, unknown fields refused.
   - Limits: the same bounds as the table's CHECK constraints, also checked
     before the database is called.
   - Advisory syntax warnings: a revision with warnings can be recorded but
     not submitted (422). The submission transaction is then rolled back,
     including its events.
7. **Readers see the state.** `management_profile_draft` gains
   `lifecycle_status` (`DRAFT` or `SUBMITTED`) and `submitted_at`, with the
   per-principal filter of 0021.
8. **Console.**
   - An editor (role read from the token, as a display hint only) can propose
     a revision, prefilled from an existing one.
   - An editor can submit the latest revision from its detail.
   - Every refusal comes from the server.

## Status codes

| Case | Answer |
| --- | --- |
| no or invalid token, workload or foreign token | 401 |
| no editor role, CA outside the token scope, no `profile-editor` grant | 403 |
| unknown revision | 404 |
| key reused, newer revision exists, already submitted, digest mismatch | 409 |
| syntax warnings on submission | 422 |
| missing or malformed key, unknown field, out-of-bounds value | 400 |
| body too large; not JSON | 413; 415 |
| writer login not configured or database unavailable | 503 |

## Evidence

- **`tests/management_profile_lifecycle.sql`** (CI). It fails before 0022
  and passes on it.
  - **Privileges:** the writer role cannot read or write any table, view or
    the digest function, and the reader role cannot execute the write
    functions.
  - **Writes:** creation, replay and key reuse, including by another editor.
  - **Refusals:** no grant for the CA, another issuer, an approver-only
    grant, CHECK violation, malformed request digest.
  - **Submission:** stale revision, altered digest, unknown revision,
    approver, one submission then replay then refusal, a new DRAFT revision
    after submission.
  - **Records:** reader view states, lifecycle and audit events with
    matching ids and digests, immutability of events and submissions.
  - **Interrupted transaction:** a failure injected in the audit write leaves
    no revision, event or submission.
  - **Mutations detected:** each of these makes the test fail:
    - dropping the grant check;
    - dropping the stale-revision check;
    - dropping the digest comparison;
    - letting a replay ignore the actor.
- **`profile_writes_are_granted_idempotent_serialized_and_submitted_once`**
  (Rust, against PostgreSQL in CI).
  - **Refusals:** reader-only token, CA outside the scope, CA in scope
    without a grant, editor without a grant, missing or malformed key,
    unknown field, oversized body, wrong content type, no writer URL (503).
  - **Concurrency:** six concurrent creations get revisions 1–6.
  - **Idempotency:** replay and key reuse.
  - **Submission:** stale, altered and unknown revisions are refused; one
    submission and its replay succeed, a second submission is refused; a
    revision with warnings gets 422 and stays DRAFT.
  - **Mutation detected:** removing the API's editor-role check makes the
    test fail.
- **`frontend/dev/profile-lifecycle-e2e.mjs`** (Compose CI job, 7 cases)
  uses Keycloak sign-ins for an author, an editor without the reader role, a
  reader and the workload. **`browser-e2e.mjs`** records and submits a
  revision through the console form as `lab-author`, and checks that a
  reader is offered no change.

## What this does not establish

- **No activation or retirement.**
  - `SUBMITTED` has no effect on issuance.
  - Signed approval and rejection came later, in
    [ADR-0011](ADR-0011-signed-profile-decisions.md); no route accepts the
    `ca-operator` grant yet.
  - No CA lifecycle.
- **The declared principal is trusted** (as in ADR-0008). The database
  cannot authenticate the API's caller. A compromised API, or a holder of
  the writer login, can act as any editor that holds a grant, but only
  through the two functions, and never as an approver.
- **No signature by the editor.** Authorship rests on the verified token and
  the grant. Signed approval with cryptographically distinct keys is the
  next slice.
- **Denied attempts are not persisted** as audit events; they appear only in
  the API's request log.
- **Syntax warnings are checked by the API only.** The database does not
  re-check them on submission; the approval slice must check them again.
- **Development-mode identity provider, no MFA** (ADR-0009).

## Alternatives considered

- **Table privileges for the writer role.** Simpler, but the database could
  not enforce grants, digests, ordering or audit atomically. Rejected.
- **A digest computed by the API only.** A compromised writer login could
  submit a revision under a digest of other content. Rejected in favour of
  the database's own computation.
- **Row-level security.** As in ADR-0008, views and functions run as their
  owner; the functions give one reviewed place for each decision.
