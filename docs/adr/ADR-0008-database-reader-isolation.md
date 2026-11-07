# ADR-0008 — Isolate certificate authorities in the management views

**Status:** Proposed · 2026-11-01. It is not accepted; acceptance needs the
owner's decision and an independent security review (AGENTS.md).
**Scope:** The read-only management API and its PostgreSQL views (migrations
0012–0021). It changes no issuance, signing or revocation path.
**Numbering:** ADR-0006 and ADR-0007 exist on the integration branch (draft
PR #94), so this one starts at 0008.

## Context

Until migration 0020, the management views filtered no rows. A session
holding `trust_api_reader` could read every authority's certificates, audit
events and reader grants by querying the views directly. This was measured in
`docs/operations/lab-history-load-query-plans.md`. Isolation between
authorities rested on each API query carrying the mandatory `ca_id`
predicate and an `EXISTS` on the server-owned grant. One API query that
missed either would expose other authorities. Any other tool given the
reader login would read everything.

PostgreSQL cannot authenticate the API's end users. The API has one login,
and the OIDC token is verified in the API.

## Decision

1. **The views filter rows.** Every management view returns only rows of
   authorities granted, in `management_reader_grant`, to the principal the
   session declares. The views are `management_ca`, `management_certificate`,
   `management_audit`, `management_reader_scope`, `management_certificate_san`,
   `management_history_bounds` and `management_profile_draft`.
   - The principal is declared in the custom settings
     `trust.reader_issuer` and `trust.reader_subject`.
   - A session that declares no principal, or a principal without grants,
     reads nothing (fail closed).
   - `management_reader_scope` shows only the declared principal's grants.
   - The filter is written into each `security_barrier` view, so it runs
     with the view owner's rights on the grant table, before any predicate
     of the caller.
2. **The API declares the principal.** On every connection it opens, it
   declares the issuer and subject of the verified token. Each request
   opens its own connection, so a session setting cannot leak to another
   request.
3. **The API keeps its own checks.** It still intersects the token's CA
   scope with the grants and keeps the `ca_id` predicate and grant `EXISTS`
   in every query. The database filter is a second, independent layer.
4. **The API fails closed on an unfiltered database.** At startup and in
   `/v1/ready`, the API requires the marker function
   `management_reader_isolation_version()`. It also checks that a session
   declaring no principal sees no CA and no grant. If either check fails,
   the API does not start, or `/v1/ready` returns 503.

## What this protects, and what it does not

| Threat | Before | After |
| --- | --- | --- |
| An API query that omits its CA predicate or grant check | exposes other authorities | returns only the declared principal's authorities |
| A tool or person using the reader login without declaring a principal | reads every authority | reads nothing |
| A query naming another authority, with any predicate shape | blocked by the API only | blocked by the view (tested with leakproof and non-leakproof predicates) |
| A compromised API process, or a holder of the reader login who declares a principal | reads every authority | **still reads any principal's authorities**: the database cannot verify the declaration |
| A principal reading another principal's grants | possible through `management_reader_scope` | not possible |

Closing the fourth row would need the database to authenticate each end
user. That means per-user database credentials, or verifying a signed
assertion inside PostgreSQL. The second would be home-grown token
verification, which AGENTS.md rules out. Neither is proposed here.

## Alternatives considered

- **Row-level security on the base tables.** The views run with their
  owner's rights, so they would bypass table policies unless each was made
  `security_invoker`. That would also need the reader to hold table
  privileges, which this design avoids.
- **One database role per principal (`SET ROLE`).** The API login would
  need membership in every reader role, so it could still assume any of
  them. This adds role management for the same trust limit.
- **A signed principal checked in the database.** This needs a key shared
  with, or verifiable by, PostgreSQL, plus token parsing in SQL. It was
  rejected as home-grown cryptographic protocol code.

## Consequences

- Every tool that reads the views must declare a principal. The lab scripts
  and tests do, through `set_config` or `PGOPTIONS`.
- The filter adds a semi-join on the small grant table: 2–11 ms on pages under
  50 ms, up to +38% on unsliced pages, and 4–12% less throughput
  ([measurements](../operations/lab-reader-isolation.md)).
- An operator querying the views as the owner also sees only the declared
  principal's rows. Owner queries on the base tables are unchanged.

## Verification

- `tests/management_reader_isolation.sql` (CI) uses two authorities and two
  principals, and checks each view:
  - nothing without a principal;
  - each principal's own authority only;
  - nothing for another issuer or an unknown subject;
  - no rows of the other authority whatever the predicate.

  It fails on a database migrated to 0020 and passes on 0021.
- **Mutation checks.**
  - A route that does not declare its principal returns 403 in the
    end-to-end history test.
  - The API's `/v1/ready` returns 503 against a 0020 database.
- **Other scripts.** The upgrade, restore and load-plan scripts check that
  an undeclared session sees nothing.
