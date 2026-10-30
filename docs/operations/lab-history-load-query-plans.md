# Laboratory history query plans under load

Lab only. This measures the filtered history reads of the read-only
management API (certificates, audit events, CA list) on a large,
reproducible, multi-CA dataset, through the security-barrier views and under
the restricted reader role. It decides which index or query change the
measurements justify. It extends the 10,000-row rehearsal in
[lab-history-filter-query-plans.md](lab-history-filter-query-plans.md).
Certificate-profile proposals are out of scope: no such table, view or route
exists on this branch.

**Outcome.** No index, view or query change is justified **within the
current security-barrier constraint**:
- Every history page costs a full scan of the authority's rows, linear in
  its size. On a 200,000-row authority that is about 300 ms for a
  certificate page and 110 ms for an audit page, and under 8 concurrent
  readers about 1.5 s and 0.5 s per page.
- The fix that would make pages index-bound (sub-millisecond) needs the
  history views to stop being `security_barrier`. That is a security
  decision for the repository owner (see [Decision needed](#decision-needed)),
  so it was measured but not applied.
- No migration is added.

## Method

- **Dataset**: `tests/management_history_load_seed.sql`. It is deterministic,
  with no randomness: every identifier, time and name derives from the row
  number. It holds 302 CAs, 306,000 certificates and 306,000 audit events:
  - authority **A** (granted to the reader) has 200,000 certificates and
    200,000 events;
  - authority **C** (not granted) has 100,000 of each, in the same tables
    and indexes;
  - 300 small CAs have 20 of each; 250 of them are granted.

  Certificate rows rise in time, with two rows per millisecond to create
  cursor ties. 90% carry verified metadata (CN, two DNS SANs, notAfter) and
  10% are historical rows without it. Audit rows vary event type (one type
  at 1%), decision (5% DENY) and policy version (4 values).
- **Queries**: `tests/management_history_load_plans.sql` runs 25 cases in
  one `READ ONLY` transaction under `SET ROLE trust_api_reader`:
  - the SQL text of `crates/management-api/src/main.rs`, with the
    server-owned grant `EXISTS` and the security-barrier views;
  - parameters as literals, since the Rust client sends each query as an
    unnamed statement, which PostgreSQL plans with the actual values;
  - every case as `EXPLAIN (ANALYZE, BUFFERS)`.

  The cases cover no filter (both orders), each filter alone, combined
  filters, cursors in the middle and near the end of A's history, the
  certificate detail route, the grant check and the CA list. The script
  aborts if the reader is granted authority C or can read any of C's
  certificates or events. Mutation: granting C makes it fail ("FAIL: the
  reader is granted authority C").
- **Load**: `pgbench -n -T 20` through a disposable login that holds only
  `trust_api_reader`, running the grant check plus the first certificate or
  audit page of authority A, with 1 and 8 clients.
- **Environment**: PostgreSQL 16.15 with default settings (shared_buffers
  128 MB, work_mem 4 MB, random_page_cost 4, JIT on), 4 CPUs, 15 GB RAM,
  the same defaults as the `postgres:16` CI image. Warm runs are the median
  of 3. A cold run restarted the cluster (empty shared buffers); the OS page
  cache could not be shown to be dropped, and its times match the warm
  ones within 10%.

## Measurements (authority A, 200,000 rows; medians of 3, ms)

| Case | Query | Before (as shipped) | 0016 draft | + extended statistics only | 0016 + views without `security_barrier` (not applied) |
| --- | --- | ---: | ---: | ---: | ---: |
| G1 | grant check | 0.025 | 0.023 | 0.026 | 0.021 |
| C1 | certificates, no filter, newest first | 302 | 501 | 269 | 0.79 |
| C2 | certificates, no filter, oldest first | 268 | 496 | 253 | 0.81 |
| C3 | CN prefix `svc-` (1%) | 268 | 476 | 252 | 5.1 |
| C4 | CN prefix `host-1` (about 10%) | 303 | 499 | 257 | 0.89 |
| C5 | CN prefix matching one row | 281 | 487 | 240 | 78 |
| C6 | exact DNS SAN (0.1%) | 342 | 601 | 747 | 134 |
| C7 | exact DNS SAN, no match | 342 | 584 | 712 | 246 |
| C8 | notAfter before an early cutoff | 324 | 588 | 316 | 1.0 |
| C9 | CN + SAN + notAfter | 384 | 662 | 451 | 140 |
| C10 | no filter, cursor in the middle | 193 | 284 | 189 | 0.76 |
| C11 | no filter, cursor near the end | 53 | 29 | 73 | 0.72 |
| C12 | SAN, cursor in the middle | 216 | 318 | 227 | 127 |
| C13 | certificate detail by serial | 20 | 27 | 17 | 19 |
| A1 | audit, no filter | 110 | 185 | 108 | 0.29 |
| A2 | event type (1%) | 12 | 21 | 13 | 1.5 |
| A3 | decision DENY (5%) | 17 | 27 | 17 | 0.51 |
| A4 | policy version (25%) | 38 | 60 | 37 | 0.27 |
| A5 | one-day recorded window | 55 | 0.048 | 54 | 0.026 |
| A6 | window + type + decision + version | 15 | 43 | 15 | 2.3 |
| A7 | no filter, cursor in the middle | 93 | 98 | 95 | 0.26 |
| A8 | no filter, cursor near the end | 48 | 0.57 | 48 | 0.24 |
| A9 | event type, cursor, oldest first | 13 | 18 | 13 | 1.9 |
| L1 | CA list, first page (251 of 302 granted) | 0.54 | 0.44 | 0.51 | 0.55 |
| L2 | CA list, second page with search | 0.47 | 0.42 | 0.46 | 0.51 |

Concurrent load (as shipped, first page of authority A, no filter):

| Page | 1 client | 8 clients |
| --- | --- | --- |
| certificates | 273 ms, 3.7 pages/s | 1,476 ms, 5.4 pages/s |
| audit | 94 ms, 10.6 pages/s | 494 ms, 16.2 pages/s |

No transaction failed. At 8 clients the certificate page reaches half of the
3-second statement timeout.

## What the plans show (as shipped)

C1, first certificate page, 312 ms and 808,893 buffers for 101 rows:

```
Gather Merge
  Sort  Sort Key: (to_char((c.signed_at AT TIME ZONE 'UTC'), 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')) DESC,
                  ((c.request_id)::text) DESC     top-N heapsort
    Nested Loop                                     rows=66667 loops=3
      Parallel Seq Scan on certificate c  Filter: ((ca_id)::text = 'cccc...000a')   (estimated 638 rows)
      Index Scan using certificate_request_pkey on certificate_request r   loops=200000
```

1. **Every page reads every row of the authority.** The views expose
   `ca_id`, ids and times as text, and the API filters, orders and pages on
   that text. `to_char()` is only STABLE, so no index can match the order.
   Leakproof quals (the `ca_id` equality, the cursor's row comparison, the
   audit time bounds) do reach the table scan, but only as filters.
2. **The certificate join is a nested loop of 200,000 index probes.** The
   planner estimates 638 rows for `ca_id::text = ...` against 200,000
   actual rows, so it joins each certificate to its request one by one
   (about 800,000 buffer hits per page).
3. **Non-leakproof filters run above the view, as the barrier intends.**
   This covers `lower(subject_cn) LIKE`, the `EXISTS (… unnest(san_dns) …)`
   SAN filter and the detail route's `encode(serial)` comparison. An index
   on CN or SAN could not be used through the view without making those
   filters leakproof, and that was not attempted.
4. **Audit pages** scan the authority's events and sort them (A1: parallel
   sequential scan, top-N sort on the formatted time).
5. **The CA list and the grant check are not a concern** (under 1 ms).
   `management_reader_grant` is scanned sequentially, but it is small.

## Changes measured and rejected

1. **Draft migration 0016 (not added).** It defined an IMMUTABLE
   `management_utc_ms(timestamptz)` returning the same text as the views,
   rebuilt both views with it (same columns and values), and added the
   expression indexes `(ca_id::text, management_utc_ms(time), id::text)` on
   `certificate` and `audit_event`.
   - The indexes help only range predicates: the audit window (A5,
     55 → 0.05 ms) and deep cursors (A8, 48 → 0.6 ms; C11, 53 → 29 ms).
   - The `ORDER BY … LIMIT` of a page is not pushed into a
     `security_barrier` subquery, so pages still scan and sort everything.
     The same query on the base table uses the index in 0.5 ms, against
     262 ms through the view.
   - The wrapper function is not inlinable (IMMUTABLE around a STABLE body),
     so it costs a call per row. Every other case regressed (×0.35–×0.74;
     ×0.40–×0.50 with a pinned `search_path`).

   Rejected.
2. **Extended statistics only** (`CREATE STATISTICS … ON (ca_id::text)`).
   They fix the row estimate, and the planner switches to a parallel hash
   join (C1 302 → 269 ms). But the SAN filters regress (C6 342 → 747 ms,
   C7 → 712 ms) and so does the deep cursor (C11 53 → 73 ms). Rejected:
   mixed.
3. **Draft 0016 plus views without `security_barrier`: measured only, not
   applied.** Pages become index-bound: C1 0.79 ms, A1 0.29 ms, A7 0.26 ms,
   C10 0.76 ms; each reads the 101 newest rows of the authority from the
   index and stops. Selective filters still walk the index until they find
   101 matches (C7 with no match: 246 ms; C6: 134 ms). The isolation check
   still passed (authority C invisible through the API query).

## Decision needed

Making history pages independent of the authority's size requires lifting
`security_barrier` on `management_certificate` and `management_audit`.
This branch does not do it. Facts for that decision:

- **The views filter no rows.** They have no `WHERE` clause.
  `trust_api_reader` can already read every authority's certificates and
  events, and every reader grant, by querying the views directly: measured
  here as 306,000 certificates, including the 100,000 of the ungranted
  authority C. Isolation between authorities is enforced by the API alone:
  its mandatory `ca_id` predicate and the `EXISTS` on the server-owned
  grant. The barrier does not add isolation at the database role level
  today. It only orders non-leakproof predicates after the view's join.
- Database-level isolation would need row filtering in the database (a
  grant-joined view or row-level security keyed on the authenticated
  reader). That design question is separate from performance and should be
  settled first. A row-filtering view would need the barrier for real, and
  its ordering would have to be designed with it.
- Until then, the measured bound for the lab is about 300 ms (certificates)
  and 110 ms (audit) per page for a 200,000-row authority, with one reader.
  It grows linearly with the authority's size and with concurrent readers.

## Reproduce

```sh
createdb trust_history_load
for m in migrations/0*.sql; do psql -X -v ON_ERROR_STOP=1 -d trust_history_load -f "$m"; done
psql -X -v ON_ERROR_STOP=1 -d trust_history_load -v big=200000 \
  -f tests/management_history_load_seed.sql
psql -X -v ON_ERROR_STOP=1 -d trust_history_load -f tests/management_history_load_plans.sql
```

The Rust schema CI job runs the same scripts with `big=50000` and prints
every plan; it fails if authority C becomes visible to the reader.

## Limits

- One machine, PostgreSQL defaults, and data that fits in memory. Cold disk
  reads, larger authorities, autovacuum or bloat, and network latency
  between the API and the database were not measured.
- The load test calls PostgreSQL directly through the reader login, not the
  HTTP API (OIDC verification, connection slots, JSON encoding).
- The fixture's metadata and time distributions are synthetic. Real
  selectivities change the filtered cases, not the unfiltered linear scan.
