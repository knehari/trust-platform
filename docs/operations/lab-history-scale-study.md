# Laboratory history filter scale study

Lab only, disposable synthetic data. This continues
[lab-history-filter-query-plans.md](lab-history-filter-query-plans.md) and
[lab-history-load-query-plans.md](lab-history-load-query-plans.md). It
measures the certificate history filters (CN, DNS SAN, recorded notAfter)
at 100,000 and 1,000,000 certificates. It also tests the two hypotheses of
the first rehearsal (text casts, per-row SAN `unnest`) and lists options
per bottleneck.

**No migration is proposed or applied.** Every change tried here was built
in a throwaway copy of the database and dropped afterwards.

## Setup

- **Cluster**: a dedicated, disposable PostgreSQL 16.15 cluster with default
  settings (shared_buffers 128 MB, work_mem 4 MB, 2 parallel workers per
  gather) and `pg_stat_statements` preloaded. 4 CPUs, 15 GB RAM.
- **Data**: `tests/management_history_scale_seed.sql` with `total=100000`
  and `total=1000000`, `seed=42`.
  - Authority A holds 80% of the rows; eight small authorities hold 2% each;
    one 4% authority U is not granted to the reader.
  - Every value derives from the row number and the seed through
    `hashint8`. Two builds with the same seed gave the same MD5 over all
    certificate rows.
  - All data is synthetic: the DER is a two-byte placeholder.

  Measured selectivity on authority A (1M fixture):

  | Filter | Strong | Medium | Null |
  | --- | --- | --- | --- |
  | CN prefix | `svc-` 0.098% | `app-` 10.0% | `zzz-` 0 rows |
  | DNS SAN | `pool-7` 0.094% | `grp-3` 8.9% | `absent` 0 rows |
  | notAfter before | 0.2% | 9.0% | 0 rows |
  | Combined | CN `app-` + SAN `pool-7`: 78 rows | CN `app-` + SAN `grp-3`: 1.0% | CN `app-` + SAN `absent` + notAfter: 0 rows |

  "Null" means that no row matches, which is the worst case: the whole
  history is read.
- **Queries**: the SQL text of `crates/management-api/src/main.rs`, through
  the `security_barrier` views and the server-owned grant `EXISTS`, run as
  a login that holds only `trust_api_reader`. The driver checks that login's
  memberships, and that a page of authority U returns 0 rows to it.
- **Warm**: `scripts/lab/history_scale_study.py` resets
  `pg_stat_statements`, makes one warm-up run, then 5 timed runs; the table
  gives the mean. The 1M database (850 MB) does not fit in shared_buffers,
  so "warm" still reads from the OS page cache.
- **Cold**: PostgreSQL restarted and the OS page cache dropped
  (`echo 3 > /proc/sys/vm/drop_caches`, which works in this container)
  before each case, then one `EXPLAIN (ANALYZE, BUFFERS)`. `DISCARD ALL`
  only resets session state and evicts no buffers, so it was not used as a
  cold start.
- **Load**: `scripts/lab/history_scale_load.py`, with one fixed pgbench
  script and `--random-seed=42`.
  - One transaction is one API page: the grant check, then one of six pages
    (page 1, middle cursor, CN medium, SAN strong, notAfter medium, combined
    medium).
  - Runs of 60 s with 1, 10 and 50 clients, every transaction logged.
  - The 3 s statement timeout was not set during the runs: a pgbench client
    that gets a cancellation aborts, which would lower the concurrency being
    measured. Transactions longer than 3 s are counted instead; with the
    timeout they would have failed.

## Results: certificate history of authority A (ms)

| Case | Matches | 100k warm | 100k cold | 1M warm | 1M cold | 1M buffers hit / read per call |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| page 1, no filter | — | 113 | 178 | 1,046 | 1,415 | 3,182,096 / 49,319 |
| middle cursor | — | 77 | 119 | 684 | 970 | 1,600,304 / 31,108 |
| end cursor (last page) | — | 24 | 43 | 178 | 302 | 1,174 / 30,436 |
| CN strong | 0.1% | 106 | 141 | 969 | 1,239 | 3,184,948 / 46,467 |
| CN medium | 10% | 105 | 140 | 971 | 1,201 | 3,182,210 / 49,206 |
| CN null | 0 | 105 | 138 | 945 | 1,220 | 3,182,220 / 49,195 |
| SAN strong | 0.1% | 129 | 181 | 1,296 | 1,700 | 3,182,193 / 49,210 |
| SAN medium | 9% | 129 | 184 | 1,285 | 1,616 | 3,182,175 / 49,227 |
| SAN null | 0 | 129 | 169 | 1,293 | 1,580 | 3,182,191 / 49,211 |
| notAfter strong | 0.2% | 22 | 43 | 175 | 295 | 7,371 / 30,917 |
| notAfter medium | 9% | 31 | 49 | 273 | 388 | 289,423 / 30,245 |
| notAfter null | 0 | 22 | 41 | 182 | 278 | 1,841 / 29,573 |
| combined strong | 0.01% | 107 | 144 | 1,076 | 1,333 | 3,182,195 / 49,207 |
| combined medium | 1% | 108 | 151 | 1,026 | 1,389 | 3,182,176 / 49,226 |
| combined null | 0 | 29 | 50 | 276 | 493 | 288,738 / 30,917 |
| SAN medium, middle cursor | 9% | 80 | 111 | 810 | 987 | 1,590,968 / 31,095 |
| SAN medium, end cursor | 9% | 23 | 43 | 196 | 285 | 3,459 / 30,423 |

Concurrent load (fixed script, 60 s each):

| Fixture | Readers | Pages | Pages/s | p50 | p95 | max | > 3 s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 100k | 1 | 663 | 11.0 | 103 ms | 131 ms | 169 ms | 0 |
| 100k | 10 | 944 | 15.6 | 588 ms | 1,279 ms | 1,617 ms | 0 |
| 100k | 50 | 979 | 15.9 | 3,555 ms | 4,836 ms | 5,176 ms | 601 (61%) |
| 1M | 1 | 64 | 1.1 | 1,026 ms | 1,295 ms | 1,364 ms | 0 |
| 1M | 10 | 103 | 1.6 | 5,136 ms | 12,199 ms | 14,620 ms | 85 (83%) |
| 1M | 50 | 119 | 1.6 | 30,772 ms | 42,260 ms | 55,558 ms | 119 (100%) |

No transaction failed: no timeout was set (see Setup). The API's own bounds
(16 data requests in flight and 8 database requests per process, then 503)
would turn most of the 50-reader queue into 503 responses or timeouts
before it reached PostgreSQL.

## Reading of the plans

1. **Every page reads the whole authority, except where a leakproof
   predicate cuts it down.**
   - Page 1, the CN filters, the SAN filters and the combined filters read
     all 800,000 rows of A and probe `certificate_request` once per row
     (3.2 million buffers).
   - Cursor pages cost in proportion to the rows that remain after the
     cursor (middle: half; last page: almost nothing).
   - The notAfter filter is cheap because `text < text` is leakproof, so it
     is evaluated on `certificate` before the join; the combined-null case
     includes it.
2. **Leakproof status decides what can reach the table.**
   - Leakproof: `texteq` and `text_lt` (equality and range on text).
   - Not leakproof: `textlike`, `lower`, `arraycontains` (`@>`) and
     `array_eq`.
   - A non-leakproof predicate on a `security_barrier` view is evaluated
     above the view's join, after every row has been read.

## Hypothesis (a): does the text cast in the view prevent index use?

**Yes for ordinary indexes, but the cast is not the main obstacle.** These
measurements use the 1M copy.

| Test | Plan | Time |
| --- | --- | ---: |
| View, small authority S1 (20,000 rows), existing PK `(ca_id, serial)` | Parallel Seq Scan, `Filter: (ca_id)::text = '…'` (326,667 rows removed per worker) | 90 ms |
| Base table, same authority, `ca_id = '…'::uuid` | Index Scan on the PK | 22 ms |
| Base table with a raw index `(ca_id, signed_at, request_id)` | Index Only Scan, 101 rows read | 0.1 ms |
| View with that raw index | still Parallel Seq Scan: the index is on `uuid`/`timestamptz`, the view compares text | 83 ms |
| View with an expression index `(ca_id::text)` | Index Scan on it for the CA: the cast can be indexed. The planner then hash-joins all 1M requests | 102 ms |
| View with an expression index matching the order (`ca_id::text`, an IMMUTABLE copy of the time formatting, `request_id::text`), barrier kept | Index Scan for S1, then Sort; Seq Scan for A | S1 35 ms, A 932 ms |
| Same index, view **without** `security_barrier` | Index Scan Backward, stops at 101 rows | S1 0.5 ms, A 0.6 ms |

The cast hides the raw indexes, and an expression index on the cast
expression fixes that. What makes every page read the whole authority is
the barrier: PostgreSQL does not push `ORDER BY … LIMIT` into a
`security_barrier` subquery. The existing view's time column uses
`to_char`, which is only STABLE, so it cannot be indexed as it stands; it
needs an IMMUTABLE copy of the same formatting (UTC fixed, numeric fields
only).

A range bound on the formatted time is leakproof (`text >=`) and does reach
that index through the barrier. Paging by time window (the 10 newest days,
widened while a page holds fewer than 101 rows) answered page 1 of A in
10–37 ms with the barrier kept.

## Hypothesis (b): the per-row SAN `unnest`

The API predicate `EXISTS (SELECT 1 FROM unnest(san_dns) … lower(name) = $x)`
runs above the barrier, once per row: 1.3 s on 1M for any selectivity.

| Option | Barrier | SAN strong (`pool-7`) | SAN medium (`grp-3`) | SAN null | Notes |
| --- | --- | ---: | ---: | ---: | --- |
| API form as is | kept | 1,296 ms | 1,285 ms | 1,293 ms | baseline |
| GIN on `lower_names(san_dns)`, query `@> ARRAY[$x]`, base table | — | 25 ms | — | — | index works on the table |
| Same GIN and query through the view | kept | 1,825 ms | — | — | `@>` is not leakproof: no index, more expensive than the baseline |
| Same GIN and query, view without barrier | removed | 5.5 ms | — | — | index used through the view |
| Same GIN, API `unnest` form, view without barrier | removed | 1,305 ms | — | — | the API query would have to change |
| Normalized table `certificate_san(ca_id, request_id, name_lower)` behind its own barrier view, `request_id IN (…)` | kept | 659 ms | 768 ms | 5 ms | the certificate side still reads all of A |
| Same table, `JOIN` form | kept | 638 ms | 11,786 ms | 5 ms | the medium case is far worse (nested loop over 83M pairs) |
| Same table with the signing time, two queries: 101 ids from the SAN view, then `request_id = ANY($ids)` on the certificate view | kept | 5.7 + 2.8 ms | 97 + 0.9 ms | 0.1 + 0.1 ms | only `text =` predicates, all leakproof; the first step still sorts the matches |

The normalized table held 2,700,108 rows and took 885 MB on the 1M fixture,
about as much as the certificates themselves.

## CN prefix (an option measured alongside)

`lower(subject_cn) LIKE 'app-%'` is not leakproof (`lower`, `textlike`). A
stored, generated column `subject_cn_lower` (`lower(subject_cn)`,
`COLLATE "C"` so that the prefix range is exact), with the index
`(ca_id::text, subject_cn_lower)` and the range predicate
`>= 'app-' AND < 'app.'` (leakproof), keeps the barrier:

| CN | Time | Plan |
| --- | ---: | --- |
| strong (`svc-`) | 10.9 ms | index |
| medium (`app-`) | 245 ms | sequential scan and sort of 80,000 rows |
| null (`zzz-`) | 0.15 ms | index |

The baseline is about 970 ms in all three cases.

## Bottlenecks and options

Security properties that every option keeps unless stated otherwise:
- the views stay `security_barrier`;
- the server-owned grant `EXISTS` and the mandatory `ca_id` predicate stay
  in every query;
- the cursor stays `(signed_at text, request_id text)` in the same order;
- the reader role stays read-only, with `SELECT` on views only.

### 1. Unfiltered and cursor pages read the whole authority (1.0 s at 1M; 1.6 pages/s; 100% over 3 s at 50 readers)

1. **Page by time window, barrier kept.**
   - Change: an IMMUTABLE copy of the time formatting used by the view
     (same output text), an ordered expression index, and an API loop that
     adds a lower bound `signed_at >= window` and widens it when a page
     holds fewer than 101 rows.
   - Measured: 10–37 ms for page 1 of A.
   - Security: barrier, grants, cursor order and read-only role unchanged.
     The new function must be truly IMMUTABLE (UTC fixed, numeric format);
     if it were not, the index could return wrong rows.
   - Costs: more API logic, and a sparse filter can need many windows (up
     to a full scan in the worst case).
2. **Remove `security_barrier` from `management_certificate` and
   `management_audit`, plus the ordered expression index.**
   - Measured: under 1 ms for any page; the planner reads 101 rows from the
     index.
   - Security: grants, cursor order and read-only role unchanged. Today the
     barrier adds no isolation: the views filter no rows, and
     `trust_api_reader` can read every authority directly (measured on the
     earlier fixture). Its removal is a security-model decision, because any
     future row filtering in these views (database-level isolation) would
     need the barrier again, together with a different answer to ordering.

### 2. DNS SAN filter (1.3 s at 1M, whatever the selectivity)

1. **Normalized SAN table behind its own barrier view, two queries.**
   - Measured: 8 ms strong, 98 ms medium, 0.2 ms null.
   - Security: barrier kept; the reader gets `SELECT` on one more barrier
     view and nothing on the table. The table is written in the same
     transaction as the certificate (by the issuance functions or a
     trigger), so it can never disagree with the stored array. The cursor
     order is unchanged, because the SAN view carries the same
     `(signed_at, request_id)` text.
   - Costs: about +100% storage, a backfill, a write-path change, and an
     API change (two round trips; combining it with CN or notAfter filters
     needs a loop like option 1.1).
2. **GIN on the lowered array with an `@>` query.**
   - Measured: 5.5 ms.
   - Security: only with the barrier removed (option 1.2); otherwise slower
     than today. It also needs an IMMUTABLE lower-array function and a
     change to the API predicate.

### 3. CN prefix filter (about 1.0 s at 1M)

1. **Stored lowered CN (`COLLATE "C"`) and a leakproof range predicate.**
   - Measured: 11 ms strong, 245 ms medium, 0.15 ms null.
   - Security: barrier kept; the column is derived, so it cannot diverge
     from `subject_cn`. The API must build the range bound safely (the
     successor of the last character); the escaping of `%`, `_` and `\`
     becomes unnecessary.
   - Costs: a new column and index, and a migration with a table rewrite.
2. **With the barrier removed:** a `text_pattern_ops` index on
   `lower(subject_cn)` would serve the current `LIKE`. Not measured here.

### 4. notAfter filter (175–275 ms at 1M)

Already leakproof and evaluated before the join; it still scans the
authority and sorts. Options 1.1 or 1.2 cover it (an expression index on the
formatted notAfter). This is the lowest priority.

### 5. Concurrency

The throughput ceiling (16 pages/s at 100k, 1.6 at 1M) follows from items
1–3 and from 4 CPUs: each page uses up to 3 parallel processes. Fixing
items 1–3 is the lever. Raising the API's 8/16 slot bounds or the 3 s
timeout would only move the queue.

## Decision (2026-10-30)

The repository owner decided to **keep `security_barrier`** on the
management views for now. Option 1.2, and option 2.2 which depends on it,
are not pursued. The candidates that remain are 1.1, 2.1 and 3.1. Each
needs its own migration and API change, and none has been started.

## Reproduce

```sh
# disposable cluster with shared_preload_libraries = 'pg_stat_statements', port 55442
createdb scale_1m
for m in migrations/0*.sql; do psql -X -v ON_ERROR_STOP=1 -d scale_1m -f "$m"; done
psql -X -v ON_ERROR_STOP=1 -d scale_1m -v total=1000000 -v seed=42 -f tests/management_history_scale_seed.sql
python3 -I scripts/lab/history_scale_study.py --db scale_1m --out OUT --cold   # as root (restart, drop_caches)
python3 -I scripts/lab/history_scale_load.py --db scale_1m --dir OUT --seconds 60
```

## Limits

- One 4-CPU machine with default PostgreSQL settings. Larger memory, a
  different `random_page_cost` or a dedicated disk would change the
  absolute numbers, but not the plans' shape.
- The load test calls PostgreSQL directly; the API's OIDC verification and
  JSON encoding, and its 503 bounds, are not in the measured path.
- Synthetic distributions: real CN, SAN and validity selectivities will
  differ.
- The hypothesis tests used throwaway copies with objects created by hand
  (functions, indexes, a table, views). None of them is a reviewed
  migration.
