# Laboratory history paging by time slice

Lab only. This implements option 1.1 of
[lab-history-scale-study.md](lab-history-scale-study.md): history pages read a
bounded time range through the `security_barrier` views instead of the whole
authority. The repository owner chose to keep the barrier (decision of
2026-10-30), so options that need it removed are not used.

**Outcome.** Measured on 1,000,000 certificates (800,000 in one authority),
through the API router:
- Unfiltered pages, cursor pages and medium-selectivity CN and SAN filters
  go from about 1 s to 8–32 ms when the authority has recent rows.
- Sparse or empty filters cost what they did before (within ±6% on the
  cases above one second). The same holds for a first page whose start
  point is far from the authority's rows (a CA that stopped issuing).
- At 50 concurrent readers on the active fixture, the share of pages served
  goes from 0% to about 50%. The remaining time-outs are the SAN and combined filters
  (bottlenecks 2 and 3 of the study, not addressed here).

## Change

### Migration 0016

- `management_certificate` gains `signed_at_window` and `management_audit`
  gains `recorded_at_window`: `date_trunc('milliseconds', time AT TIME ZONE
  'UTC')`. This is the same instant as the existing text column at the same
  precision, so no new information is exposed. A test checks that
  `to_char(window)` equals the text column on every row.
- The two expression indexes are on the window expression **alone**. Indexes
  on `(ca_id::text, window)` were tried first: they gave the planner exact
  statistics for the views' CA predicate, and with them it moved the unsliced
  SAN filter from a parallel hash join (1.7 s) to a serial merge join
  (3.8 s). This is the regression already seen with extended statistics in
  [lab-history-load-query-plans.md](lab-history-load-query-plans.md).
- Both views stay `security_barrier`. Grants, roles and the other columns
  are unchanged. The lab migration runner records 0016 and checks its
  columns and indexes. The API refuses to start, and `/v1/ready` returns
  503, without them (checked against a database migrated to 0015).

### API

- **Transaction.** One `REPEATABLE READ READ ONLY` transaction per page, so
  every slice of a page sees one snapshot. The grant check runs in it. The
  3-second limit now covers the whole page: each statement gets what is
  left of it.
- **Anchor.** The slices start from:
  - the cursor's time;
  - for a first page, the current time (newest first) or the CA's creation
    time (oldest first).
- **Slices.** Up to four bounded slices of 1, 4, 16 and 64 hours outward
  from the anchor.
  - Each is the existing query plus a range on the window column.
    `timestamp <=`, `<`, `>=` and `>` are leakproof, so the range reaches the
    index through the barrier.
  - Slices are contiguous and disjoint, and all rows of one millisecond fall
    in one slice, so concatenating them keeps the page order. The text cursor
    `(signed_at, request_id)` is unchanged.
  - A first page has no bound on the far side of the anchor, so rows dated
    after the current time are still listed.
- **Fallback.** If the four slices hold fewer than 101 rows, the page is
  read again with the unsliced statement, whose plan is the one used before
  this change.
- **Cursor validation.** A cursor time is now checked as a real calendar
  time (an impossible date returned rows before; it now returns 400),
  because it anchors a timestamp.

### Security properties

| Property | Effect |
| --- | --- |
| `security_barrier` views | kept; only leakproof comparisons on the new column reach the scan |
| Server CA grant and mandatory `ca_id` | in every slice, and the grant check runs in the page's transaction |
| Cursor order and format | unchanged (text time, request or event id) |
| Reader role | unchanged: `SELECT` on the views only, transactions read-only |
| Isolation between CAs | unchanged; still enforced by the API query (see the load study) |
| Exposed data | one column per view, equal to the existing time at the same precision |

## Measurements

### Method

- **Fixtures.** `tests/management_history_scale_seed.sql` with `total=1000000`
  and `seed=42`, built twice:
  - **active**: `-v origin` set to 730 days before the run, so the
    authority's newest row is about now;
  - **stopped**: the default origin, so its rows end on 2025-12-31, ten
    months before the run.
- **Harness.** `crates/management-api/src/history_timing.rs`.
  - It goes through the API router with a signed test token, as a login
    holding only `trust_api_reader`. Each request opens its own connection,
    as the API does.
  - Medians of 5 warm runs per case.
  - The load mix (page 1, middle cursor, CN medium, SAN strong, notAfter
    medium, combined medium) runs for 60 s per client count.
  - The API slot limits are raised to the client count, so time-outs come
    from the database rather than the 503 bound.
- **Comparison.** The previous code (`de44f17`, same harness) ran before and
  after the new code on the same database state; the table gives the mean of
  those two runs. Its queries do not reference the window expression, so its
  plans are the same with or without the new index.
- **Environment.** PostgreSQL 16.15 with default settings, 4 CPUs, 15 GB,
  rustc 1.99.0, release build.

### Pages (ms, authority A, 800,000 certificates)

| Case | Active: before | Active: after | Stopped: before | Stopped: after |
| --- | ---: | ---: | ---: | ---: |
| page 1, newest first | 1,363 | **8** | 1,256 | 1,238 |
| middle cursor | 898 | **8** | 810 | **10** |
| end cursor (last page) | 240 | 202 | 221 | 198 |
| page 1, oldest first | 1,166 | 1,114 | 1,086 | 1,069 |
| CN strong (0.1%) | 1,220 | 1,148 | 1,093 | 1,094 |
| CN medium (10%) | 1,116 | **25** | 1,056 | 1,076 |
| CN null | 1,080 | 1,070 | 1,144 | 1,084 |
| SAN strong (0.1%) | 1,557 | 1,582 | 1,577 | 1,599 |
| SAN medium (9%) | 1,506 | **30** | 1,627 | 1,645 |
| SAN null | 1,518 | 1,599 | 1,559 | 1,551 |
| notAfter strong | 210 | 188 | 212 | 253 |
| notAfter medium | 306 | 296 | 303 | 290 |
| notAfter null | 204 | 227 | 208 | 238 |
| CN + SAN strong | 1,326 | 1,270 | 1,201 | 1,195 |
| CN + SAN medium | 1,244 | 1,209 | 1,153 | 1,181 |
| CN + SAN + notAfter, null | 305 | 368 | 340 | 349 |
| SAN medium, middle cursor | 987 | **32** | 971 | **36** |

Reading:
- A page gains when 101 matching rows lie within 85 hours of its anchor.
- Otherwise it costs the unsliced statement plus four small slices (a few
  milliseconds, up to about 60 ms on the 300 ms cases).
- The oldest-first first page starts from the CA's creation, 31 days before
  its first certificate in this fixture, so it does not gain.
- On the stopped fixture, newest-first first pages start from the current
  time, ten months after the last row, so they do not gain either.

### Concurrent readers (60 s each, the load mix)

| Fixture | Readers | Before: pages/s | Before: failed | After: pages/s | After: failed | After: p50 / p95 (served) |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| active | 1 | 1.0 | 0% | 1.8 | 0% | 297 / 1,777 ms |
| active | 10 | 0.3 | 91% | 4.4 | 40% | 41 / 1,601 ms |
| active | 50 | 0 | 100% | 15.6 | 50% | 124 / 381 ms |
| stopped | 1 | 1.1 | 0% | 1.2 | 0% | 1,107 / 1,802 ms |
| stopped | 10 | 0.5 | 87% | 1.2 | 72% | 36 / 2,174 ms |
| stopped | 50 | 0 | 100% | 3.3 | 84% | 97 / 209 ms |

- "Failed" pages returned 503: the 3-second limit, which the earlier study
  left unset under pgbench.
- The "before" load rows were measured without the 0016 indexes.
- Failed requests' durations were not recorded. Under load, the slow pages
  of the mix (SAN strong, combined medium and, on the stopped fixture, page
  1 and CN medium) are the ones that exceed the limit. This is an inference
  from the per-case times above, not a per-request measurement.

## Tried and rejected

1. **Skipping empty stretches with `EXISTS` probes** (to find the rows of a CA
   that stopped issuing).
   - Through the barrier, the planner answers a probe over a wide range with
     a sequential scan, or with `enable_seqscan` off, a full scan of another
     index. When the matching rows sit at the far end of the table, either
     costs 300–700 ms per probe.
   - A covering index with planner settings turned off made probes fast, but
     only through planner hints. Rejected for now; see the limits below.
2. **An open last slice** (the remaining rows with a window bound) instead of
   the unsliced fallback. The per-row window computation in the scan made
   sparse filters 25–40% slower than before. Rejected.
3. **Indexes on `(ca_id::text, window)`**: the SAN plan regression above.
   Rejected.

## Tests

- `history_slices_read_every_row_in_order`
  (`tests/management_history_window_seed.sql`, run in CI):
  - **Fixture:** 376 rows with ties in one millisecond, rows in the future,
    minute, hour and 30-day spacing, the year 1601, and rows older than the
    CA.
  - **Pages:** every page of both orders, a sparse CN filter and an audit
    event-type filter, for certificates and audit events.
  - **Check:** each listing must equal one unsliced statement through the
    same views, as the reader login.
  - **Mutation checks:** each of these makes it fail:
    - an exclusive inner bound (newest or oldest);
    - a one-second gap between slices;
    - stopping after the first non-empty slice;
    - dropping the fallback.
- `history_slices_partition_distances` and
  `history_cursor_time_checks_calendar_date` (unit tests).
- `tests/management_history_load_plans.sql`:
  - **W1 and W2:** the first bounded slice of a certificate page and of an
    audit page;
  - **Check:** fails unless the plans use the window indexes.
- The migration ledger, retry, upgrade and restore scripts include 0016, and
  `tests/management_populated_upgrade_verify.sql` checks that the window
  columns equal the text times.

## Reproduce

```sh
# 1M fixture of an authority still issuing (without -v origin, rows end on 2025-12-31)
createdb scale_1m_recent
for m in migrations/0*.sql; do psql -X -v ON_ERROR_STOP=1 -d scale_1m_recent -f "$m"; done
psql -X -v ON_ERROR_STOP=1 -d scale_1m_recent -v total=1000000 -v seed=42 \
  -v origin="$(date -u -d '730 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
  -f tests/management_history_scale_seed.sql
# reader login holding only trust_api_reader, then:
TRUST_API_TIMING_DATABASE_URL=postgresql://<reader>@<host>/scale_1m_recent \
TRUST_API_TIMING_CLIENTS=1,10,50 \
  cargo test -p trust-management-api --release --bin trust-management-api \
  history_timing -- --nocapture
```

## Limits

- **Remaining slow cases.**
  - A first page whose start point is more than 85 hours from the
    authority's rows: a CA that stopped issuing (newest first), or one
    created long before its first certificate (oldest first).
  - Filters matching fewer than 101 rows within 85 hours of the anchor.

  These still read the whole authority. Finding the rows' edge cheaply
  through the barrier needs either planner hints or a view without the
  barrier, and both are owner decisions.
- **Remaining bottlenecks.** SAN and CN filters keep their per-row cost
  (options 2.1 and 3.1 of the study).
- **Scope of the measurements.**
  - One machine and data that fits in the OS cache; no cold-cache run for
    this change.
  - No network latency between API and database.
  - The slice widths are tuned for this fixture's density (about 46 rows
    per hour); a much denser authority puts more rows in each slice.
- **Consistency.** One page is one snapshot; successive pages are not.
