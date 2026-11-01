# Laboratory history CN filter on a stored lowered column

Lab only. This implements option 3.1 of
[lab-history-scale-study.md](lab-history-scale-study.md). The CN prefix filter
of certificate history reads an index through the `security_barrier`
certificate view instead of running `lower(subject_cn) LIKE` above the
barrier on every row. It builds on the time slices of 0016
([lab-history-time-window.md](lab-history-time-window.md)) and the SAN table
of 0017 ([lab-history-san-table.md](lab-history-san-table.md)). Every
management view keeps its barrier.

**Outcome.** Measured on 1,000,000 certificates (800,000 in one authority),
through the API router, against the previous code (PR #169):

| Change | Before | After |
| --- | ---: | ---: |
| CN prefixes with few or no matches | 1.1 s | 11–25 ms |
| A medium CN prefix on an authority that stopped issuing | 1.1 s | 359 ms |

- A medium prefix on an authority still issuing was already fast through
  the time slices. It now costs 31 ms instead of 21 ms (see the plans
  below).
- Other cases are unchanged.
- The column and its index add 31 MB of index, plus the stored text, to the
  certificate table.

## Change

### Migration 0018

- **`certificate.subject_cn_lower`** is a stored generated column,
  `lower(subject_cn)`, in the `"C"` collation.
  - PostgreSQL computes it on every write. No one can write it directly, so
    it cannot disagree with `subject_cn`.
  - `lower()` is the function the previous API predicate applied, so
    matching is unchanged.
- **`management_certificate`** (still `security_barrier`) gains the column
  at its end. It shows nothing that `subject_cn` did not already show.
- **Index.** `certificate_management_cn_lower` is on the column alone. An
  index that also covered `ca_id::text` would change the planner's
  statistics for the view's CA predicate, the regression measured for 0016.
- **Cost.** Adding the column rewrites the table: 9–17 s on the 1M fixture.
- **Checks.**
  - The lab migration runner records 0018.
  - The API refuses to start, and `/v1/ready` returns 503, without the
    column.
  - The upgrade check fails if any row's column differs from
    `lower(subject_cn)`.

### API

- **Before:** `lower(subject_cn) LIKE $1 ESCAPE '\'`, with `%`, `_` and `\`
  escaped. `lower()` and `LIKE` are not leakproof, so this ran above the
  barrier.
- **After:** `subject_cn_lower ^@ $1`, where `$1` is the trimmed,
  lowercased input.
  - `starts_with` (`^@`) is leakproof, so it reaches the scan.
  - On a `"C"`-collated column, PostgreSQL turns it into a btree range on
    the index.
  - Wildcards are literal by construction, as they were after escaping.
- **Unchanged:** input validation, page order, cursor and the time slices.
- **CA list search:** it keeps its escaped `LIKE` on `management_ca`.

### Security properties

| Property | Effect |
| --- | --- |
| `security_barrier` views | kept; only `starts_with`, leakproof, reaches the scan |
| Server CA grant and mandatory `ca_id` | unchanged in every statement |
| Cursor order and format | unchanged |
| Reader role | unchanged privileges; one more column in a view it already reads |
| Isolation between CAs | unchanged; still enforced by the API query |
| Integrity of derived data | a generated column: computed by PostgreSQL from `subject_cn`, not writable |

## Measurements

Method as in the two previous documents: the same harness and fixtures,
with 0018 applied. The previous code (`f61ee01`) was measured before and
after this code on the same database state; the "before" columns give the
mean of those two runs.

### Pages (ms, authority A, 800,000 certificates)

| Case | Active: before | Active: after | Stopped: before | Stopped: after |
| --- | ---: | ---: | ---: | ---: |
| page 1, newest first | 20 | 17 | 1,169 | 1,192 |
| middle cursor | 11 | 9 | 11 | 10 |
| end cursor | 211 | 223 | 212 | 196 |
| page 1, oldest first | 1,098 | 999 | 1,088 | 1,043 |
| **CN strong (0.1%)** | 1,104 | **25** | 1,151 | **20** |
| **CN medium (10%)** | 21 | 31 | 1,132 | **359** |
| **CN null** | 1,133 | **12** | 1,082 | **11** |
| SAN strong (0.1%) | 19 | 18 | 17 | 15 |
| SAN medium (9%) | 14 | 12 | 123 | 120 |
| SAN null | 9 | 10 | 8 | 8 |
| notAfter strong | 202 | 212 | 201 | 181 |
| notAfter medium | 304 | 294 | 301 | 287 |
| notAfter null | 199 | 190 | 195 | 194 |
| CN + SAN strong | 69 | 54 | 65 | 76 |
| CN + SAN medium | 64 | 52 | 175 | 188 |
| CN + SAN + notAfter, null | 10 | 10 | 9 | 9 |
| SAN medium, middle cursor | 13 | 13 | 14 | 12 |

- **CN medium, active authority (21 → 31 ms).** For the 64-hour slice the
  planner combines the window and CN indexes in a `BitmapAnd` (16 ms)
  instead of reading the window index alone (10 ms).
- **CN medium, stopped authority (359 ms).** The unsliced fallback reads the
  80,000 matching rows of the authority from the CN index and sorts them.
- **Combined CN + SAN.** These cases already went through the SAN table
  (0017); the CN predicate only filters its batches.

### Concurrent readers (60 s each, the load mix)

| Fixture | Readers | Before: pages/s | Before: failed | After: pages/s | After: failed |
| --- | ---: | ---: | ---: | ---: | ---: |
| active | 1 | 13.3 | 0% | 13.0 | 0% |
| active | 10 | 22.5 | 6% | 23.6 | 6% |
| active | 50 | 50.4 | 18% | 52.3 | 18% |
| stopped | 1 | 2.3 | 0% | 3.2 | 0% |
| stopped | 10 | 4.0 | 40% | 6.0 | 23% |
| stopped | 50 | 10.1 | 58% | 9.3 | 61% |

- **Active authority.** The mix's CN filter is the medium one, already fast
  there, so load does not change.
- **Stopped authority.** Up to 10 readers, CN medium (now 359 ms) raises
  throughput. At 50 readers the remaining failures come from first pages
  that read the whole authority (the anchor limit of 0016), and the totals
  stay within run-to-run spread.

## Tests

- **`history_slices_read_every_row_in_order`** (fixture
  `tests/management_history_window_seed.sql`, in CI) gains three CN cases.
  The fixture now has mixed-case CNs `Wild_%-<n>` and near misses
  `wildx-<n>`. Each case must equal the previous escaped `LIKE` through the
  same view:
  - `WILD_%`;
  - `wild_` (which must not match `wildx-`);
  - `wildx`, oldest first.
- **Mutation checks.** Each of these makes the test fail:
  - an unescaped `LIKE` on the new column (`_` becomes a wildcard);
  - a prefix that is not lowercased;
  - a generated column without `lower()`.
- **`tests/management_history_load_plans.sql`** gains K1 and fails unless it
  uses `certificate_management_cn_lower`. Locally, on 50,000 certificates
  per authority, K1 takes 9.0 ms against 133 ms for the previous form (C3).
- **Migration and restore scripts.** The ledger, retry, upgrade and restore
  scripts include 0018; the upgrade check compares the column with
  `lower(subject_cn)`. The core-row fingerprint of the migration tests leaves
  the derived column out, as it already left out the 0014–0015 metadata.

## Limits

- **Collation changes.** `lower()` is evaluated when a row is written. A
  later change of the database's collation provider version could make
  stored values differ from what `lower()` returns afterwards. The upgrade
  check detects this; regenerating means rewriting the column.
- **Unicode case folding.** The input is lowercased by Rust's `to_lowercase`
  and the column by PostgreSQL's `lower()`. They agree on ASCII. On other
  scripts they may differ, exactly as the previous predicate could.
- **Remaining slow cases.**
  - A medium CN prefix on an authority with no recent rows still sorts all
    its matches (359 ms on 80,000).
  - First pages far from the authority's rows (0016) are unchanged.
- **Scope of the measurements.** One machine and warm caches, as before.
