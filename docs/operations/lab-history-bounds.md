# Laboratory history first pages anchored at each authority's bounds

Lab only. This removes the remaining slow case of
[lab-history-time-window.md](lab-history-time-window.md) (0016). A first
history page used to start its time slices at the current time (newest
first) or at the CA's creation (oldest first). When the authority's rows
were more than 85 hours from that point, as for a CA that stopped issuing,
the slices found nothing and the page scanned the whole authority. The
earlier fixes needed planner hints or a view without the barrier, both left
to the owner. This one needs neither: every management view keeps its
barrier, and no planner setting is used.

**Outcome.** Measured on 1,000,000 certificates (800,000 in one authority),
through the API router, against the previous code (PR #170):

| Change | Before | After |
| --- | ---: | ---: |
| First page, newest first, authority that stopped issuing | 1,201 ms | 14 ms |
| First page, oldest first (either authority) | 1.1–1.2 s | 11–12 ms |
| CN medium, authority that stopped issuing | 362 ms | 28 ms |
| SAN medium, authority that stopped issuing | 148 ms | 16 ms |
| CN + SAN medium, authority that stopped issuing | 181 ms | 75 ms |

At 50 readers, the stopped authority now matches the active one:

| Authority | Before | After |
| --- | --- | --- |
| Stopped | 9.1 pages/s, 62% failed | 51.5 pages/s, 18% failed |
| Active | 50.3 pages/s, 18% failed | 48.2 pages/s, 18% failed |

## Change

### Migration 0019

- **Indexes:** `certificate (ca_id, signed_at)` and `audit_event (ca_id,
  recorded_at)`. These are plain columns, so unlike an index on `ca_id::text`
  they add no planner statistics for the views' CA predicate.
- **`management_history_bounds`** (`security_barrier`) gives each CA's
  newest and oldest signing and recording times, as millisecond windows.
  - Each bound is a scalar `max()` or `min()` subquery on the base table
    inside the view. PostgreSQL answers it with one probe of the index. The
    barrier does not stop this, because the aggregate is inside the view;
    only an `ORDER BY … LIMIT` from outside cannot enter it.
  - The view shows the first and last row times of each authority, which
    the history views already show. The reader gets `SELECT` on it.
- **Checks.**
  - The lab migration runner records 0019.
  - The API refuses to start, and `/v1/ready` returns 503, without the view.
  - The upgrade check compares every bound with the authority's rows.

### API

- **Anchor of a first page.** It is the authority's newest time (newest
  first) or oldest time (oldest first), read from the bounds view.
  - The statement keeps the CA predicate and the server-owned grant, in the
    page's transaction.
  - An authority with no rows starts at the current time.
  - The SAN steps of 0017 use the certificate bounds too.
- **Cursor pages:** still start at the cursor.
- **Correctness does not depend on the anchor.** The first slice of a first
  page stays open on its far side (newer than the anchor for newest first,
  older for oldest first). The other slices and the unsliced fallback are
  unchanged.

### Security properties

| Property | Effect |
| --- | --- |
| `security_barrier` views | kept; the new view has the barrier too |
| Server CA grant and mandatory `ca_id` | in the anchor query and every other statement |
| Cursor order and format | unchanged |
| Reader role | `SELECT` on one more view; still read-only |
| Isolation between CAs | unchanged; still enforced by the API query |
| Planner settings | none |

## Measurements

Method as in the previous documents: the same harness and fixtures, with
0019 applied to both. The previous code (`0e99275`) was measured before
and after this code on the same database state; the "before" columns give
the mean of those two runs.

| Case | Active: before | Active: after | Stopped: before | Stopped: after |
| --- | ---: | ---: | ---: | ---: |
| **page 1, newest first** | 19 | **10** | 1,201 | **14** |
| middle cursor | 11 | 10 | 12 | 12 |
| end cursor | 224 | 218 | 226 | 227 |
| **page 1, oldest first** | 1,166 | **12** | 1,115 | **11** |
| CN strong (0.1%) | 29 | 29 | 28 | 30 |
| **CN medium (10%)** | 27 | 30 | 362 | **28** |
| CN null | 13 | 13 | 13 | 14 |
| SAN strong (0.1%) | 18 | 16 | 17 | 17 |
| **SAN medium (9%)** | 14 | 14 | 148 | **16** |
| SAN null | 11 | 10 | 10 | 17 |
| notAfter strong | 224 | 183 | 197 | 207 |
| notAfter medium | 306 | 300 | 303 | 310 |
| notAfter null | 218 | 185 | 188 | 210 |
| CN + SAN strong | 67 | 61 | 63 | 80 |
| **CN + SAN medium** | 72 | 52 | 181 | **75** |
| CN + SAN + notAfter, null | 11 | 10 | 9 | 11 |
| SAN medium, middle cursor | 15 | 13 | 13 | 18 |

- The differences of a few milliseconds on the fast cases are within the
  run-to-run spread seen in the previous documents. The largest are SAN null
  (10 → 17 ms) and CN + SAN strong (63 → 80 ms) on the stopped authority.
- The scale fixtures hold no audit events, so the audit bounds were checked
  by the load plans (B1) and the upgrade check, not timed.

Concurrent readers (60 s each, the load mix):

| Fixture | Readers | Before: pages/s | Before: failed | After: pages/s | After: failed |
| --- | ---: | ---: | ---: | ---: | ---: |
| active | 1 | 13.3 | 0% | 13.6 | 0% |
| active | 10 | 23.9 | 6% | 22.0 | 6% |
| active | 50 | 50.3 | 18% | 48.2 | 18% |
| stopped | 1 | 3.2 | 0% | 12.8 | 0% |
| stopped | 10 | 5.5 | 26% | 23.2 | 6% |
| stopped | 50 | 9.1 | 62% | 51.5 | 18% |

The 18% failures that remain at 50 readers are pages that exceed the 3 s
limit under contention for 4 CPUs. On their own, every case of the mix now
takes under 310 ms.

## Tests

- **`tests/management_history_load_plans.sql`** gains B1: 0.16 ms on 50,000
  rows per authority. It fails if any bound does not come from its index, or
  if the plan scans `certificate` or `audit_event` sequentially.
- **`tests/management_populated_upgrade_verify.sql`** (upgrade, retry and
  ledger tests) fails if any bound differs from the authority's rows, or if
  the view does not list every CA.
- **`history_slices_read_every_row_in_order`** passes unchanged. Its first
  pages now start at the fixture's newest row, three days in the future,
  instead of the current time.
- **Migration and restore scripts.** The ledger, retry, upgrade and restore
  scripts include 0019.

## Limits

- **Remaining load failures.** These come from capacity on this 4-CPU
  machine (18% at 50 readers), not from a scan of the authority. The API's
  own bounds (8 database requests per process, then 503) would refuse most
  of that load earlier.
- **Sparse filters.** Sparse CN and notAfter filters still end in the
  unsliced statement, now with indexes for CN (0018); notAfter has none.
- **Scope of the measurements.** One machine and warm caches, as before.
