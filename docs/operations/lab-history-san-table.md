# Laboratory history SAN filter through a normalized table

Lab only. This implements option 2.1 of
[lab-history-scale-study.md](lab-history-scale-study.md): the DNS SAN filter
of certificate history reads an index through its own `security_barrier`
view instead of unnesting every certificate's array above the barrier. It
builds on the time slices of
[lab-history-time-window.md](lab-history-time-window.md) (migration 0017).
Every management view keeps its barrier.

**Outcome.** Measured on 1,000,000 certificates (800,000 in one authority),
through the API router, against the previous code (PR #168):

| Change | Before | After |
| --- | ---: | ---: |
| SAN filters with few or no matches | 1.4–1.5 s | 8–19 ms |
| Combined CN + SAN filters | 1.2 s | 58–166 ms |
| A medium SAN filter on an authority that stopped issuing | 1.4 s | 123 ms |

- Other cases are unchanged.
- At 50 readers on an authority still issuing, throughput rises from 15.6
  to 50.5 pages/s and failed pages fall from 50% to 18%.
- Cost: the SAN table and its indexes take 626 MB beside the
  certificates' 450 MB on this fixture.

## Change

### Migration 0018

- **`certificate_san_dns`** holds one row per certificate and lowered DNS
  name, with the certificate's `ca_id` and `signed_at`.
  - Its primary key `(request_id, name_lower)` collapses case variants and
    repeats of a name in one certificate.
  - A foreign key to `certificate (request_id)` cascades updates and deletes.
- **The trigger `certificate_san_dns_sync`** maintains it after `INSERT`, and
  after `UPDATE OF request_id, ca_id, signed_at, san_dns`.
  - It runs in the same transaction, from the new row alone, and replaces
    the certificate's rows.
  - `lower()` is the function the previous API predicate applied to each
    name, so matching is unchanged.
  - The trigger function is `SECURITY INVOKER` with a pinned `search_path`.
    On this branch certificates are written by the schema owner. A future
    writer role would need write access to the table, or issuance would fail
    closed.
- **Backfill.** The migration fills the table from existing rows: 2,700,108
  rows in 55 s on the 1M fixture.
- **`management_certificate_san`** (`security_barrier`) exposes `ca_id`,
  `request_id`, `san_dns` (the lowered name), `signed_at` and
  `signed_at_window`. They use the same text formats and window expression
  as `management_certificate`, from the same copied instant.
  - The reader gets `SELECT` on the view only, not on the table.
  - Everything it shows was already readable through `management_certificate`.
- **Indexes.**
  - `((ca_id::text), name_lower, window)` on the SAN table, for the
    leakproof equalities and range the API sends.
  - `((request_id::text))` on `certificate`, for the second step.
- **Checks.**
  - The lab migration runner records 0018.
  - The API refuses to start, and `/v1/ready` returns 503, without the view.
  - The upgrade check and the window fixture fail if the table differs, in
    either direction, from the lowered distinct names of every
    certificate's array.

### API

A certificate page with `san_dns` is read in two steps, in the page's
`REPEATABLE READ READ ONLY` transaction and 3-second budget:

1. **Step one** reads up to 101 request ids, in page order, from
   `management_certificate_san`.
   - The statement has the CA predicate, the server-owned grant, the page
     cursor and `san_dns = $name`.
   - It uses the time slices of 0017, with their unsliced fallback.
2. **Step two** reads those certificates from `management_certificate`
   with `request_id = ANY($ids)`.
   - The statement also has the CA predicate, the grant, the cursor and the
     CN and notAfter filters.
3. **Continuation.** When the other filters drop rows and step one returned
   a full batch, step one continues after its last id.

Both steps order by the same `(signed_at, request_id)` text, so the page
order and the `X-Next-Cursor` format are unchanged.

### Security properties

| Property | Effect |
| --- | --- |
| `security_barrier` views | kept on all views; the new view has the barrier too; only `text =`, `= ANY` and timestamp ranges (leakproof) reach the scans |
| Server CA grant and mandatory `ca_id` | in both steps and in every slice |
| Cursor order and format | unchanged |
| Reader role | `SELECT` on one more view; no privilege on the table; still read-only |
| Isolation between CAs | unchanged; still enforced by the API query |
| Integrity of derived data | written only by the trigger, from the certificate row, in its transaction; no role but the owner holds a privilege on the table |

## Measurements

Method as in [lab-history-time-window.md](lab-history-time-window.md):
- the same harness and fixtures, with 0018 applied to both;
- the previous code (`19e0152`) measured before and after this code on the
  same database state; the "before" columns give the mean of those two runs.

The **active** fixture had aged 46 hours since it was built: its newest row
was 46 hours old. First pages then need the 64-hour slice, so they are
slower than in the previous document.

### Pages (ms, authority A, 800,000 certificates)

| Case | Active: before | Active: after | Stopped: before | Stopped: after |
| --- | ---: | ---: | ---: | ---: |
| page 1, newest first | 20 | 26 | 1,141 | 1,024 |
| middle cursor | 12 | 10 | 12 | 9 |
| end cursor | 207 | 231 | 205 | 197 |
| page 1, oldest first | 1,145 | 1,106 | 1,170 | 1,091 |
| CN strong (0.1%) | 1,075 | 1,145 | 1,080 | 1,087 |
| CN medium (10%) | 19 | 18 | 1,102 | 1,161 |
| CN null | 1,113 | 1,088 | 1,036 | 1,076 |
| **SAN strong (0.1%)** | 1,470 | **19** | 1,412 | **16** |
| **SAN medium (9%)** | 21 | **12** | 1,401 | **123** |
| **SAN null** | 1,452 | **8** | 1,446 | **10** |
| notAfter strong | 200 | 195 | 204 | 187 |
| notAfter medium | 304 | 288 | 300 | 283 |
| notAfter null | 204 | 192 | 186 | 202 |
| **CN + SAN strong** | 1,168 | **58** | 1,206 | **66** |
| **CN + SAN medium** | 1,162 | **59** | 1,153 | **166** |
| **CN + SAN + notAfter, null** | 280 | **9** | 292 | **10** |
| **SAN medium, middle cursor** | 35 | **13** | 36 | **13** |

- Cases without a SAN filter do not use the new view. Their differences
  (up to about ±12%, a few milliseconds on the fast cases) are the
  run-to-run spread of the earlier measurements.
- The combined cases now cost the CN filter applied to at most a few
  batches of SAN matches.

### Concurrent readers (60 s each, the load mix)

| Fixture | Readers | Before: pages/s | Before: failed | After: pages/s | After: failed | After: p50 / p95 (served) |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| active | 1 | 2.0 | 0% | 13.3 | 0% | 20 / 319 ms |
| active | 10 | 4.3 | 41% | 23.6 | 6% | 64 / 1,277 ms |
| active | 50 | 15.6 | 50% | 50.5 | 18% | 240 / 837 ms |
| stopped | 1 | 1.2 | 0% | 2.3 | 0% | 249 / 1,230 ms |
| stopped | 10 | 1.2 | 71% | 4.1 | 38% | 98 / 1,835 ms |
| stopped | 50 | 3.2 | 84% | 10.3 | 58% | 173 / 2,778 ms |

- Failed pages returned 503 at the page's 3-second limit.
- The mix's other slow pages are page 1 and CN medium on the stopped
  fixture. Those are the first-page anchor limit of 0017 and bottleneck 3
  (CN), not changed here.

## Tests

- **`history_slices_read_every_row_in_order`** (fixture
  `tests/management_history_window_seed.sql`, in CI) gains eight SAN cases:
  - a frequent name stored twice with different case, newest and oldest
    first, queried in upper case once;
  - a rare name stored only in upper case;
  - a single-certificate name and an absent name;
  - a dense and a sparse CN + SAN combination.

  Each must equal the previous `unnest` predicate through the same view, as
  the reader login.
- **Mutation checks.** Each of these makes the test or its fixture fail:
  - stopping after the first batch of SAN matches;
  - resuming step one after a wrong id;
  - a trigger without `lower()` (the fixture's consistency check fails).
- **`tests/management_certificate_san.sql`** (in CI) checks:
  - no rows for a certificate without SANs;
  - lowered distinct names, with NULL elements ignored;
  - replacement on a new array;
  - copying a new signing time;
  - equal time text and window to `management_certificate`;
  - no read or write of the table for the reader;
  - cascade on delete.
- **`tests/management_history_load_plans.sql`** gains S1 and S2, the two
  steps for a 0.1% SAN on 50,000 rows per authority in CI (0.5 ms and
  1.0 ms locally). It fails unless they use `certificate_san_dns_lookup` and
  `certificate_management_request_text`.
- **Migration and restore scripts.** The ledger, retry, upgrade and restore
  scripts include 0018.

## Limits

- **Storage.** The table roughly doubles the storage of certificate
  metadata on this fixture (three names per certificate).
- **Write path.** Each certificate insert or SAN update writes its names
  again. Issuance throughput with the trigger was not measured.
- **Remaining slow cases.** The CN filter (option 3.1) and first pages far
  from the authority's rows (0017) are unchanged.
- **Scope of the measurements.** One machine and warm caches, as before.
