# Laboratory history-filter query plans

The read-only management API applies CN, DNS SAN and recorded `notAfter`
filters through `management_certificate`, a PostgreSQL security-barrier view.
Its three-second statement timeout is a bound, not evidence that a filter is
fast on a large authority. This rehearsal records the plan under the
`trust_api_reader` role and the same CA grant used by an authenticated API
read. It never uses production records or certificate DER as evidence.

The Rust schema job first exercises the 102-certificate pagination fixture,
then adds 10,000 synthetic certificates with
`tests/management_history_filter_plan_seed.sql`. It executes
`tests/management_history_filter_plan.sql` inside a read-only transaction and
prints `EXPLAIN (ANALYZE, BUFFERS)` for CN prefix, exact DNS SAN and recorded
validity end. The fixture contains one synthetic SAN/date match from the
pagination test and ten extra date-bearing rows. The SQL is deliberately close
to the API query, including the server-owned issuer/subject/CA grant check.

On a local PostgreSQL 16.15 fixture (22 October 2026), the three plans on 101
rows returned in 3.68 ms, 0.40 ms and 0.04 ms respectively. After inserting
10,000 extra rows inside a transaction and rolling it back, they returned in
9.95 ms, 8.51 ms and 0.36 ms on 10,101 rows. The CN and SAN plans scanned
both certificate and request tables, and the SAN filter ran `unnest` per
candidate row. The validity plan scanned certificate rows and removed 10,090
nonmatches. These are single warm-cache observations, not latency targets or
capacity results. The CI plan on 10,102 rows must be inspected before changing
an index or claiming a large-history bound.

The view formats timestamps and UUIDs as text for the API. This may prevent
use of ordinary indexes on underlying timestamp/UUID columns, and the SAN
array predicate may require a different query shape or an expression index.
Any change must retain the signed CA scope, database grant, cursor order and
read-only role. Follow-up load tests should vary authority size, matching
selectivity, concurrent readers and cold buffers; this rehearsal covers only
one disposable dataset.

The follow-up measurement on 306,000 certificates and 306,000 events across
302 authorities, with cursors, combined filters and concurrent readers, is in
[lab-history-load-query-plans.md](lab-history-load-query-plans.md).
