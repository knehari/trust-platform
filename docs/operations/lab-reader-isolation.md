# Laboratory database isolation between authorities: cost

Lab only. This measures the cost of migration 0020
([ADR-0008](../adr/ADR-0008-database-reader-isolation.md), Proposed). Since
0020, every management view returns only the rows of authorities granted to
the reader principal the session declares. The method is that of
[lab-history-bounds.md](lab-history-bounds.md): the API router, 1,000,000
certificates with 800,000 in one authority, and two fixtures, one for an
authority still issuing ("active") and one for an authority that stopped
("stopped").

The previous code (PR #171, `69fc736`) ran on both databases at 0019. Then
0020 was applied and this code ran. This is one run of each, so the
run-to-run spread of the earlier documents (up to about ±12%) applies.

## Pages (median ms)

| Case | Active: 0019 | Active: 0020 | Stopped: 0019 | Stopped: 0020 |
| --- | ---: | ---: | ---: | ---: |
| page 1, newest first | 11 | 15 | 11 | 13 |
| middle cursor | 12 | 14 | 10 | 12 |
| end cursor | 221 | 218 | 224 | 230 |
| page 1, oldest first | 11 | 16 | 11 | 14 |
| CN strong | 33 | 38 | 30 | 36 |
| CN medium | 33 | 44 | 28 | 39 |
| CN null | 14 | 14 | 14 | 17 |
| SAN strong | 26 | 20 | 18 | 21 |
| SAN medium | 15 | 16 | 13 | 17 |
| SAN null | 10 | 13 | 9 | 13 |
| notAfter strong | 206 | 211 | 203 | 221 |
| notAfter medium | 314 | 432 | 303 | 351 |
| notAfter null | 213 | 207 | 194 | 232 |
| CN + SAN strong | 66 | 86 | 67 | 69 |
| CN + SAN medium | 60 | 74 | 60 | 70 |
| CN + SAN + notAfter, null | 10 | 14 | 10 | 13 |
| SAN medium, middle cursor | 16 | 17 | 13 | 15 |

**Pages already under 50 ms.** The filter adds about 2–11 ms. Each request
now also declares its principal (one more statement), and each view checks
the grant table for every row it returns.

**Unsliced notAfter pages.** These read the whole authority, and the per-row
grant check adds 5–38%. The worst is notAfter medium on the active
authority, from 314 to 432 ms. It is a single run; on the stopped authority
the same case went from 303 to 351 ms.

## Concurrent readers (60 s each, the load mix)

| Fixture | Readers | 0019: pages/s | 0019: failed | 0020: pages/s | 0020: failed |
| --- | ---: | ---: | ---: | ---: | ---: |
| active | 1 | 13.2 | 0% | 11.6 | 0% |
| active | 10 | 22.9 | 6% | 21.9 | 6% |
| active | 50 | 50.5 | 18% | 48.3 | 18% |
| stopped | 1 | 13.4 | 0% | 11.9 | 0% |
| stopped | 10 | 23.2 | 6% | 22.1 | 6% |
| stopped | 50 | 51.2 | 17% | 48.9 | 18% |

Throughput drops by about 4–12%, and the share of failed pages under load
is unchanged.

## Limits

- One run per configuration, on one machine with warm caches.
- The fixtures' reader principal holds 9 grants. A principal with many
  grants makes the grant check larger, but it stays an index lookup on the
  grant table's primary key `(issuer, subject, ca_id)`.
