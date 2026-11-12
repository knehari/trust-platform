# ADR-0038 — Operational metrics from the background worker

**Status:** Proposed · 2026-11-12. It is not accepted; acceptance needs the
owner's decision and an independent security review (AGENTS.md). It is the
review's P1 item "observability". AGENTS.md also asks for "métriques
d'expiration, erreurs de signature, retards de publication et opérations à
réconcilier".

**Scope:**
- migration 0045: `operational_metrics_lab()`, for the worker's role only;
- the worker's task loops, counters and `GET /metrics` listener;
- the laboratory compose service and CI check;
- tests.

**Out of scope:**
- alerting rules and dashboards;
- a metrics server and log shipping;
- tracing;
- metrics from the API's request path and the signer's process.

## Context

The platform reported its state only through:
- log lines (`crl_auto_renewal`, `audit_checkpoint` and so on);
- the console's per-CA views;
- the independent audit tools.

Nothing could be watched continuously. Nothing would page an operator when:
- a CRL nears its nextUpdate;
- issuance or CRL signing awaits reconciliation;
- a renewal keeps failing;
- the audit chain stops being sealed or checkpointed.

## Decision

1. **The database computes aggregates, for the worker only.**
   `operational_metrics_lab()` (SECURITY DEFINER, EXECUTE granted only to
   `trust_worker`) returns rows of (metric, CA identifier or none, number):

   | Metric | What it counts |
   | --- | --- |
   | `certificates_valid` | certificates in force (not expired, not revoked), per CA |
   | `certificates_expiring_30d` | of those, the ones expiring within 30 days, per CA |
   | `issuance_reconciliation_required` | certificate signing outcomes awaiting reconciliation; a confirmed void resolves one |
   | `issuance_unconfirmed_stale` | signing intents unconfirmed for more than 5 minutes |
   | `crl_reconciliation_required` | CRL signing outcomes awaiting reconciliation |
   | `crl_next_update_seconds` | seconds until the latest CRL's nextUpdate, negative once expired |
   | `crl_unpublished_entries` | revocations not yet in a published CRL |
   | `audit_unsealed_events` | committed audit events not yet sealed |
   | `audit_chain_head_seq` | the head of the audit chain |
   | `audit_checkpoint_age_seconds` | time since the latest signed checkpoint |

   The function returns no certificate, subject, actor or request.
2. **The worker adds its own counters:**
   - passes of each task (`audit_seal`, `crl_renewal`, `audit_checkpoint`),
     successful or failed;
   - the time of each task's last success;
   - CRL renewal outcomes;
   - checkpoint outcomes, including the signer's refusals;
   - the number of events sealed.

   The task loops moved from the API modules into the worker, which counts
   them.
3. **Exposition.**
   - With `TRUST_WORKER_METRICS_BIND`, the worker serves `GET /metrics` in
     the Prometheus text format, version 0.0.4, and nothing else.
   - Each scrape reads the database once, bounded to 5 seconds, through the
     worker's two connection slots.
   - If the database does not answer, `trust_metrics_database_up` is 0. The
     database metrics are then absent rather than stale, and the worker's
     counters remain.
   - Metric names come from a fixed list. The only label value taken from
     the database is a CA identifier, which must be a canonical UUID.
     Anything else is dropped, so a row cannot inject lines.
4. **Laboratory.** The compose `worker` binds `0.0.0.0:9464` inside its
   container, published only on host loopback (`127.0.0.1:9464`).

## Alternatives considered

- **Metrics on the API.** That would add an unauthenticated endpoint to the
  management plane, or tie scraping to OIDC. ADR-0030 removed the API's
  last anonymous route; the worker already has the right login and no
  listener of its own.
- **A Prometheus client library.** It would add dependencies for a few
  counters and gauges. The text format is small, and the module renders it
  with a unit-tested, fixed set of families.
- **Exporting from the database (a PostgreSQL exporter with SQL queries).**
  That would give another process read access to the tables. The function
  keeps the reads behind one grant to the worker's role.

## Consequences and open risks

- **Plain HTTP, no authentication.** Anyone who can reach the port reads the
  counts and the CA identifiers. In the lab the port is on host loopback
  only. A deployment must keep it on a private network or put TLS and
  authentication in front.
- **Per-process counters.** The counters restart from zero with the worker.
  Prometheus `rate()` and `increase()` handle resets.
- **Scrape cost.** Each scrape runs the aggregate query, so the scrape
  interval bounds the load. `certificates_*` scans the certificate table;
  that is fine in the lab, but a large inventory would need an index or a
  materialized summary.
- **No alerting is defined yet.** Natural first alerts:
  - `crl_next_update_seconds` < 2 days;
  - any `*_reconciliation_required` > 0;
  - `trust_worker_task_last_success_timestamp_seconds` older than three
    intervals;
  - `audit_checkpoint_age_seconds` beyond its interval;
  - `trust_metrics_database_up == 0`.

## Tests

- `tests/management_operational_metrics.sql` (new):
  - the reader, writer, signer and publisher roles are refused;
  - the result has exactly three columns (text, text, double precision);
  - on a fixture, the per-CA values are exact: expiring, expired and
    revoked certificates; an ambiguous issuance; a stale and a recent
    unconfirmed intent;
  - a new audit event counts as unsealed;
  - no NULL or NaN values.
- `management_dedicated_worker.sql`: the worker role's exact function list
  now includes the two new functions.
- `worker_metrics` unit tests:
  - known families are rendered, with their types;
  - unknown metric names and non-UUID labels are dropped (an injection
    attempt);
  - output without the database;
  - non-finite values.
- The API HTTP test (67 tests): the worker login's metrics include the CA's
  `crl_next_update_seconds` and the audit gauges; with the writer's login,
  `trust_metrics_database_up` is 0 and no database metric appears.
- CI compose job, and locally with the full stack after
  `scripts/lab/up.sh --reset --demo`:
  - `/metrics` has the database up, the issuing CA's CRL and certificate
    gauges, a published renewal and a successful sealing pass;
  - `/` is refused.

  The local run also showed one `REFUSED` checkpoint, from before the
  audit key ceremony, as expected.
