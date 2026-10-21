# Laboratory CRL housekeeping

Lab only. `crates/pki-core/examples/crl_housekeeping.rs` runs one housekeeping
pass for one CA (ADR-0006 section D, proposed). It calls
`PgRevocationStore::crl_housekeeping`, which:

1. retires `RESERVED` CRL numbers older than `--reserved-older-than` seconds
   (`abandon_stale_crl_reservations`, migration 0016). Such rows never
   recorded an intent, so they were never signed. Their numbers stay taken.
2. quarantines `INTENT_RECORDED` rows older than `--intent-older-than` seconds
   (`quarantine_stale_crl_intents`) as `RECONCILIATION_REQUIRED`. A signature
   may exist for them; see `reconcile_crl` (migration 0021) when the DER is
   still held.
3. reports `crl_due` and the number of `overdue_status_changes`.

It also reads the database clock between two readings of the host clock
(`clock_skew_us`, `clock_uncertainty_us`, `clock_ok`) and alerts when
|skew| + uncertainty exceeds 2 s (ADR-0006 condition 6). The same bound
makes `PgRevocationStore::reserve_crl` refuse a reservation whose thisUpdate
disagrees with the host clock (`ClockSkew`, nothing signed). Both hosts
still need authenticated time (NTS) of their own.

The example then reports `unreviewed_schema_changes` (migration 0026,
database-wide): DDL and object grants recorded by the schema-change event
triggers after the last `acknowledge_schema_changes` call. Each reviewed
migration ends with that call, so any other count means someone changed the
schema outside a reviewed migration. Investigate with a superuser:

```
SELECT * FROM schema_change_audit
WHERE change_seq > (SELECT coalesce(max(reviewed_up_to), 0) FROM schema_change_review);
```

Acknowledge (as a superuser) only after the change was reviewed, naming the
review reference: `SELECT acknowledge_schema_changes('0026_manual_review_x');`.
Role changes are not in this audit; enable server logging (pgaudit, `ROLE`
class) for them.

Both thresholds default to 3600 seconds. Since 0017/0020 a stale or
superseded reservation can no longer be signed, so the sweep is for hygiene
and evidence. It is not what keeps old CRLs from being signed.

```
TRUST_DATABASE_URL=postgresql://... \
  cargo run -p trust-pki-core --features postgres-store --example crl_housekeeping -- <ca-uuid>|--all
```

With `--all` the job covers every CA with a registered issuer certificate
(`crl_issuing_cas()`, migration 0033, operator only), so no CA can be
forgotten in a hand-kept list. A CA that fails is reported on stderr and
the others still run.

Exit status:
- 0: nothing to do;
- 2: attention needed (something was retired or quarantined, a CRL is due,
  a change is overdue, a schema change is unreviewed, or the clocks
  disagree);
- 1: error on any CA (an error outranks an alert).

A scheduler (cron, systemd timer) can therefore alert on any non-zero status.
For example, an hourly cron line can call a wrapper script that runs the
command above and mails its output when it exits non-zero.

The connection uses the lab `NoTls` adapter. Run it only against a loopback
or private lab database. It authenticates nobody and holds no key. It
refuses a privileged login (`connect_lab_service`): use a login granted only
`trust_crl_operator` (migration 0023).
Covered by `housekeeping_reports_and_cleans_up` and
`unreviewed_schema_changes_reach_the_operator` in
`crates/pki-core/tests/revocation_crl_postgres.rs`, and by
`tests/schema_change_audit.sql`.
