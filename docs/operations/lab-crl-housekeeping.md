# Laboratory CRL housekeeping

Lab only. `crates/pki-core/examples/crl_housekeeping.rs` runs one housekeeping
pass for one CA (ADR-0006 part C, proposed). It calls
`PgRevocationStore::crl_housekeeping`, which:

1. retires `RESERVED` CRL numbers older than `--reserved-older-than` seconds
   (`abandon_stale_crl_reservations`, migration 0016). Such rows never
   recorded an intent, so they were never signed. Their numbers stay taken.
2. quarantines `INTENT_RECORDED` rows older than `--intent-older-than` seconds
   (`quarantine_stale_crl_intents`) as `RECONCILIATION_REQUIRED`. A signature
   may exist for them; see `reconcile_crl` (migration 0021) when the DER is
   still held.
3. reports `crl_due` and the number of `overdue_status_changes`.

Both thresholds default to 3600 seconds. Since 0017/0020 a stale or
superseded reservation can no longer be signed, so the sweep is for hygiene
and evidence. It is not what keeps old CRLs from being signed.

```
TRUST_DATABASE_URL=postgresql://... \
  cargo run -p trust-pki-core --features postgres-store --example crl_housekeeping -- <ca-uuid>
```

Exit status:
- 0: nothing to do;
- 2: attention needed (something was retired or quarantined, a CRL is due,
  or a change is overdue);
- 1: error.

A scheduler (cron, systemd timer) can therefore alert on any non-zero status.
For example, an hourly cron line can call a wrapper script that runs the
command above and mails its output when it exits non-zero.

The connection uses the lab `NoTls` adapter. Run it only against a loopback
or private lab database. It authenticates nobody and holds no key. Under
ADR-0006 part A it would run as the EXECUTE-only `trust_crl_operator` role.
Covered by `housekeeping_reports_and_cleans_up` in
`crates/pki-core/tests/revocation_crl_postgres.rs`.
