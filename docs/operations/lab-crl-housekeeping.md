# Laboratory CRL housekeeping

Lab only. `crates/management-api/src/bin/crl_housekeeping.rs` runs one housekeeping
pass for one CA (ADR-0006 section D, proposed). It calls
`PgRevocationStore::crl_housekeeping`, which:

1. retires `RESERVED` CRL numbers older than `--reserved-older-than` seconds
   (`abandon_stale_crl_reservations`, migration 0016). Such rows never
   recorded an intent, so they were never signed. Their numbers stay taken.
2. quarantines `INTENT_RECORDED` rows older than `--intent-older-than` seconds
   (`quarantine_stale_crl_intents`) as `RECONCILIATION_REQUIRED`. A signature
   may exist for them; see `reconcile_crl` (migration 0021) when the DER is
   still held.
3. reports `crl_due` and the number of `overdue_status_changes`, overdue
   precautionary holds, and break-glass uses not yet reviewed by two admins
   (`open_breakglass_uses`, `overdue_breakglass_uses`, migration 0045). Any
   of them sets the attention exit status.
4. purges the CA's challenges that expired unused more than 30 days ago
   (`purge_expired_challenges`, migration 0053; `purged_challenges`). Consumed
   challenges are evidence and are never deleted.
5. reports CA-admin proposals past `admin_proposal_max_age_hours`
   (`stale_admin_proposals`, migration 0054). They can no longer be approved;
   an admin rejects them (and proposes again if still wanted). Any of them
   sets the attention exit status.
6. backfills `not_after` for certificates stored before migration 0031
   (`backfilled_not_after`, migration 0055), read from each stored DER after
   checking its serial, so expired-entry pruning can cover them. A stored
   DER that does not parse or names another serial is counted in
   `unreadable_certificates`, never guessed, and sets the attention status.

It also reads the database clock between two readings of the host clock
(`clock_skew_us`, `clock_uncertainty_us`, `clock_ok`) and alerts when
|skew| + uncertainty exceeds 2 s (ADR-0006 condition 6). The same bound
makes `PgRevocationStore::reserve_crl` refuse a reservation whose thisUpdate
disagrees with the host clock (`ClockSkew`, nothing signed). Both hosts
still need authenticated time (NTS) of their own.

The job then reports `unreviewed_schema_changes` (migration 0026,
database-wide): DDL and object grants recorded by the schema-change event
triggers after the last `acknowledge_schema_changes` call. Each reviewed
migration ends with that call, so any other count means someone changed the
schema outside a reviewed migration. Investigate with a superuser:

```
SELECT * FROM schema_change_audit
WHERE change_seq > (SELECT coalesce(max(reviewed_up_to), 0) FROM schema_change_review);
```

It also reports `unreviewed_role_changes` (migration 0057): how many lines
of the security-relevant role state (trust_* roles and their members,
SUPERUSER/CREATEROLE/BYPASSRLS/REPLICATION holders) differ from the last
snapshot a superuser acknowledged. Roles are cluster-wide, so a change made
from any database counts. Compare and acknowledge after review:

```
SELECT unnest(role_state())
EXCEPT SELECT unnest(state) FROM role_state_review ORDER BY 1;  -- added lines
SELECT acknowledge_role_state('reviewed: <ticket>');
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
  cargo run -p trust-management-api --bin crl_housekeeping -- <ca-uuid>|--all
```

With `--all` the job covers every CA with a registered issuer certificate
(`crl_issuing_cas()`, migration 0033, operator only), so no CA can be
forgotten in a hand-kept list. A CA that fails is reported on stderr and
the others still run.

Exit status:
- 0: nothing to do;
- 2: attention needed (something was retired or quarantined, a CRL is due,
  a change is overdue, a precautionary hold is past its confirmation
  deadline (`overdue_precautionary_holds`, migration 0036), a schema change
  is unreviewed, or the clocks disagree);
- 1: error on any CA (an error outranks an alert).

A scheduler (cron, systemd timer) can therefore alert on any non-zero status.
For example, an hourly cron line can call a wrapper script that runs the
command above and mails its output when it exits non-zero.

The connection follows the management API's policy: TLS 1.3, verified
against `TRUST_DATABASE_CA_FILE` (certificate and host name), by default.
Plaintext only with the explicit lab opt-out `TRUST_DATABASE_TLS=disable-lab`,
reported on stderr; `tests/management_db_tls.sh` covers this. The job
authenticates nobody and holds no key. It refuses a privileged login
(`from_service_client`): use a login granted only `trust_crl_operator`
(migration 0023).
Covered by `housekeeping_reports_and_cleans_up` and
`unreviewed_schema_changes_reach_the_operator` in
`crates/pki-core/tests/revocation_crl_postgres.rs`, and by
`tests/schema_change_audit.sql`.
