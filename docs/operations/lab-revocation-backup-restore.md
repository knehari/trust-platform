# Laboratory revocation database restore rehearsal

Lab only. `tests/revocation_backup_restore.sh` takes a logical backup
(`pg_dump --format=custom`) of a **populated** revocation database and
restores it into an empty database. It then checks that the restore kept
what the store's guarantees depend on. It runs in the Rust schema CI job
right after `signed_status_change_postgres` and `signed_evidence_audit_all.sh`.
At that point the database holds signed evidence for several CAs (some of it
deliberately altered), credentials, CRLs and audit history.

This is not a disaster recovery procedure. CA keys, the external checkpoint
file and the CRL distribution point live outside the database. RTO and RPO
are neither specified nor measured.

## Running it

Use PostgreSQL 16 client tools, a superuser URL for the source, and an
**empty** target database in the **same cluster**:

```sh
TRUST_CI_DATABASE_URL="$POPULATED_DATABASE_URL" \
TRUST_RESTORE_TARGET_URL="$EMPTY_TARGET_DATABASE_URL" \
  bash tests/revocation_backup_restore.sh
```

The script refuses a target with the same database name as the source, a
target that is not empty, and a source without signed evidence. The archive
lives in a temporary directory with owner-only permissions and is removed at
exit. `pg_restore` runs in one transaction with `--exit-on-error` and keeps
owners and ACLs. Those matter here: the `SECURITY DEFINER` functions run as
their NOLOGIN owner roles, and each capability role holds only its own
grants. The roles are cluster-global, so they must already exist on the
target cluster.

## What it checks

1. **Before the backup:**
   - the audit chain is sealed;
   - a checkpoint is exported to a file outside the database;
   - `signed_evidence_audit --all` is recorded (exit 3, because altered
     evidence is present).
2. **Structure and rows.**
   `tests/revocation_restore_fingerprint.sql` produces one sorted line per
   item, and the source and restored outputs must be identical. It covers:
   - every public table (row count and digest of its sorted rows);
   - every sequence position;
   - the owner, effective ACL and row-level security flags of every relation;
   - the owner, `SECURITY DEFINER` flag, settings (`search_path`), effective
     ACL and body digest of every public function;
   - every trigger with its enabled state (`ENABLE ALWAYS` included);
   - both event triggers;
   - the row-level security policies.
3. **Privileges:** `tests/revocation_privileges.sql` passes on the restored
   database.
4. **No schema changes from the restore itself:**
   `unreviewed_schema_changes()` is the same before and after.
5. **Evidence:** `signed_evidence_audit --all` on the restored database has
   the same exit status and the same output as on the source.
6. **Audit chain:**
   - The restored chain verifies against the checkpoint taken before the
     backup.
   - The source then records and seals a new event and exports a second
     checkpoint. Against that later checkpoint, the restored database (now a
     stale backup) is refused as `Truncated` (exit 3). Restoring an old
     backup would silently lose records, and that includes revocations.
     The external checkpoint is what exposes it.
7. **Working store:** the restored database seals a new record and extends
   its own checkpoint.

## Evidence that it detects a bad restore

The checks were mutated without changing the script, by substituting
the client tools with `TRUST_PG_RESTORE_BIN` or `TRUST_PG_DUMP_BIN`. Each
mutation fails with
`restored database differs from the source`:

| Mutation | What it loses |
| --- | --- |
| `pg_restore --no-owner` | Owners: definer functions and tables owned by the restoring superuser |
| `pg_restore --no-acl` | Grants, and the revocations of the default PUBLIC EXECUTE |
| `pg_dump --exclude-table-data=breakglass_review` | Rows of one evidence table |

The stale-backup refusal is part of the normal run: the script expects
exit 3.

## Limits

- Same cluster only. Restoring into a fresh cluster needs the trust roles
  and logins first (`pg_dumpall --globals-only` or the role migrations).
  That is not exercised for the revocation schema. The management schema
  rehearsal covers it for its reader role
  (`docs/operations/lab-management-backup-restore.md`).
- Not covered:
  - point-in-time recovery, or a backup taken under concurrent signing;
  - encryption, off-site retention or custody of the archive;
  - restoring the checkpoint file itself (it must be kept apart from the
    database backup, or a matching rollback of both goes undetected);
  - the CRL distribution point's cached CRLs.
- After a restore from an older backup, everything recorded after the
  backup is gone, revocations included: a certificate revoked since then
  would be listed as good again, and the next CRL would reuse a number
  already published. The external checkpoint detects the rollback. There
  is no tool yet to set a CRL number floor or to re-apply revocations from
  the last published CRL, and no runbook.
- RTO and RPO need a human-designed recovery exercise.
