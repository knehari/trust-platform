# Laboratory management database restore rehearsal

`tests/management_dump_restore.sh` exercises a logical PostgreSQL backup and
restore of the **disposable management fixture** created by
`tests/management_populated_upgrade.sh`. It runs in the Rust schema CI job and
can be repeated locally from the repository root. This exercise is scoped to
management database rows, schema, views and grants; it is not a CA or signer
recovery procedure.

## Prerequisites and execution

Use PostgreSQL 16 client tools (`psql`, `pg_dump`, `pg_restore`) and a disposable
cluster. Apply migrations 0001–0011, seed the fixture, and apply 0012–0013 by
running `management_populated_upgrade.sh` against an empty source database.
Provision the `trust_api_reader` role in the same cluster as the target and
create a **separate, empty** target database owned by the test operator. The
CI job provisions both databases and the role automatically. Run from the
repository root:

```sh
TRUST_RESTORE_SOURCE_URL="$SOURCE_DATABASE_URL" \
TRUST_RESTORE_TARGET_URL="$EMPTY_TARGET_DATABASE_URL" \
  bash tests/management_dump_restore.sh
```

The script rejects identical database names and targets containing public
relations. It creates a custom-format archive in a temporary directory with
owner-only permissions, restores without changing object ownership, and
removes the archive at exit. It compares a digest of **all rows in the six
populated fixture tables** before and after restoration, then reruns the
negative `trust_api_reader` privilege fixture against the target. A second
run against the restored target must fail before `pg_restore` starts. Never
point the target URL at a database containing data to preserve.

## Scope and next gates

The digest is a regression comparison for this exact fixture, not an audit
integrity proof or a generic backup verifier. `pg_dump` does not include
cluster-global role definitions; this same-cluster exercise relies on the
role already being provisioned. It does not test recovery on a fresh cluster,
backup encryption or off-site retention, point-in-time recovery, online
consistency with active issuance, rollback, CA private keys/HSM state, or
signing-intent reconciliation. RTO and RPO are neither specified nor measured.
Those require a separately designed operational recovery exercise and human
review before any production claim.
