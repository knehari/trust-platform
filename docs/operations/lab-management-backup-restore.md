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
Provision the `trust_api_reader` NOLOGIN role in the target cluster and create
a **separate, empty** target database owned by the test operator. The CI job
tests both same-cluster and fresh-cluster restoration. For a fresh cluster, it
first confirms that the missing role is rejected before the archive is made,
then provisions the role and restores. Run from the repository root:

```sh
TRUST_RESTORE_SOURCE_URL="$SOURCE_DATABASE_URL" \
TRUST_RESTORE_TARGET_URL="$EMPTY_TARGET_DATABASE_URL" \
  bash tests/management_dump_restore.sh
```

The script rejects identical database names, targets containing public
relations, and targets without the NOLOGIN reader role before writing. Use a
different target database name even when the clusters differ. It creates a
custom-format archive in a temporary directory with owner-only permissions,
restores SQL objects and rows in one transaction without changing object
ownership, and removes the archive at exit. CI injects a DDL failure after
earlier objects have been created; the failed transaction leaves the target
without restored relations, and a retry succeeds after removing the fault.
The successful path compares a digest of **all rows in the six
populated fixture tables** before and after restoration, then reruns the
negative `trust_api_reader` privilege fixture against the target. A second
run against the restored target must fail before `pg_restore` starts. Never
point the target URL at a database containing data to preserve.

When the source has a `management_migration_ledger`, the same restore test
also compares the complete ledger rows (including checksums and timestamps)
with the target. A separate CI fixture restores a database on which the
ledgered 0012–0013 runner has completed, then reruns that binary against the
restored target: both migrations must be skipped with matching checksums.
This confirms continuity of the laboratory migration record through this
logical restore. It does not validate an externally modified schema or make
the ledger tamper-evident.

In the fresh-cluster CI fixture, an independently provisioned test login is
also checked over a real PostgreSQL connection. It cannot read management
views before membership in `trust_api_reader`; with that membership it sees
the expected view rows but cannot read raw certificate or reader-grant tables
or update a CA. Revoking membership removes view access again. The test login
and its password exist only in the disposable CI cluster; the dump does not
restore application credentials.

## Scope and next gates

The digest is a regression comparison for this exact fixture, not an audit
integrity proof or a generic backup verifier. `pg_dump` does not include
cluster-global role definitions; the fresh-cluster exercise provisions the
NOLOGIN reader role separately. It does not test recovery of arbitrary global
roles or login credentials, backup encryption or off-site retention,
point-in-time recovery, online consistency with active issuance, rollback of
already-committed application changes, CA private keys/HSM state, or
signing-intent reconciliation. RTO and RPO are neither specified nor measured.
Those require a separately designed operational recovery exercise and human
review before any production claim.
