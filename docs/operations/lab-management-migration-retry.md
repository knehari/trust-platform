# Interrupted management migration rehearsal

`tests/management_migration_retry.sh` exercises the existing 0012 and 0013
SQL files on a new, disposable PostgreSQL 16 database. It applies 0001–0011,
inserts the populated fixture, then commits 0012. An event trigger deliberately
fails 0013 after its reader-grant table has been created but before the
migration's `COMMIT`.

The test requires the 0012 management view and all five original fixture
tables to remain, while the 0013 table and view are absent. It compares an
all-row fingerprint before and after the failure, removes the fault, applies
the **unchanged** 0013 file again, and checks the original rows, management
views and restricted reader privileges. Run from the repository root against
an empty database owned by the laboratory migration operator:

```sh
TRUST_UPGRADE_DATABASE_URL="$EMPTY_DISPOSABLE_DATABASE_URL" \
  bash tests/management_migration_retry.sh
```

This proves transactional rollback and manual retry for **0013 only** under
the injected failure. It does not authorize rerunning 0013 after a successful
commit: the migration is not idempotent. There is no applied-migration ledger,
checksum verification, concurrent migration lock, deployed-data upgrade,
online migration procedure or operational rollback. An operator must inspect
the database state before any real recovery; those missing controls require a
separate migration runner and review.
