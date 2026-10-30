# Laboratory management migration ledger

`lab_migrate_management` applies only management migrations 0012 and 0013 to a PostgreSQL 16 database that already has 0001–0011. It is a laboratory operator tool, not the Compose bootstrap or a production migration service. Run it as the migration owner against a disposable database:

```sh
cargo build -p trust-management-api --bin lab_migrate_management --locked
TRUST_MIGRATION_DATABASE_URL='postgresql://operator:password@127.0.0.1:5432/lab_db' \
  target/debug/lab_migrate_management
```

Use a protected credential source outside the repository for real environments. This binary uses PostgreSQL `NoTls`; the example assumes loopback laboratory transport. The operator must own the schema and have permission to create the management views/table and grant `SELECT` to the pre-provisioned `trust_api_reader` role. The API reader does not need, and is not granted, access to the ledger.

The runner takes a PostgreSQL session advisory lock so two copies serialize. It verifies a SHA-256 digest of each embedded migration source, executes the SQL body and inserts its ledger record in one transaction per migration. It removes only the audited outer `BEGIN`/`COMMIT` lines from those files; the historical SQL files remain unchanged. A second run skips matching recorded migrations. A failed 0013 rolls back 0013 and its ledger row while preserving committed 0012; retry can then complete 0013. It refuses checksum drift, missing recorded relations and management relations with no matching ledger entry. Existing databases that ran 0012–0013 outside this runner require a separately reviewed manual adoption procedure; the tool will not infer success from schema presence.

`tests/management_migration_ledger.sh` exercises concurrent runs, idempotence, checksum and schema drift, failed 0013 recovery and refusal of an untracked database. `tests/management_ledger_restore.sh` checks that a logical restore retains the ledger and a subsequent runner invocation skips both migrations. Both use disposable databases only. The ledger records application, not the full SQL definition or integrity of every object. The database owner can modify both schema and ledger; this is not a tamper-evident audit log, automatic rollback, online upgrade, protected backup, or production readiness proof.
