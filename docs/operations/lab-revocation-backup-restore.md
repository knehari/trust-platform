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

## Restoring into a fresh cluster

`pg_dump` does not carry roles, and this schema depends on them. The NOLOGIN
owner roles own the `SECURITY DEFINER` functions, and each capability role
holds its grants. Part of the schema (core tables such as `ca`,
`certificate` and `audit_event`, about 50 functions, and the two
schema-change event triggers) is owned by the login that ran the
migrations. None of those functions is `SECURITY DEFINER`.
`tests/revocation_fresh_cluster_restore.sh` rehearses the restore into a
fresh PostgreSQL 16 cluster (a second container in CI):

1. It lists the roles the dump needs from the source catalog: owners of
   public objects and event triggers, and ACL grantees.
2. A restore without them must fail as a whole (`role ... does not
   exist`), and the target must stay empty.
3. Each missing role is created `NOLOGIN`, including one named after the
   migration login: ownership needs the name, not a login. No credential
   is copied. PostgreSQL requires an event trigger's owner to be a
   superuser, so the owner of the event triggers is created
   `NOLOGIN SUPERUSER`. The script checks that no other provisioned role
   can log in or is privileged.
4. `pg_restore --single-transaction --exit-on-error` runs with owners and
   ACLs. The fingerprint must then match the source (pgcrypto's functions
   are recreated by `CREATE EXTENSION` and owned by the restoring
   superuser, so they are compared as extension versions instead). The
   privilege invariants must pass, and `reserve_crl` must work under the
   restored definer owners.

Mutations: `TRUST_PG_RESTORE_BIN` wrappers adding `--no-owner` or
`--no-acl` both fail with `restored database differs from the source`.

Choosing which superuser owns the event triggers, and which login runs
future migrations, is an operator decision. In the rehearsal it is a
NOLOGIN role with the old login's name.

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

## After restoring an older backup: CRL number floor

The next CRL number is the CA's highest stored number plus one. After
restoring a backup older than the last published CRL, the next CRL would
reuse a number that relying parties already hold with other content
(RFC 5280 section 5.2.3 requires increasing numbers). Since migration 0058,
before any CRL is signed on the restored database, a superuser raises the
floor of each CA to the highest number known to be published (from the
distribution point or a relying party's copy):

```sql
SELECT raise_crl_number_floor('<ca>', <highest published number>,
                              'restore of <backup> on <date>');
```

`reserve_crl` then numbers above the floor. The floor only rises, is
append-only (`crl_number_floor`), and each raise writes a
`crl.number_floor.raised` audit event. No service role can call it.
Choosing the number is the operator's decision. A floor that is too low
does not prevent reuse, and the database cannot know the right number.
Tested by `tests/crl_number_floor.sql`, which simulates the rollback.

## After restoring an older backup: re-applying revocations

A database restored from a backup older than the last published CRL has
lost every status change made since. A certificate revoked since then reads
`VALID` again, and the next CRL would leave it out. Since migration 0060,
the last published CRL is used to put those revocations back. That CRL is
signed evidence of the decisions, and the operator takes it from the
distribution point or a relying party's copy. Run this **before** any new
CRL is signed on the restored database:

```sh
TRUST_DATABASE_URL=postgresql://<superuser>@db.lab.invalid/trust \
TRUST_DATABASE_CA_FILE=/etc/trust/db-ca.pem \
  cargo run -p trust-management-api --bin crl_restore_revocations -- \
  <ca-uuid> last-published.crl --reason "restore of <backup> on <date>"
```

How it works:

- The Rust core verifies the CRL against the CA's registered issuer
  certificate (`crl::published_crl_entries`): signature, canonical DER, a
  complete CRL, and only entry extensions it can represent. The database
  cannot check the signature, so `restore_revocations_from_crl` has no
  grant: the binary requires a superuser login and refuses any other.
- A CRL that is not newer than the database's latest stored complete CRL is
  refused. An old CRL would re-apply holds that were released since.
- The CRL bytes are kept in `crl_restore` (append-only). The CRL number
  floor is raised to the CRL's number (0058), and a
  `revocation.restored_from_crl` audit event records the counts.

It prints one line per certificate:

| Outcome | Meaning | Database change |
| --- | --- | --- |
| `RESTORED` | Not revoked here | Inserted with the CRL's date and reason (actor `crl-restore:<number>`, no status change record) |
| `UPGRADED` | On hold here, definitive on the CRL | Reason changed, original date kept |
| `PRESENT` | Same reason here | None |
| `CONFLICT` | Definitive here with another reason, or definitive here and on hold on the CRL | None: definitive revocations are irreversible |
| `UNKNOWN_CERTIFICATE` | Not in this database (issued after the backup) | None |
| `HOLD_NOT_ON_CRL` | On hold here, absent from the CRL (perhaps released since) | None: a release needs dual control |

The exit status is 0 when nothing is left to do, 2 when an operator must act
on at least one certificate, and 1 on an error (nothing changed).

Until a new CRL is signed, the distribution point serves the restored
database's latest stored CRL. That CRL is older than the one relying parties
already hold, so sign a new complete CRL right after the restore. It is
numbered above the restored one and lists the re-applied revocations.

Check `UNKNOWN_CERTIFICATE` with particular care. The database lost both the
certificate and its revocation, so no new CRL will list it, and it
disappears for relying parties. Recovering lost certificates is not
automated: it needs the issuance records from outside the database.

Tested by:

- `tests/crl_revocation_restore.sql`: every outcome, idempotence, evidence,
  audit, floor and grants;
- `revocations_lost_in_a_restore_are_reapplied_from_the_published_crl`
  (PostgreSQL, real lab signatures): a forged CRL is refused, and the next
  CRL lists the restored revocations and goes through the usual signing
  pipeline;
- `tests/crl_restore_revocations.sh`: the binary itself, with a service
  login and a forged CRL refused and exit status 2 for the unknown
  certificate.

## Limits

- Logins are not restored. Service logins (with their passwords or
  certificates) are created again in the new cluster and granted their
  capability roles.
- Not covered:
  - point-in-time recovery, or a backup taken under concurrent signing;
  - encryption, off-site retention or custody of the archive;
  - restoring the checkpoint file itself (it must be kept apart from the
    database backup, or a matching rollback of both goes undetected);
  - the CRL distribution point's cached CRLs.
- After a restore from an older backup, everything recorded after the
  backup is gone. The external checkpoint detects the rollback, and the
  revocations can be re-applied from the last published CRL (above).
  Changes not on any published CRL are lost: status changes after that CRL,
  rejected or withdrawn proposals, signed evidence and audit events. So are
  certificates issued after the backup. Delta CRLs are not used for the
  restore.
- `tests/crl_restore_rehearsal.sh` runs the restore tool on a database
  restored by `pg_restore` from a dump taken before the published CRL. The
  loss is still staged: that CRL is signed by the test, not by a CA that
  went on running after the dump. Same cluster only, as above.
- RTO and RPO need a human-designed recovery exercise.
