# Disposable laboratory stack

This Compose stack runs only the read-only management slice: PostgreSQL 16, ordered migrations and two example CAs, the restricted Rust API, a React/Vite console, a loopback test OIDC issuer, and the scheduled lab database jobs. It does **not** run CA issuance, software signing or a real IAM service. The generated database passwords stay in ignored `.env.lab`; the script preserves an existing file rather than replacing credentials underneath a running volume.

From the repository root, with Docker Compose, OpenSSL and a free local 8080/8081/5173:

```sh
scripts/lab/init-env.sh
docker compose --env-file .env.lab -f compose.lab.yaml config --quiet
docker compose --env-file .env.lab -f compose.lab.yaml up -d --build --wait
node frontend/dev/compose-smoke.mjs
```

### Scheduled database jobs

The `jobs` service (`Dockerfile.jobs`, `scripts/lab/jobs.sh`) runs every
`TRUST_LAB_JOBS_INTERVAL_SECONDS` (default 300, 10 to 86400). Each job uses
its own login, created by `scripts/lab/init-db.sh` with a password from
`.env.lab`:

| Job | Login | Role |
| --- | --- | --- |
| `crl_housekeeping --all` | `trust_housekeeping_lab` | `trust_crl_operator` |
| `audit_chain_anchor seal` | `trust_sealer_lab` | `trust_audit_sealer` |
| `audit_chain_anchor verify` | `trust_auditor_lab` | `trust_audit_verifier` |
| `signed_evidence_audit --all` | `trust_auditor_lab` | `trust_audit_verifier` |

None of them is a superuser or an owner member, and the jobs refuse such
logins. The audit chain checkpoints go to the `trust_lab_checkpoints` volume,
outside the database but on the same host. That makes it a lab stand-in,
not an independent anchor.

Each job prints `job=<name> exit=<status>`: 0 means nothing to report, 2 an
alert (housekeeping, unsealed records), 3 evidence or chain that does not
verify, 1 an error. A failing job does not stop the others. Nothing pages
anyone: read the logs with
`docker compose --env-file .env.lab -f compose.lab.yaml logs jobs`. The
container is healthy while its last round finished within three intervals.

`init-db.sh` acknowledges the lab role provisioning
(`acknowledge_role_state('lab-init')`, migration 0057). On a fresh volume,
housekeeping therefore reports `unreviewed_role_changes=0` and only alerts
on later role changes; without that acknowledgement it exited 2 from the
first round. `init-env.sh` adds missing passwords to an existing `.env.lab`
without touching the others. The new logins only exist on a volume created
after that, so reset the lab volume (below).

Open `http://127.0.0.1:5173/` to inspect the UI. The test issuer automatically approves a fixed laboratory operator and one of the two seeded CAs. The second CA must remain absent from the list and return 403 by direct API request. All published ports bind host loopback. The API shares the issuer's container network namespace so both browser and API can use the exact OIDC issuer `http://127.0.0.1:8080`; the frontend development proxy targets the shared namespace at `issuer:8081`.

Stop while retaining the disposable database:

```sh
docker compose --env-file .env.lab -f compose.lab.yaml down
```

Bring an existing volume up to this checkout's migrations, keeping its data:

```sh
docker compose --env-file .env.lab -f compose.lab.yaml exec -T db sh /lab/migrate.sh
```

On a volume created before migration 0064, or by the entrypoint, the first
run refuses until the operator adopts the digests of the applied files
(`sh /lab/migrate.sh --adopt`, see below).

`scripts/lab/migrate.sh` reads which migrations are applied from
`schema_change_review`: since 0026, each migration records its file name
there. It applies only the missing ones, in order, one transaction per file,
and stops at the first failure. It refuses:
- a database that predates 0026;
- a database that records a migration newer than this checkout;
- a gap in the sequence;
- a login that is not a superuser;
- a migration file that differs from the one applied, or that was applied
  and is missing here. Since 0064, `migration_file_digest` (append-only)
  keeps the SHA-256 of every applied file;
- applied files without a recorded digest, unless `--adopt` is given. The
  entrypoint and runs before 0064 kept none. With `--adopt` the operator
  states that this checkout holds the files that were applied; their
  digests are taken from it and recorded as `adopted` (trust on first use:
  an edit made before adoption goes unnoticed). The runner never adopts on
  its own, like the historical management ledger, which does not infer
  applied migrations from the schema.

The runner records the digest of each file it applies (`applied`). A run that
fails leaves the files it applied without a digest, so the next run needs
`--adopt`. One runner works on a database at a time: it holds a session
advisory lock until it exits, and a second runner is refused while the lock
is held. It does
not add the job logins of `init-db.sh` to an older volume; reset the volume
for those. Tested by `tests/revocation_migration_runner.sh`, and in the
`laboratory-compose` job, which runs it on the fresh volume: it must refuse
without `--adopt`, adopt with it, then report `up to date`.

Reset **only this laboratory stack** after a seed change, or for a volume the
runner refuses:

```sh
docker compose --env-file .env.lab -f compose.lab.yaml down -v --remove-orphans
docker compose --env-file .env.lab -f compose.lab.yaml up -d --build --wait
```

PostgreSQL's entrypoint runs every migration in `migrations/` (`0001`–`0065`) and seed data only when its volume is first created; startup fails on a migration error. The seed grants the fixture operator access to one CA; a grant for the same subject under a different issuer does not authorize the hidden CA. This is a disposable bootstrap, not an online migration/rollback system; the runner above upgrades an existing volume, without rollback. Plaintext PostgreSQL transport (`TRUST_DATABASE_TLS=disable-lab`, logged at API startup) is confined to the Compose network, and the OIDC fixture has no human authentication. Production transport, credential management, CA key custody, policy-controlled issuance, independent review and G0 remain separate gates.

The Rust schema CI also runs `tests/management_populated_upgrade.sh` against a separate empty PostgreSQL database. It seeds data after migration 0011, applies 0012–0013 and checks row preservation and reader privileges. This is an upgrade regression for those two migrations only; it does not upgrade an existing Compose volume or provide a repeatable production migration runner.

`tests/revocation_populated_upgrade.sh` does the same for 0014–0015 in another empty database. Both migrations fail closed on rows they cannot carry forward and roll back entirely: 0014 aborts on a legacy `revocation` row with reason 7 or 8, and 0015 aborts on any pre-existing `crl_publication` row (it has no operation reference, intent, DER or entry snapshot). 0016 likewise aborts on a revocation date outside 1970-01-01 .. 9999-12-31. The script checks that each abort leaves no object of that migration behind, that each migration applies once the operator has removed the offending row, and that a legacy revocation stays irreversible, reports `REVOKED` and is frozen into the first CRL reservation with the canonical entry digest. There is no automatic conversion of legacy CRL rows.

A second disposable database exercises [interrupted migration 0013 and manual retry](../operations/lab-management-migration-retry.md), checking that 0012 and existing rows survive a failed 0013 transaction before retry. That historical test uses direct SQL and has no ledger.

The [laboratory management migration ledger](../operations/lab-management-migration-ledger.md) adds a separate operator runner for 0012–0013 and tests concurrent application, repeat runs, source drift and interruption on disposable databases. Compose still bootstraps its own empty volume with the historical SQL files.

A later schema CI step [restores that populated fixture](../operations/lab-management-backup-restore.md) into another empty disposable database and checks row equality and restricted reader privileges. It does not back up this Compose volume or any CA key material.

CI also starts a second disposable PostgreSQL 16 cluster to verify that a missing global reader role stops restoration before any write, then provisions that role and repeats the same data and privilege checks across clusters.
It separately provisions a temporary API login in that cluster and verifies view-only access through the login before grant, during grant and after revocation.

The schema job also injects a mid-restore DDL error in a third disposable database. The restore transaction must roll back all created relations, after which an unmodified retry must pass. This tests SQL restore failure handling, not recovery of the Compose volume or signer state.

The `laboratory-compose` GitHub Actions job builds the images and runs the same scoped smoke on a disposable runner. [Run 39059362985](https://github.com/knehari/trust-platform/actions/runs/39059362985) passed on Draft #53's exact head. Local Docker execution must be recorded separately from CI; a successful `docker compose config` or local PostgreSQL script alone does not establish that the containers start.
