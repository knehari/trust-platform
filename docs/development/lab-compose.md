# Disposable laboratory stack

This Compose stack runs only the read-only management slice: PostgreSQL 16, ordered migrations and two example CAs, the restricted Rust API, a React/Vite console and a loopback test OIDC issuer. It does **not** run CA issuance, software signing or a real IAM service. The generated database passwords stay in ignored `.env.lab`; the script preserves an existing file rather than replacing credentials underneath a running volume.

From the repository root, with Docker Compose, OpenSSL and a free local 8080/8081/5173:

```sh
scripts/lab/init-env.sh
docker compose --env-file .env.lab -f compose.lab.yaml config --quiet
docker compose --env-file .env.lab -f compose.lab.yaml up -d --build --wait
node frontend/dev/compose-smoke.mjs
```

Open `http://127.0.0.1:5173/` to inspect the UI. The test issuer automatically approves a fixed laboratory operator and one of the two seeded CAs. Each CA has one synthetic certificate metadata record and one synthetic audit event; only the allowed CA's records may appear. The certificate DER seed is a schema sentinel, not a valid signed X.509 certificate. The second CA must remain absent from the list and return 403 by direct API request. The smoke checks list and detail routes, 400/403/404 responses, absence of certificate DER and actor IDs, and `no-store` on detail responses. All published ports bind host loopback. The API shares the issuer's container network namespace so both browser and API can use the exact OIDC issuer `http://127.0.0.1:8080`; the frontend development proxy targets the shared namespace at `issuer:8081`.

Stop while retaining the disposable database:

```sh
docker compose --env-file .env.lab -f compose.lab.yaml down
```

Reset **only this laboratory stack** after a migration or seed change:

```sh
docker compose --env-file .env.lab -f compose.lab.yaml down -v --remove-orphans
docker compose --env-file .env.lab -f compose.lab.yaml up -d --build --wait
```

PostgreSQL's entrypoint runs migrations `0001`–`0013` and seed data only when its volume is first created; startup fails on a migration error. The seed grants the fixture operator access to one CA; a grant for the same subject under a different issuer does not authorize the hidden CA. This is a disposable bootstrap, not an online migration/rollback system. `NoTls` PostgreSQL transport is confined to the Compose network, and the OIDC fixture has no human authentication. Production transport, credential management, CA key custody, policy-controlled issuance, independent review and G0 remain separate gates.

The Rust schema CI also runs `tests/management_populated_upgrade.sh` against a separate empty PostgreSQL database. It seeds data after migration 0011, applies 0012–0013 and checks row preservation and reader privileges. This is an upgrade regression for those two migrations only; it does not upgrade an existing Compose volume or provide a repeatable production migration runner.

A second disposable database exercises [interrupted migration 0013 and manual retry](../operations/lab-management-migration-retry.md), checking that 0012 and existing rows survive a failed 0013 transaction before retry. That historical test uses direct SQL and has no ledger.

The [laboratory management migration ledger](../operations/lab-management-migration-ledger.md) adds a separate operator runner for 0012–0013 and tests concurrent application, repeat runs, source drift and interruption on disposable databases. Compose still bootstraps its own empty volume with the historical SQL files.

A later schema CI step [restores that populated fixture](../operations/lab-management-backup-restore.md) into another empty disposable database and checks row equality and restricted reader privileges. It does not back up this Compose volume or any CA key material.

CI also starts a second disposable PostgreSQL 16 cluster to verify that a missing global reader role stops restoration before any write, then provisions that role and repeats the same data and privilege checks across clusters.
It separately provisions a temporary API login in that cluster and verifies view-only access through the login before grant, during grant and after revocation.

The schema job also injects a mid-restore DDL error in a third disposable database. The restore transaction must roll back all created relations, after which an unmodified retry must pass. This tests SQL restore failure handling, not recovery of the Compose volume or signer state.

The `laboratory-compose` GitHub Actions job builds the images and runs the same scoped smoke on a disposable runner. [Run 39059362985](https://github.com/knehari/trust-platform/actions/runs/39059362985) passed on Draft #53's exact head. Local Docker execution must be recorded separately from CI; a successful `docker compose config` or local PostgreSQL script alone does not establish that the containers start.
