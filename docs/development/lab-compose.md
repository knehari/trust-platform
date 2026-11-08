# Disposable laboratory stack

This Compose stack runs only the read-only management slice: PostgreSQL 16, ordered migrations and two example CAs, the restricted Rust API, a React/Vite console and a laboratory Keycloak identity provider ([ADR-0009](../adr/ADR-0009-laboratory-identity-provider.md), Proposed) with a real login form. It does **not** run CA issuance, software signing or a production IAM service: Keycloak runs in development mode on loopback HTTP with an in-container store, and has no multi-factor authentication. The generated database passwords, Keycloak administrator password, workload secret and per-user passwords stay in ignored `.env.lab`. The script never replaces an existing value, so credentials are not rotated underneath a running volume; it appends values missing from an older file.

From the repository root, with Docker Compose, OpenSSL and a free local 8080/8081/5173:

```sh
scripts/lab/init-env.sh
docker compose --env-file .env.lab -f compose.lab.yaml config --quiet
docker compose --env-file .env.lab -f compose.lab.yaml up -d --build --wait
node frontend/dev/check-api-compat.mjs
set -a; . ./.env.lab; set +a
node frontend/dev/compose-smoke.mjs
node frontend/dev/iam-negative.mjs
node frontend/dev/profile-lifecycle-e2e.mjs   # signs decisions with .lab-keys/
```

### Signing in

Open `http://127.0.0.1:5173/`, choose **Sign in with your organization** and sign in on the Keycloak page with one of these laboratory accounts. Each password is the matching value in your own `.env.lab` (for example `grep TRUST_LAB_PW_READER .env.lab`).

| User | Password variable | Roles | Expected in the console |
| --- | --- | --- | --- |
| `lab-reader` | `TRUST_LAB_PW_READER` | `trust-ca-reader` | the allowed CA and its records only |
| `lab-approver-1`, `lab-approver-2` | `TRUST_LAB_PW_APPROVER_1`, `_2` | reader + `trust-policy-approver`, with an approver grant and a registered key | as `lab-reader`, and can **approve or reject** a SUBMITTED revision by signing its claim (see below) |
| `lab-operator` | `TRUST_LAB_PW_OPERATOR` | reader + `trust-ca-operator`, with an operator grant | as `lab-reader`, and can **activate** an APPROVED revision and **retire** the ACTIVE one |
| `lab-author` | `TRUST_LAB_PW_AUTHOR` | reader + `trust-profile-editor`, with an editor grant | as `lab-reader`, and can **propose a revision** and **submit it for approval** in Profile proposals |
| `lab-ca-admin` | `TRUST_LAB_PW_CA_ADMIN` | `trust-ca-administrator` only, with a platform grant | no CA (the CA list answers 403); on the overview, can **propose a CA**, **register its issuer certificate** and **activate** it once approved |
| `lab-requester` | `TRUST_LAB_PW_REQUESTER` | reader + `trust-certificate-requester`, scoped to the lab issuing CA | once the issuing CA is provisioned, can **submit certificate applications** in Certificates |
| `lab-ra-officer` | `TRUST_LAB_PW_RA_OFFICER` | reader + `trust-registration-officer`, scoped to the lab issuing CA | can **approve or reject** others' applications |
| `lab-ca-approver-1`, `lab-ca-approver-2` | `TRUST_LAB_PW_CA_APPROVER_1`, `_2` | `trust-ca-approver` only, with a platform grant and a registered key | no CA; on the overview, can **approve or reject** a KEY_ATTESTED CA proposal with their own key |
| `lab-editor` | `TRUST_LAB_PW_EDITOR` | `trust-profile-editor` only, with an editor grant | refused (403) in the console: the editor role grants no read; it can still write through the API |
| `lab-outsider` | `TRUST_LAB_PW_OUTSIDER` | none | refused (403) |
| `lab-other-ca` | `TRUST_LAB_PW_OTHER_CA` | reader, scoped to a CA granted to nobody | no authority |
| `lab-disabled` | `TRUST_LAB_PW_DISABLED` | reader | cannot sign in |

**Sign out** in the console also ends the Keycloak session. Five wrong passwords lock an account for a minute or more. The Keycloak administration console is at `http://127.0.0.1:8080/admin/` (user `lab-admin`, password `TRUST_LAB_KC_ADMIN_PASSWORD`); changes made there are lost when the container is recreated. The realm files in `scripts/lab/keycloak/` hold no secrets, only `${...}` placeholders filled from `.env.lab`. The `trust-lab-foreign` realm and the `trust-lab-workload` client exist only so that the negative suite can show that the API refuses another issuer's tokens and workload tokens.

### Approving a revision

`scripts/lab/init-env.sh` also generates one P-256 key per approver with OpenSSL into the git-ignored `.lab-keys/` (`lab-approver-1.pem`, `lab-approver-2.pem`) and puts only their public points in `.env.lab`; the database registers them at its first start ([ADR-0011](../adr/ADR-0011-signed-profile-decisions.md), Proposed). To approve a SUBMITTED revision, sign in as `lab-approver-1`, open the revision, choose **Prepare approval**, and sign the claim it shows from the repository root:

```sh
printf '%s' '<claim shown by the console>' | openssl dgst -sha256 -sign .lab-keys/lab-approver-1.pem | openssl base64 -A
```

Paste the output as the signature and record it. The revision becomes APPROVED when `lab-approver-2` has done the same with its own key; one rejection makes it REJECTED. The author and the submitter of a revision cannot decide on it. APPROVED does not activate anything: sign in as `lab-operator` to **Activate this revision** and later **Retire this revision** ([ADR-0012](../adr/ADR-0012-profile-revision-activation.md), Proposed). Activation needs the CA's policy version (`v1` for the allowed CA) and suites the CA declares (`ecdsa-p256-sha256` in the lab; new revisions default to it). No issuance path uses the active revision yet. If `.lab-keys/` is lost, rerun `init-env.sh` and reset the stack (`down -v`) so the new public keys are registered.

To propose a CA ([ADR-0013](../adr/ADR-0013-ca-proposal-and-issuer-certificate.md), Proposed), sign in as `lab-ca-admin` and use **CA proposals** on the overview. Generate the root outside the platform with the proposal's exact display name:

```sh
scripts/lab/create-lab-root.sh "Laboratory Root One"
```

The key stays in `.lab-keys/ca/ca-root-laboratory-root-one.pem`; paste only the printed certificate. The proposal becomes KEY_ATTESTED. It is not yet a CA. Sign in as `lab-ca-approver-1`, then `lab-ca-approver-2`, choose **Prepare CA approval**, and sign the shown claim with your own key, for example `printf '%s' '<claim>' | openssl dgst -sha256 -sign .lab-keys/lab-ca-approver-1.pem | openssl base64 -A`. After two approvals, `lab-ca-admin` can **Activate this CA** ([ADR-0014](../adr/ADR-0014-ca-approval-and-activation.md), Proposed). The CA then exists, with its attested suite as its only signing capability, but readers see it only once the owner grants it, and it issues nothing. On an ACTIVE CA, `lab-ca-admin` can **Suspend this CA** at once, or **Request retirement**; on a SUSPENDED one, **Request reactivation**. The two CA approvers then sign the change claim the same way, and `lab-ca-admin` applies it ([ADR-0015](../adr/ADR-0015-ca-suspension-and-retirement.md), Proposed). Retirement is final.

To try certificate applications ([ADR-0016](../adr/ADR-0016-certificate-applications.md), Proposed), create the **lab issuing CA** with the identifier `dddddddd-dddd-4ddd-8ddd-dddddddddddd` (as `lab-ca-admin`, with the API's optional `ca_id`), register its root, approve and activate it as above, then provision it as the database owner:

```sh
docker compose --env-file .env.lab -f compose.lab.yaml exec -T db psql -U trust_lab -d trust_lab -v ON_ERROR_STOP=1 -v ca=dddddddd-dddd-4ddd-8ddd-dddddddddddd -f - < scripts/lab/provision-issuing-ca.sql
```

Approved applications of that CA can then be issued ([ADR-0017](../adr/ADR-0017-application-issuance-lab-signer.md), Proposed): `lab-ra-officer` or the application's requester chooses **Issue certificate**. The `signer` service, the only one that reads the CA key, signs it once. It serves only the lab issuing CA and reads `.lab-keys/ca/ca-root-lab-issuing-ca.pem` (made by `scripts/lab/create-lab-root.sh "Lab Issuing CA"`) from its read-only mount of `.lab-keys/ca/`. It listens only on a Unix socket shared with the API, and its database login can only read its intent view and claim an intent once. Check a certificate with `openssl verify -CAfile .lab-keys/ca/ca-root-lab-issuing-ca.crt -purpose sslserver cert.pem`. This is a software key with no custody or hardware protection.

To revoke it ([ADR-0018](../adr/ADR-0018-revocation-and-crl.md), Proposed), the requester (or an officer) chooses **Request revocation** with a reason, and `lab-ra-officer`, if they did not ask, chooses **Approve revocation**. **Publish CRL** has the signer sign the next CRL; check it with `openssl crl -in crl.pem -CAfile .lab-keys/ca/ca-root-lab-issuing-ca.crt -noout -verify` and the certificate with `openssl verify -crl_check -CAfile .lab-keys/ca/ca-root-lab-issuing-ca.crt -CRLfile crl.pem cert.pem`. Readers fetch CRLs from `GET /v1/cas/{ca_id}/crls/{crl_number}`. The provisioning script also publishes the lab issuing CA's CRLs ([ADR-0019](../adr/ADR-0019-public-crl-publication.md), Proposed): its new certificates carry the distribution point `http://127.0.0.1:8081/v1/public/crls/dddddddd-dddd-4ddd-8ddd-dddddddddddd/latest.crl`, served without authentication, so `openssl verify -crl_check -crl_download -CAfile .lab-keys/ca/ca-root-lab-issuing-ca.crt cert.pem` fetches the CRL by itself. The console warns when the CRL must be renewed (within two days of nextUpdate) or has expired.

Then activate a profile for it (as for CA E), sign in as `lab-requester` to submit a CSR made with OpenSSL, and as `lab-ra-officer` to approve it. `frontend/dev/certificate-application-e2e.mjs` does all of this on a fresh stack. Nothing is signed yet. If `.lab-keys/` is lost, rerun `init-env.sh` and reset the stack (`down -v`).

The smoke signs `lab-reader` in through the Keycloak login form with code + PKCE, then reads through the API. `lab-reader` holds the reader role and one of the two seeded CAs. Each CA has one synthetic certificate metadata record and one synthetic audit event; only the allowed CA's records may appear. The certificate DER seed is a schema sentinel, not a valid signed X.509 certificate. The second CA must remain absent from the list and return 403 by direct API request. The smoke checks list and detail routes, 400/403/404 responses, absence of certificate DER and actor IDs, and `no-store` on detail responses. All published ports bind host loopback. The API shares the Keycloak container's network namespace so both browser and API can use the exact OIDC issuer `http://127.0.0.1:8080/realms/trust-lab`; the frontend development proxy targets the shared namespace at `issuer:8081`. The [IAM negative suite](../adr/ADR-0009-laboratory-identity-provider.md#negative-evidence) then checks wrong and locked passwords, a disabled user, users without the reader role, an ungranted CA scope, a workload token, an ID token, another realm's token and altered tokens. The [profile lifecycle suite](../adr/ADR-0010-profile-draft-writes.md#evidence) (`frontend/dev/profile-lifecycle-e2e.mjs`) records, replays and submits revisions as `lab-author` and `lab-editor` and checks the refusals for readers, the workload, the hidden CA, stale and altered revisions and syntax warnings. The API writes through a second database login, `trust_api_writer_lab`, that can only execute the two lifecycle functions of migration 0022; nothing in the stack can approve or activate a profile.

Stop while retaining the disposable database:

```sh
docker compose --env-file .env.lab -f compose.lab.yaml down
```

Reset **only this laboratory stack** after a migration or seed change:

```sh
docker compose --env-file .env.lab -f compose.lab.yaml down -v --remove-orphans
docker compose --env-file .env.lab -f compose.lab.yaml up -d --build --wait
```

PostgreSQL's entrypoint runs migrations `0001`–`0031` and seed data only when its volume is first created; startup fails on a migration error. The seed includes a synthetic `*.lab.invalid` subject CN for its invalid-DER certificate metadata and grants the realm's fixed user IDs access to one CA. Some of those grants must authorize nothing (users without the reader role, the workload, and a grant under the foreign realm's issuer); the negative suite checks that they do not. This is a disposable bootstrap, not an online migration/rollback system. `NoTls` PostgreSQL transport is confined to the Compose network, and Keycloak's development mode is not a production identity service. Production transport, credential management, CA key custody, policy-controlled issuance, independent review and G0 remain separate gates.

The Rust schema CI also runs `tests/management_populated_upgrade.sh` against a separate empty PostgreSQL database. It seeds data after migration 0011, applies 0012–0031 and checks row preservation and reader privileges. This is an upgrade regression for those 20 migrations only; it does not upgrade an existing Compose volume or provide a repeatable production migration runner.

A second disposable database exercises [interrupted migration 0013 and manual retry](../operations/lab-management-migration-retry.md), checking that 0012 and existing rows survive a failed 0013 transaction before retry. That historical test uses direct SQL and has no ledger.

The [laboratory management migration ledger](../operations/lab-management-migration-ledger.md) adds a separate operator runner for 0012–0031 and tests concurrent application, repeat runs, source drift and interruption on disposable databases. Compose still bootstraps its own empty volume with the historical SQL files.

A later schema CI step [restores that populated fixture](../operations/lab-management-backup-restore.md) into another empty disposable database and checks row equality and restricted reader privileges. It does not back up this Compose volume or any CA key material.

CI also starts a second disposable PostgreSQL 16 cluster to verify that a missing global reader role stops restoration before any write, then provisions that role and repeats the same data and privilege checks across clusters.
It separately provisions a temporary API login in that cluster and verifies view-only access through the login before grant, during grant and after revocation.

The schema job also injects a mid-restore DDL error in a third disposable database. The restore transaction must roll back all created relations, after which an unmodified retry must pass. This tests SQL restore failure handling, not recovery of the Compose volume or signer state.

The `laboratory-compose` GitHub Actions job builds the images and runs the same scoped smoke on a disposable runner. [Run 39059362985](https://github.com/knehari/trust-platform/actions/runs/39059362985) passed on Draft #53's exact head. Local Docker execution must be recorded separately from CI; a successful `docker compose config` or local PostgreSQL script alone does not establish that the containers start.
