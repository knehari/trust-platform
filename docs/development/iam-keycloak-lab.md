# Isolated Keycloak IAM laboratory

This Compose project exercises MVP criterion 5 without changing the existing fixture stack on port 5173. It is a loopback-only development environment, not a production IdP deployment. The realm import defines two separate human accounts (`maker`, `checker`), a public console client using Authorization Code and PKCE S256, and a confidential service client using client credentials. Each client emits an RS256 `at+jwt` access token for `trust-api` with explicit CA scope. The API also requires a database-owner-managed `(issuer, subject, CA)` grant.

## Start and test

From the repository root:

```sh
sh scripts/lab/init-iam-env.sh
docker compose --env-file .env.iam.lab -f compose.iam.lab.yaml up -d --build
set -a; . ./.env.iam.lab; set +a
PYTHONDONTWRITEBYTECODE=1 python3 scripts/lab/iam-smoke.py
PYTHONDONTWRITEBYTECODE=1 python3 scripts/lab/provision-iam-workload-grant.py
PYTHONDONTWRITEBYTECODE=1 python3 scripts/lab/iam-smoke.py --workload-granted
```

The Python checks use `requests` 2.x. The first smoke run proves that an authenticated but ungranted service account has no CA access. The provisioning command obtains the real Keycloak service-account subject from its admin API and inserts exactly one grant into this lab's PostgreSQL database; it is idempotent. The second run proves positive access to that CA and denial for the unrelated CA. Both runs exercise independent human sign-ins, PKCE token exchange, access versus ID token distinction, signed client and role claims, and anonymous denial. They do not change the original 5173 stack.

The IAM console is at [http://127.0.0.1:5273/](http://127.0.0.1:5273/), Keycloak at [http://127.0.0.1:8180/](http://127.0.0.1:8180/), and the API at `http://127.0.0.1:8181/v1`. Account names are `maker` and `checker`. Their generated passwords, the admin password and the service secret are in ignored, mode-0600 `.env.iam.lab`; do not copy them into tracked files or browser screenshots. `init-iam-env.sh` preserves an existing file. Keycloak imports the realm only on a new data volume, so editing the realm JSON does not reconfigure an existing realm. Do not remove a non-disposable volume to apply changes.

The console may log out and sign in with either human account. The workload secret stays server-side. The realm disables password grants for the console; the API refuses an ID token as a credential. The API login has read-only database privileges and cannot create its own CA grants. HTTP and Keycloak development mode are acceptable only on loopback. A controlled pilot must use TLS, governed credentials, a hardened IdP, configured MFA/session policy, TLS-authenticated database transport, an independent security review, and a deployed operator recovery procedure. Maker/checker approval policy is implemented with the write lifecycle under criterion 6; this lab only proves separate authentication and claims.
