#!/bin/sh
set -eu

# Starts the disposable laboratory stack on 127.0.0.1, from the repository
# root, with Docker Compose, OpenSSL and (for --demo) Node.js 24.
#
#   scripts/lab/up.sh            start or update the stack, keeping its data
#   scripts/lab/up.sh --reset    destroy the stack, its volumes and its tokens
#                                first (needed after an upgrade that adds
#                                logins, keys or migrations to a database)
#   scripts/lab/up.sh --demo     also create the lab issuing CA, its profile, a
#                                certificate and its CRLs, as
#                                frontend/dev/certificate-application-e2e.mjs
#                                does (needs a fresh stack: use with --reset)
#
# Optional environment:
#   TRUST_LAB_COMPOSE_OVERRIDE=<file>   an extra Compose file (local overrides)
#   TRUST_LAB_SKIP_BROWSER_INSTALL=1    --demo uses an already installed
#                                       Playwright Chromium
#
# Laboratory only: development-mode Keycloak, SoftHSM2 software tokens,
# generated passwords and keys in the ignored .env.lab and .lab-keys/.
cd "$(dirname "$0")/../.."
reset=0
demo=0
for argument in "$@"; do
  case "$argument" in
    --reset) reset=1 ;;
    --demo) demo=1 ;;
    *) echo "usage: scripts/lab/up.sh [--reset] [--demo]" >&2; exit 2 ;;
  esac
done
for tool in docker openssl; do
  command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 1; }
done
docker compose version >/dev/null 2>&1 || { echo 'Docker Compose v2 is required (docker compose)' >&2; exit 1; }
compose() {
  if [ -n "${TRUST_LAB_COMPOSE_OVERRIDE:-}" ]; then
    docker compose --env-file .env.lab -f compose.lab.yaml -f "$TRUST_LAB_COMPOSE_OVERRIDE" "$@"
  else
    docker compose --env-file .env.lab -f compose.lab.yaml "$@"
  fi
}

if [ "$reset" = 1 ] && [ -f .env.lab ]; then
  echo '== Removing the previous stack, its volumes and its SoftHSM2 tokens'
  compose down -v --remove-orphans
  # Public material tied to the destroyed tokens and database.
  rm -f .lab-keys/audit/audit-checkpoint.pub.pem .lab-keys/ca/ca-root-lab-issuing-ca.crt
fi

echo '== Generating missing laboratory credentials, keys and certificates'
scripts/lab/init-env.sh
compose config --quiet

echo '== Building and starting the services (first build: several minutes)'
compose up -d --build --wait --wait-timeout 900

echo '== Audit checkpoint key (ADR-0035)'
if out=$(scripts/lab/create-audit-key-hsm.sh 2>&1); then
  echo 'generated in the trust-lab-audit token; public key in .lab-keys/audit/audit-checkpoint.pub.pem'
elif printf '%s' "$out" | grep -q KeyExists; then
  echo 'already in the trust-lab-audit token'
  if [ ! -s .lab-keys/audit/audit-checkpoint.pub.pem ]; then
    echo 'WARNING: .lab-keys/audit/audit-checkpoint.pub.pem is missing; rerun with --reset to start afresh' >&2
  fi
else
  printf '%s\n' "$out" >&2
  exit 1
fi

if [ "$demo" = 1 ]; then
  command -v node >/dev/null || { echo 'node is required for --demo' >&2; exit 1; }
  echo '== Demo data: the lab issuing CA, a profile, a certificate, its revocation and CRLs'
  [ -d frontend/node_modules ] || npm ci --prefix frontend
  [ "${TRUST_LAB_SKIP_BROWSER_INSTALL:-0}" = 1 ] || (cd frontend && npx playwright install chromium)
  # Node clients verify the HTTPS API and Keycloak against the lab CA.
  NODE_EXTRA_CA_CERTS="$PWD/.lab-keys/tls/ca.crt"
  export NODE_EXTRA_CA_CERTS
  set -a; . ./.env.lab; set +a
  db=$(compose ps -q db)
  TRUST_LAB_OWNER_PSQL="docker exec -i $db psql -U trust_lab -d trust_lab -v ON_ERROR_STOP=1 -q"
  export TRUST_LAB_OWNER_PSQL
  node frontend/dev/certificate-application-e2e.mjs
fi

cat <<'EOF'

The laboratory stack is up, on loopback only:
  Console            http://127.0.0.1:5173/
  Identity provider  https://127.0.0.1:8443/realms/trust-lab   (Keycloak, lab certificate)
  Management API     https://127.0.0.1:8081/   (lab certificate)
  CRLs               http://127.0.0.1:8082/v1/public/crls/<ca_id>/latest.crl
  Metrics            http://127.0.0.1:9464/metrics

Your browser does not know the lab service CA. Either import
.lab-keys/tls/ca.crt as a trusted authority in a test browser profile, or open
https://127.0.0.1:8443/realms/trust-lab/.well-known/openid-configuration once
and accept its certificate. Then sign in from the console (Sign in with your
organization). https://127.0.0.1:8443/ itself is the Keycloak administration
console (master realm, lab-admin only): lab accounts cannot sign in there.

Accounts: see "Signing in" in docs/development/lab-compose.md; each password
is in .env.lab, for example: grep TRUST_LAB_PW_RA_OFFICER= .env.lab
Logs: docker compose --env-file .env.lab -f compose.lab.yaml logs -f api worker signer
Stop: docker compose --env-file .env.lab -f compose.lab.yaml down   (add -v to erase)
EOF
