#!/usr/bin/env bash
# Cold backup of the laboratory stack (ADR-0041, Proposed). Laboratory only.
#
#   scripts/lab/backup.sh [--out <dir>]
#
# Stops the services that write (api, worker, publisher, signer), then saves,
# into a new owner-only directory (default .lab-backups/<UTC time>):
#   database.dump       pg_dump custom format of trust_lab, by the owner
#   signer-volumes.tar  the SoftHSM2 tokens (CA and audit keys, encrypted
#                       under their PINs) and the signer's checkpoint state
#   manifest.json       the time, the code revision, the record counts and
#                       digests of backup-facts.sql, and each file's SHA-256
# and restarts the services. Stopping them keeps the three parts consistent:
# the signer's state never runs ahead of the database it checkpointed.
#
# Not saved: .env.lab and .lab-keys/ (passwords, PINs, TLS and approver
# keys), which a restore needs unchanged and which must be kept apart from the
# archive (the tokens are only as safe as their PINs); Keycloak's state (the
# lab realm is imported at start); the public CRL tree (republished from the
# database). The archive holds the CA's and the audit key's token files:
# keep it as protected as the keys.
set -euo pipefail
cd "$(dirname "$0")/../.."
out=
while [ $# -gt 0 ]; do
  case "$1" in
    --out) out=${2:?--out needs a directory}; shift 2 ;;
    *) echo 'usage: scripts/lab/backup.sh [--out <dir>]' >&2; exit 2 ;;
  esac
done
[ -f .env.lab ] || { echo '.env.lab is missing: no laboratory stack to back up' >&2; exit 1; }
compose() {
  if [ -n "${TRUST_LAB_COMPOSE_OVERRIDE:-}" ]; then
    docker compose --env-file .env.lab -f compose.lab.yaml -f "$TRUST_LAB_COMPOSE_OVERRIDE" "$@"
  else
    docker compose --env-file .env.lab -f compose.lab.yaml "$@"
  fi
}
db=$(compose ps -q db)
[ -n "$db" ] || { echo 'the database service is not running' >&2; exit 1; }
out=${out:-.lab-backups/$(date -u +%Y%m%dT%H%M%SZ)}
[ ! -e "$out" ] || { echo "$out already exists" >&2; exit 1; }
umask 077
mkdir -p "$out"
chmod 700 "$out"
started=$(date +%s)

writers=(api worker publisher signer)
restart() { compose up -d --wait --wait-timeout 300 "${writers[@]}" >/dev/null; }
echo "== Stopping ${writers[*]}"
compose stop "${writers[@]}" >/dev/null
trap 'echo "backup failed; restarting the services" >&2; restart' ERR

echo '== Database (pg_dump, custom format)'
docker exec "$db" pg_dump -U trust_lab -d trust_lab -Fc > "$out/database.dump"
facts=$(docker exec -i "$db" psql -U trust_lab -d trust_lab -XAtq -v ON_ERROR_STOP=1 < scripts/lab/backup-facts.sql)

echo '== Signer tokens and checkpoint state'
compose run --rm --no-deps -T --entrypoint tar signer -C /var/lib -cf - softhsm/tokens trust-signer \
  > "$out/signer-volumes.tar"
tar -tf "$out/signer-volumes.tar" | grep -q '^softhsm/tokens/' \
  || { echo 'the signer archive holds no token' >&2; false; }

revision=$(git rev-parse HEAD 2>/dev/null || echo unknown)
python3 - "$out" "$revision" "$facts" <<'PY'
import hashlib, json, os, sys, datetime
out, revision, facts = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])
files = {}
for name in ("database.dump", "signer-volumes.tar"):
    with open(os.path.join(out, name), "rb") as handle:
        files[name] = hashlib.sha256(handle.read()).hexdigest()
manifest = {
    "format": "trust-platform:lab-backup:v1",
    "created_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "code_revision": revision,
    "facts": facts,
    "files": files,
}
with open(os.path.join(out, "manifest.json"), "w") as handle:
    json.dump(manifest, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
chmod 600 "$out"/*

trap - ERR
echo "== Restarting ${writers[*]}"
restart
echo "PASS: backup in $out in $(( $(date +%s) - started )) s (services stopped meanwhile)"
echo "$facts"
