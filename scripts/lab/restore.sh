#!/usr/bin/env bash
# Restore of a laboratory backup made by scripts/lab/backup.sh (ADR-0041,
# Proposed). Laboratory only.
#
#   scripts/lab/restore.sh --replace-stack <backup dir>
#       Destroys the current stack and ALL its volumes (database, SoftHSM2
#       tokens, signer state, public CRLs), starts a fresh database, restores
#       the dump into it and the tokens and signer state into their volumes,
#       then starts every service.
#   scripts/lab/restore.sh --database-only <backup dir>
#       Replaces only the database, keeping the tokens and the signer's
#       state. If the signer checkpointed the audit chain after the backup,
#       it will refuse every checkpoint of the restored database
#       (AuditRollback): the rollback is detected, by design. Restore the
#       matching signer state with --replace-stack to resume checkpoints.
#
# Both need the same .env.lab and .lab-keys/ as when the backup was made
# (logins, PINs, TLS certificates), and code whose schema version markers
# match the backup's; the restore refuses otherwise, before replacing
# anything. Each part is checked against the manifest's SHA-256 first, and
# the restored records against the manifest's facts after.
set -euo pipefail
cd "$(dirname "$0")/../.."
mode=
dir=
while [ $# -gt 0 ]; do
  case "$1" in
    --replace-stack) mode=stack; shift ;;
    --database-only) mode=database; shift ;;
    -*) echo "unknown option $1" >&2; exit 2 ;;
    *) dir=$1; shift ;;
  esac
done
[ -n "$mode" ] && [ -n "$dir" ] || {
  echo 'usage: scripts/lab/restore.sh --replace-stack|--database-only <backup dir>' >&2; exit 2; }
[ -f .env.lab ] || { echo '.env.lab is missing: the restore needs the original one' >&2; exit 1; }
compose() {
  if [ -n "${TRUST_LAB_COMPOSE_OVERRIDE:-}" ]; then
    docker compose --env-file .env.lab -f compose.lab.yaml -f "$TRUST_LAB_COMPOSE_OVERRIDE" "$@"
  else
    docker compose --env-file .env.lab -f compose.lab.yaml "$@"
  fi
}
manifest_field() { python3 -c 'import json,sys; v=json.load(open(sys.argv[1])); [v:=v[k] for k in sys.argv[2:]]; print(json.dumps(v) if isinstance(v,(dict,list)) else v)' "$dir/manifest.json" "$@"; }
started=$(date +%s)

echo '== Checking the backup'
[ "$(manifest_field format)" = 'trust-platform:lab-backup:v1' ] || { echo 'not a laboratory backup' >&2; exit 1; }
for name in database.dump signer-volumes.tar; do
  [ "$(sha256sum "$dir/$name" | cut -d' ' -f1)" = "$(manifest_field files "$name")" ] \
    || { echo "$name does not match the manifest" >&2; exit 1; }
done
expected_facts=$(manifest_field facts)
owner_psql() { docker exec -i "$(compose ps -q db)" psql -U trust_lab -XAtq -v ON_ERROR_STOP=1 "$@"; }
facts() { owner_psql -d trust_lab < scripts/lab/backup-facts.sql; }
schema_of() { python3 -c 'import json,sys; print(json.loads(sys.argv[1])["schema_sha256"])' "$1"; }

writers=(api worker publisher signer)
if [ "$mode" = stack ]; then
  echo '== Destroying the current stack and its volumes'
  compose down -v --remove-orphans
  echo '== Starting a fresh database'
  compose up -d --wait --wait-timeout 300 db >/dev/null
else
  [ -n "$(compose ps -q db)" ] || { echo 'the database service is not running' >&2; exit 1; }
  echo "== Stopping ${writers[*]}"
  compose stop "${writers[@]}" >/dev/null
fi
# The code's schema must be the backup's: compare the version markers of the
# running database (fresh from this code, or the current one) first.
current=$(facts)
if [ "$(schema_of "$current")" != "$(schema_of "$expected_facts")" ]; then
  echo 'the backup was made with another schema version; check out its code revision:' >&2
  manifest_field code_revision >&2
  exit 1
fi

echo '== Restoring the database'
owner_psql -d postgres -c 'DROP DATABASE trust_lab WITH (FORCE)' -c 'CREATE DATABASE trust_lab OWNER trust_lab'
docker exec -i "$(compose ps -q db)" pg_restore -U trust_lab -d trust_lab --exit-on-error --single-transaction \
  < "$dir/database.dump"

if [ "$mode" = stack ]; then
  echo '== Restoring the signer tokens and checkpoint state'
  compose run --rm --no-deps -T --entrypoint tar signer -C /var/lib -xf - < "$dir/signer-volumes.tar"
fi

restored=$(facts)
python3 - "$expected_facts" "$restored" <<'PY'
import json, sys
expected, restored = json.loads(sys.argv[1]), json.loads(sys.argv[2])
differ = [key for key in expected if expected[key] != restored.get(key)]
if differ:
    sys.exit("restored records differ from the backup: " + ", ".join(differ))
PY

echo '== Starting the services'
compose up -d --wait --wait-timeout 300 >/dev/null
echo "PASS: restored $dir ($mode) in $(( $(date +%s) - started )) s"
echo "$restored"
