#!/usr/bin/env bash
# Lab-only: scripts/lab/migrate.sh brings an existing database up to this
# checkout's migrations and refuses the cases it cannot handle safely.
# Needs a superuser URL to a cluster where it may create and drop databases
# named trust_migrate_*, psql and the migrations:
#   TRUST_CI_DATABASE_URL=postgresql://.../any bash tests/revocation_migration_runner.sh
set -euo pipefail
: "${TRUST_CI_DATABASE_URL:?TRUST_CI_DATABASE_URL is required}"
temp="$(mktemp -d)"
trap 'rm -rf "$temp"' EXIT
fail() { echo "FAIL: $*" >&2; cat "$temp/out" >&2 2>/dev/null; exit 1; }
url_for() { # <database>
  python3 - "$TRUST_CI_DATABASE_URL" "$1" <<'PY'
import sys, urllib.parse
u = urllib.parse.urlsplit(sys.argv[1])
print(urllib.parse.urlunsplit((u.scheme, u.netloc, "/" + sys.argv[2], u.query, u.fragment)))
PY
}
admin="$(url_for postgres)"
fresh() { # <database> [last migration prefix]: a new database, migrated up to the prefix
  psql -X -q -v ON_ERROR_STOP=1 "$admin" -c "DROP DATABASE IF EXISTS $1" -c "CREATE DATABASE $1" 2>/dev/null
  if [ -n "${2:-}" ]; then
    for m in migrations/*.sql; do
      [ "$(basename "$m" | cut -c1-4)" \> "$2" ] && continue
      psql -X -q -v ON_ERROR_STOP=1 "$(url_for "$1")" -f "$m" >/dev/null
    done
  fi
}
refs() { psql -X -q -A -t -v ON_ERROR_STOP=1 "$(url_for "$1")" -c "SELECT count(*) FROM schema_change_review"; }
migrate() { # <database> [migrations dir]
  TRUST_MIGRATE_DATABASE_URL="$(url_for "$1")" TRUST_MIGRATIONS_DIR="${2:-migrations}" \
    sh scripts/lab/migrate.sh >"$temp/out" 2>&1
}
expect_refused() { # <database> <message> [migrations dir]
  local before; before="$(refs "$1" 2>/dev/null || echo none)"
  if migrate "$1" "${3:-}"; then fail "$1: accepted"; fi
  grep -q "$2" "$temp/out" || fail "$1: wrong refusal"
  [ "$(refs "$1" 2>/dev/null || echo none)" = "$before" ] || fail "$1: a refused run changed the database"
}
newest="$(ls migrations | grep -E '^[0-9]{4}_' | sort | tail -n 1 | cut -c1-4)"
files_from_0026="$(ls migrations | grep -E '^[0-9]{4}_' | awk '$0 >= "0026"' | wc -l)"

# An empty database gets every migration; a second run changes nothing.
fresh trust_migrate_empty
migrate trust_migrate_empty || fail "empty database"
grep -q "now at $newest" "$temp/out" || fail "empty database not brought to $newest"
[ "$(refs trust_migrate_empty)" = "$files_from_0026" ] || fail "not every migration recorded"
migrate trust_migrate_empty || fail "second run"
grep -q "up to date" "$temp/out" || fail "second run was not a no-op"
[ "$(refs trust_migrate_empty)" = "$files_from_0026" ] || fail "second run recorded something"

# A database left at 0057 gets the later migrations only.
fresh trust_migrate_0057 0057
migrate trust_migrate_0057 || fail "upgrade from 0057"
grep -q "applying 0058_" "$temp/out" || fail "0058 not applied"
grep -q "applying 0057_" "$temp/out" && fail "0057 applied twice"
[ "$(refs trust_migrate_0057)" = "$files_from_0026" ] || fail "upgrade from 0057 incomplete"

# Refusals, each leaving the database as it was.
fresh trust_migrate_ahead 0057
psql -X -q "$(url_for trust_migrate_ahead)" -c "SELECT acknowledge_schema_changes('9998_from_the_future')" >/dev/null
expect_refused trust_migrate_ahead "newer than every file here"
fresh trust_migrate_gap 0057
psql -X -q "$(url_for trust_migrate_gap)" -c "SELECT acknowledge_schema_changes('0059_delta_crl')" >/dev/null
expect_refused trust_migrate_gap "gap: 0058_crl_number_floor is not recorded"
fresh trust_migrate_old 0013
expect_refused trust_migrate_old "predates migration 0026"
psql -X -q "$admin" -c "DO \$\$BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trust_migrate_plain_ci') THEN
      CREATE ROLE trust_migrate_plain_ci LOGIN PASSWORD 'test-only-not-secret';
    END IF; END\$\$" >/dev/null
plain_url="$(python3 - "$(url_for trust_migrate_0057)" <<'PY'
import sys, urllib.parse
u = urllib.parse.urlsplit(sys.argv[1])
host = u.hostname + (f":{u.port}" if u.port else "")
print(urllib.parse.urlunsplit((u.scheme, f"trust_migrate_plain_ci:test-only-not-secret@{host}", u.path, u.query, u.fragment)))
PY
)"
if TRUST_MIGRATE_DATABASE_URL="$plain_url" sh scripts/lab/migrate.sh >"$temp/out" 2>&1; then
  fail "a non-superuser login was accepted"
fi
grep -q "not a superuser" "$temp/out" || fail "non-superuser: wrong refusal"

# A failing migration stops the run; it rolled back and the next is not tried.
cp -r migrations "$temp/migrations"
printf 'BEGIN;\nCREATE TABLE runner_probe_ok (x int);\nSELECT 1/0;\nCOMMIT;\n' >"$temp/migrations/9990_broken.sql"
printf 'BEGIN;\nCREATE TABLE runner_probe_after (x int);\nCOMMIT;\n' >"$temp/migrations/9991_after.sql"
before="$(refs trust_migrate_empty)"
if migrate trust_migrate_empty "$temp/migrations"; then fail "a failing migration was accepted"; fi
grep -q "9990_broken failed and was rolled back" "$temp/out" || fail "failure not reported"
[ "$(psql -X -q -A -t "$(url_for trust_migrate_empty)" -c "SELECT to_regclass('runner_probe_ok') IS NULL
     AND to_regclass('runner_probe_after') IS NULL")" = t ] || fail "the failed migration or the next one left objects"
[ "$(refs trust_migrate_empty)" = "$before" ] || fail "the failed run recorded something"

for db in empty 0057 ahead gap old; do
  psql -X -q "$admin" -c "DROP DATABASE IF EXISTS trust_migrate_$db" 2>/dev/null
done
echo "PASS: migrate.sh brings an existing database to $newest, is a no-op when current, and refuses newer, gapped, pre-0026 and non-superuser databases and stops on a failing migration"
