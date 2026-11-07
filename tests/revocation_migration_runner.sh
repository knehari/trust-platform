#!/usr/bin/env bash
# Lab-only: scripts/lab/migrate.sh brings an existing database up to this
# checkout's migrations and refuses the cases it cannot handle safely,
# including a migration file changed or removed after it was applied (0076).
# Needs a superuser URL to a cluster where it may create and drop databases
# named trust_migrate_*, psql and the migrations:
#   TRUST_CI_DATABASE_URL=postgresql://.../any bash tests/revocation_migration_runner.sh
set -euo pipefail
: "${TRUST_CI_DATABASE_URL:?TRUST_CI_DATABASE_URL is required}"
temp="$(mktemp -d)"
holder=""
trap 'rm -rf "$temp"; [ -z "$holder" ] || kill "$holder" 2>/dev/null || true' EXIT
fail() { echo "FAIL: $*" >&2; cat "$temp/out" >&2 2>/dev/null; exit 1; }
url_for() { # <database>
  local base=${TRUST_CI_DATABASE_URL%%\?*}
  local query=${TRUST_CI_DATABASE_URL#"$base"}
  [[ "$base" == postgresql://*/* || "$base" == postgres://*/* ]] \
    || { echo 'TRUST_CI_DATABASE_URL must include a database path' >&2; return 1; }
  printf '%s/%s%s\n' "${base%/*}" "$1" "$query"
}
admin="$(url_for postgres)"
fresh() { # <database> [last migration prefix]: a new database, migrated up to the prefix
  psql -X -q -v ON_ERROR_STOP=1 "$admin" \
    -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '$1'" \
    -c "DROP DATABASE IF EXISTS $1" -c "CREATE DATABASE $1" >/dev/null 2>"$temp/out" \
    || fail "could not recreate $1"
  if [ -n "${2:-}" ]; then
    for m in migrations/*.sql; do
      [ "$(basename "$m" | cut -c1-4)" \> "$2" ] && continue
      psql -X -q -v ON_ERROR_STOP=1 "$(url_for "$1")" -f "$m" >/dev/null
    done
  fi
}
refs() { psql -X -q -A -t -v ON_ERROR_STOP=1 "$(url_for "$1")" -c "SELECT count(*) FROM schema_change_review"; }
digests() { # <database> <recorded_how>
  psql -X -q -A -t -v ON_ERROR_STOP=1 "$(url_for "$1")" \
    -c "SELECT count(*) FROM migration_file_digest WHERE recorded_how = '$2'"
}
migrate() { # <database> [migrations dir] [--adopt]
  TRUST_MIGRATE_DATABASE_URL="$(url_for "$1")" TRUST_MIGRATIONS_DIR="${2:-migrations}" \
    sh scripts/lab/migrate.sh ${3:-} >"$temp/out" 2>&1
}
expect_refused() { # <database> <message> [migrations dir]
  local before; before="$(refs "$1" 2>/dev/null || echo none)"
  if migrate "$1" "${3:-}"; then fail "$1: accepted"; fi
  grep -q "$2" "$temp/out" || fail "$1: wrong refusal"
  [ "$(refs "$1" 2>/dev/null || echo none)" = "$before" ] || fail "$1: a refused run changed the database"
}
newest="$(ls migrations | grep -E '^[0-9]{4}_' | sort | tail -n 1 | cut -c1-4)"
all_files="$(ls migrations | grep -Ec '^[0-9]{4}_[a-z0-9_]+\.sql$')"
files_to_0069="$(ls migrations | grep -E '^[0-9]{4}_' | awk '$0 < "0070"' | wc -l)"
files_from_0038="$(ls migrations | grep -E '^[0-9]{4}_' | awk '$0 >= "0038"' | wc -l)"

# An empty database gets every migration; a second run changes nothing.
fresh trust_migrate_empty
migrate trust_migrate_empty || fail "empty database"
grep -q "now at $newest" "$temp/out" || fail "empty database not brought to $newest"
[ "$(refs trust_migrate_empty)" = "$files_from_0038" ] || fail "not every migration recorded"
migrate trust_migrate_empty || fail "second run"
grep -q "up to date" "$temp/out" || fail "second run was not a no-op"
[ "$(refs trust_migrate_empty)" = "$files_from_0038" ] || fail "second run recorded something"
# The runner applied every file, so it recorded every digest as applied.
[ "$(digests trust_migrate_empty applied)" = "$all_files" ] || fail "digests of applied files not recorded"
[ "$(digests trust_migrate_empty adopted)" = 0 ] || fail "applied files recorded as adopted"

# A database left at 0069 gets the later migrations only.
fresh trust_migrate_0069 0069
# Its files were applied without digests: adopting them is an explicit step.
expect_refused trust_migrate_0069 "$files_to_0069 applied migration file(s) have no recorded digest"
grep -q "rerun with --adopt" "$temp/out" || fail "adoption not explained"
migrate trust_migrate_0069 migrations --adopt || fail "upgrade from 0069"
grep -q "applying 0070_" "$temp/out" || fail "0070 not applied"
grep -q "applying 0069_" "$temp/out" && fail "0069 applied twice"
[ "$(refs trust_migrate_0069)" = "$files_from_0038" ] || fail "upgrade from 0069 incomplete"
# Files applied before digests were kept are adopted from this checkout;
# later runs need no --adopt.
[ "$(digests trust_migrate_0069 adopted)" = "$files_to_0069" ] || fail "earlier files not adopted"
[ "$(digests trust_migrate_0069 applied)" = "$((all_files - files_to_0069))" ] || fail "upgrade digests not recorded"
psql -X -q "$(url_for trust_migrate_0069)" -c "DELETE FROM migration_file_digest" >/dev/null 2>&1 \
  && fail "migration_file_digest is not append-only"
migrate trust_migrate_0069 || fail "run after adoption"
grep -q "up to date" "$temp/out" || fail "run after adoption was not a no-op"

# A migration file changed or removed after it was applied is refused.
cp -r migrations "$temp/changed"
printf -- '-- edited after it was applied\n' >>"$temp/changed/0042_crl_distribution.sql"
expect_refused trust_migrate_empty "0042_crl_distribution.sql differs from the file applied" "$temp/changed"
cp -r migrations "$temp/removed"
rm "$temp/removed/0042_crl_distribution.sql"
expect_refused trust_migrate_empty "0042_crl_distribution was applied but its file is missing" "$temp/removed"

# Refusals, each leaving the database as it was.
fresh trust_migrate_ahead 0069
psql -X -q "$(url_for trust_migrate_ahead)" -c "SELECT acknowledge_schema_changes('9998_from_the_future')" >/dev/null
expect_refused trust_migrate_ahead "newer than every file here"
fresh trust_migrate_gap 0069
psql -X -q "$(url_for trust_migrate_gap)" -c "SELECT acknowledge_schema_changes('0071_delta_crl')" >/dev/null
expect_refused trust_migrate_gap "gap: 0070_crl_number_floor is not recorded"
fresh trust_migrate_old 0013
expect_refused trust_migrate_old "existing profile database needs --adopt"
psql -X -q "$admin" -c "DO \$\$BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trust_migrate_plain_ci') THEN
      CREATE ROLE trust_migrate_plain_ci LOGIN PASSWORD 'test-only-not-secret';
    END IF; END\$\$" >/dev/null
plain_base=$(url_for trust_migrate_0069)
plain_scheme=${plain_base%%://*}
plain_tail=${plain_base#*://}
plain_authority=${plain_tail%%/*}
plain_host=${plain_authority##*@}
plain_url="$plain_scheme://trust_migrate_plain_ci:test-only-not-secret@$plain_host/${plain_tail#*/}"
if TRUST_MIGRATE_DATABASE_URL="$plain_url" sh scripts/lab/migrate.sh >"$temp/out" 2>&1; then
  fail "a non-superuser login was accepted"
fi
grep -q "not a superuser" "$temp/out" || fail "non-superuser: wrong refusal"

# A second runner on the same database is refused while the first holds the
# runner lock (pg_try_advisory_lock with the key in scripts/lab/migrate.sh),
# and the lock is released when the holder ends.
psql -X -q "$(url_for trust_migrate_empty)" \
  -c "SELECT pg_advisory_lock(7426147730113041)" -c "SELECT pg_sleep(20)" >/dev/null 2>&1 &
holder=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
  [ "$(psql -X -q -A -t "$admin" -c "SELECT count(*) FROM pg_locks
        WHERE locktype = 'advisory' AND objid = (7426147730113041 & 4294967295)::oid
          AND database = (SELECT oid FROM pg_database WHERE datname = 'trust_migrate_empty')")" = 1 ] && break
  sleep 0.5
done
expect_refused trust_migrate_empty "another migration runner is working on this database"
kill "$holder" 2>/dev/null; wait "$holder" 2>/dev/null || true
psql -X -q "$admin" -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity
    WHERE datname = 'trust_migrate_empty' AND pid <> pg_backend_pid()" >/dev/null
migrate trust_migrate_empty || fail "runner after the lock holder ended"
grep -q "up to date" "$temp/out" || fail "runner after the lock holder ended: not up to date"
# The runner releases its own lock: nothing is left held after it.
[ "$(psql -X -q -A -t "$admin" -c "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory'
      AND objid = (7426147730113041 & 4294967295)::oid")" = 0 ] || fail "runner lock left held"

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

for db in empty 0069 ahead gap old; do
  psql -X -q "$admin" -c "DROP DATABASE IF EXISTS trust_migrate_$db" 2>/dev/null
done
echo "PASS: migrate.sh brings an existing database to $newest, is a no-op when current, records file digests, and refuses changed or removed files, a concurrent runner, newer, gapped, pre-0038 and non-superuser databases and stops on a failing migration"
