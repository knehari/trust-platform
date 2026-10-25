#!/bin/sh
# Lab-only migration runner: brings an existing lab database up to the
# migrations of this checkout (an existing Compose volume, a restored
# backup), instead of recreating it. POSIX sh, so it also runs inside the
# Compose db container:
#   docker compose --env-file .env.lab -f compose.lab.yaml exec -T db sh /lab/migrate.sh
#   TRUST_MIGRATE_DATABASE_URL=postgresql://... sh scripts/lab/migrate.sh
#
# Which migrations are applied comes from schema_change_review: from 0026 on,
# every migration records its file name there (acknowledge_schema_changes)
# in the transaction that applies it. The runner:
# * on an EMPTY database (no public relation) applies every migration;
# * refuses a database that has relations but no schema_change_review (it
#   predates 0026: rebuild it, see docs/development/lab-compose.md);
# * refuses a database that records a migration-like reference newer than
#   every file here (the database is ahead of this checkout);
# * refuses a gap: a migration file from 0026 up to the newest recorded one
#   that is not recorded (applied out of order, or acknowledged by hand);
# * applies the remaining files in order, one psql run per file (each file
#   is its own transaction), checks that each recorded its reference, and
#   stops at the first failure: that migration rolled back, the later ones
#   are not attempted.
# It needs a superuser (the migrations create roles and SECURITY DEFINER
# functions). It does not compare file contents with what was applied
# (no checksums), and two runners started at once are not serialised: the
# second fails on the first object that already exists.
# Exit status: 0 up to date (applied or nothing to do), 1 refused or failed.
set -eu

migrations_dir=${TRUST_MIGRATIONS_DIR:-/lab/migrations}
[ -d "$migrations_dir" ] || migrations_dir="$(dirname "$0")/../../migrations"
[ -d "$migrations_dir" ] || { echo "migrate: no migrations directory" >&2; exit 1; }

if [ -n "${TRUST_MIGRATE_DATABASE_URL:-}" ]; then
  set -- "$TRUST_MIGRATE_DATABASE_URL"
else
  set -- -U "${POSTGRES_USER:?set TRUST_MIGRATE_DATABASE_URL or POSTGRES_USER}" \
         -d "${POSTGRES_DB:?set TRUST_MIGRATE_DATABASE_URL or POSTGRES_DB}"
fi
q() { psql -X -q -A -t -v ON_ERROR_STOP=1 "$@"; }
sql() { q "$@" -c "$SQL"; }
refuse() { echo "migrate: refused: $*" >&2; exit 1; }

SQL="SELECT rolsuper FROM pg_roles WHERE rolname = session_user"
[ "$(sql "$@")" = t ] || refuse "the login is not a superuser"

files=$(ls "$migrations_dir" | grep -E '^[0-9]{4}_[a-z0-9_]+\.sql$' | sort)
[ -n "$files" ] || refuse "no migration files in $migrations_dir"
newest_file=$(echo "$files" | tail -n 1 | cut -c1-4)

SQL="SELECT count(*) FROM pg_class WHERE relnamespace = 'public'::regnamespace"
relations=$(sql "$@")
SQL="SELECT to_regclass('public.schema_change_review') IS NOT NULL"
has_review=$(sql "$@")

applied=""
if [ "$relations" = 0 ]; then
  echo "migrate: empty database, applying every migration"
elif [ "$has_review" != t ]; then
  refuse "the database predates migration 0026 (no schema_change_review); rebuild it"
else
  SQL="SELECT DISTINCT migration_ref FROM schema_change_review ORDER BY 1"
  applied=$(sql "$@")
  newest_recorded=$(echo "$applied" | cut -c1-4 | sort | tail -n 1)
  if [ "$newest_recorded" \> "$newest_file" ]; then
    refuse "the database records migration $newest_recorded, newer than every file here ($newest_file)"
  fi
  for f in $files; do
    n=$(echo "$f" | cut -c1-4)
    ref=${f%.sql}
    if [ ! "$n" \< 0026 ] && [ ! "$n" \> "$newest_recorded" ] \
       && ! echo "$applied" | grep -qx "$ref"; then
      refuse "gap: $ref is not recorded although $newest_recorded is"
    fi
  done
fi

count=0
for f in $files; do
  n=$(echo "$f" | cut -c1-4)
  ref=${f%.sql}
  if [ -n "$applied" ] && { [ "$n" \< 0026 ] || echo "$applied" | grep -qx "$ref"; }; then
    continue
  fi
  if [ -n "$applied" ] && [ ! "$n" \> "$newest_recorded" ]; then
    continue
  fi
  echo "migrate: applying $ref"
  if ! q "$@" -f "$migrations_dir/$f" >/dev/null; then
    echo "migrate: $ref failed and was rolled back; later migrations not attempted" >&2
    exit 1
  fi
  if [ ! "$n" \< 0026 ]; then
    SQL="SELECT count(*) FROM schema_change_review WHERE migration_ref = '$ref'"
    [ "$(sql "$@")" -ge 1 ] || refuse "$ref ran but did not record its reference"
  fi
  count=$((count + 1))
done
if [ "$count" = 0 ]; then
  echo "migrate: up to date ($newest_file)"
else
  echo "migrate: applied $count migration(s), now at $newest_file"
fi
