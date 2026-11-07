#!/bin/sh
# Lab-only migration runner: brings an existing lab database up to the
# migrations of this checkout (an existing Compose volume, a restored
# backup), instead of recreating it. POSIX sh, so it also runs inside the
# Compose db container:
#   docker compose --env-file .env.lab -f compose.lab.yaml exec -T db sh /lab/migrate.sh [--adopt]
#   TRUST_MIGRATE_DATABASE_URL=postgresql://... sh scripts/lab/migrate.sh [--adopt]
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
# * refuses a migration file that differs from the one applied, or that
#   was applied but is missing here: since 0064, migration_file_digest
#   keeps the SHA-256 of every applied file;
# * refuses, before applying anything, a database holding applied files
#   without a digest (applied by the Compose entrypoint, or before 0064)
#   unless --adopt is given. With --adopt the operator states that this
#   checkout holds the files that were applied: their digests are taken from
#   it and recorded as 'adopted' (trust on first use, never inferred
#   silently; an edit made before adoption goes unnoticed);
# * applies the remaining files in order, one psql run per file (each file
#   is its own transaction), checks that each recorded its reference, and
#   stops at the first failure: that migration rolled back, the later ones
#   are not attempted;
# * then records the digest of each file it applied ('applied'). A run that
#   fails leaves the files it applied without a digest: the next run needs
#   --adopt.
# It needs a superuser (the migrations create roles and SECURITY DEFINER
# functions). One runner works on a database at a time: right after the
# superuser check it takes a session advisory lock (pg_try_advisory_lock,
# RUNNER_LOCK_KEY) in a psql session it keeps open until it exits, and a
# second runner is refused while the lock is held. The lock goes with that
# session, so it is released however the runner ends.
# Exit status: 0 up to date (applied or nothing to do), 1 refused or failed.
set -eu

adopt=no
case "${1:-}" in
  --adopt) adopt=yes ;;
  "") ;;
  *) echo "usage: migrate.sh [--adopt]" >&2; exit 1 ;;
esac
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
digest() { sha256sum "$1" | cut -c1-64; }
sql() { q "$@" -c "$SQL"; }
refuse() { echo "migrate: refused: $*" >&2; exit 1; }

SQL="SELECT rolsuper FROM pg_roles WHERE rolname = session_user"
[ "$(sql "$@")" = t ] || refuse "the login is not a superuser"

# One runner at a time: hold the lock in a session that lives as long as
# this script (its stdin is a FIFO this script keeps open).
RUNNER_LOCK_KEY=7426147730113041
lock_dir=$(mktemp -d)
mkfifo "$lock_dir/in"
q "$@" <"$lock_dir/in" >"$lock_dir/out" 2>&1 &
lock_pid=$!
exec 3>"$lock_dir/in"
trap 'exec 3>&-; wait "$lock_pid" 2>/dev/null || true; rm -rf "$lock_dir"' EXIT
echo "SELECT pg_try_advisory_lock($RUNNER_LOCK_KEY);" >&3
waited=0
while [ ! -s "$lock_dir/out" ] && [ "$waited" -lt 300 ]; do
  sleep 0.1
  waited=$((waited + 1))
done
case "$(head -n 1 "$lock_dir/out")" in
  t) ;;
  f) refuse "another migration runner is working on this database" ;;
  *) refuse "could not take the migration runner lock" ;;
esac

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

# Applied files must not have changed since (digests kept since 0064).
SQL="SELECT to_regclass('public.migration_file_digest') IS NOT NULL"
if [ "$(sql "$@")" = t ]; then
  SQL="SELECT migration_ref || ' ' || encode(file_sha256, 'hex') FROM migration_file_digest ORDER BY 1"
  recorded=$(sql "$@")
  while read -r ref hex; do
    [ -n "$ref" ] || continue
    [ -f "$migrations_dir/$ref.sql" ] || refuse "$ref was applied but its file is missing here"
    [ "$(digest "$migrations_dir/$ref.sql")" = "$hex" ] \
      || refuse "$ref.sql differs from the file applied to this database"
  done <<EOF
$recorded
EOF
  SQL="SELECT migration_ref FROM migration_file_digest"
  known=$(sql "$@")
else
  known=""
fi
# Applied files without a digest are adopted only on request.
unknown=0
first_unknown=""
if [ "$relations" != 0 ]; then
  for f in $files; do
    n=$(echo "$f" | cut -c1-4)
    ref=${f%.sql}
    [ "$n" \> "$newest_recorded" ] && continue
    echo "$known" | grep -qx "$ref" && continue
    unknown=$((unknown + 1))
    [ -n "$first_unknown" ] || first_unknown=$ref
  done
fi
if [ "$unknown" != 0 ] && [ "$adopt" != yes ]; then
  refuse "$unknown applied migration file(s) have no recorded digest (first: $first_unknown);" \
         "check that this checkout holds the files that were applied, then rerun with --adopt"
fi

count=0
applied_now=""
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
  applied_now="$applied_now $ref"
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

# Record the digest of every file without one: all of them are applied now,
# by this run or (with --adopt) before it.
adopted=0
SQL="SELECT to_regclass('public.migration_file_digest') IS NOT NULL"
[ "$(sql "$@")" = t ] || refuse "migration_file_digest is missing (is 0064 in $migrations_dir?)"
for f in $files; do
  ref=${f%.sql}
  echo "$known" | grep -qx "$ref" && continue
  how=adopted
  case " $applied_now " in *" $ref "*) how=applied ;; esac
  [ "$how" = adopted ] && adopted=$((adopted + 1))
  SQL="INSERT INTO migration_file_digest (migration_ref, file_sha256, recorded_how)
       VALUES ('$ref', decode('$(digest "$migrations_dir/$f")', 'hex'), '$how')"
  sql "$@" >/dev/null
done
[ "$adopted" = 0 ] || echo "migrate: adopted the digests of $adopted file(s) applied before digests were kept"
if [ "$count" = 0 ]; then
  echo "migrate: up to date ($newest_file)"
else
  echo "migrate: applied $count migration(s), now at $newest_file"
fi
