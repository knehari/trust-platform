#!/usr/bin/env bash
# Lab-only rehearsal: the populated revocation database is restored into a
# FRESH PostgreSQL 16 cluster, where none of its cluster-global roles exist.
# pg_dump does not carry roles, and the schema depends on them: the
# NOLOGIN owner roles own the SECURITY DEFINER functions, each capability
# role holds its grants, and part of the schema is owned by the login that
# ran the migrations. The script:
# 1. derives from the source catalog the roles the dump needs (owners of
#    public objects and event triggers, ACL grantees), none from pg_*;
# 2. checks that a restore without them fails as a whole (one transaction)
#    and leaves the target empty;
# 3. creates each missing role NOLOGIN in the fresh cluster (the migration
#    login too: ownership needs its name, not a login; no credential is
#    copied). The owner of the event triggers must be a superuser
#    (PostgreSQL rule), so that one role is NOLOGIN SUPERUSER. Then it
#    restores with owners and ACLs;
# 4. compares tests/revocation_restore_fingerprint.sql on both sides
#    (extension member functions, recreated by CREATE EXTENSION and owned by
#    the restoring superuser, are compared as extension versions), runs
#    tests/revocation_privileges.sql on the target, and reserves a CRL
#    there (the definer functions work under their restored owners).
# Needs superuser URLs of the populated source and of an empty database in
# another cluster, and PostgreSQL 16 client tools:
#   TRUST_CI_DATABASE_URL=... TRUST_FRESH_TARGET_URL=... \
#     bash tests/revocation_fresh_cluster_restore.sh
set -euo pipefail
: "${TRUST_CI_DATABASE_URL:?TRUST_CI_DATABASE_URL is required}"
: "${TRUST_FRESH_TARGET_URL:?TRUST_FRESH_TARGET_URL must name an empty database in a fresh cluster}"
src="$TRUST_CI_DATABASE_URL"
dst="$TRUST_FRESH_TARGET_URL"
restore_bin=${TRUST_PG_RESTORE_BIN:-pg_restore}
umask 077
temp="$(mktemp -d)"
trap 'rm -rf "$temp"' EXIT
fail() { echo "FAIL: $*" >&2; cat "$temp/out" >&2 2>/dev/null; exit 1; }
sql() { local db="$1"; shift; psql -X -q -A -t -v ON_ERROR_STOP=1 "$db" -c "$1"; }
relations() { sql "$dst" "SELECT count(*) FROM pg_class WHERE relnamespace = 'public'::regnamespace"; }
cluster_id() { sql "$1" 'SELECT system_identifier FROM pg_control_system()'; }

[ "$(cluster_id "$src")" != "$(cluster_id "$dst")" ] || fail "target is in the source cluster"
[ "$(relations)" = 0 ] || fail "target database must be empty"

# Roles the dump refers to, from the source catalog.
sql "$src" "
  WITH needed(oid) AS (
      SELECT relowner FROM pg_class WHERE relnamespace = 'public'::regnamespace
      UNION SELECT proowner FROM pg_proc WHERE pronamespace = 'public'::regnamespace
      UNION SELECT typowner FROM pg_type WHERE typnamespace = 'public'::regnamespace
      UNION SELECT evtowner FROM pg_event_trigger
      UNION SELECT (aclexplode(relacl)).grantee FROM pg_class
            WHERE relnamespace = 'public'::regnamespace AND relacl IS NOT NULL
      UNION SELECT (aclexplode(proacl)).grantee FROM pg_proc
            WHERE pronamespace = 'public'::regnamespace AND proacl IS NOT NULL)
  SELECT r.rolname FROM needed n JOIN pg_roles r ON r.oid = n.oid
  WHERE r.rolname !~ '^pg_' ORDER BY 1" >"$temp/roles"
[ -s "$temp/roles" ] || fail "no roles found in the source"
grep -qx trust_revocation_owner "$temp/roles" || fail "trust_revocation_owner not among the needed roles"

pg_dump --format=custom --file="$temp/backup.dump" "$src"

# Without the roles the restore fails as a whole.
missing=0
while read -r role; do
  [ "$(sql "$dst" "SELECT count(*) FROM pg_roles WHERE rolname = '$role'")" = 0 ] && missing=$((missing + 1))
done <"$temp/roles"
[ "$missing" -gt 0 ] || fail "the target cluster already has every role: not a fresh cluster"
if "$restore_bin" --exit-on-error --single-transaction --dbname="$dst" "$temp/backup.dump" >"$temp/out" 2>&1; then
  fail "restore succeeded without the roles"
fi
grep -q 'role ".*" does not exist' "$temp/out" || fail "restore failed for another reason"
[ "$(relations)" = 0 ] || fail "a failed restore left relations behind"

# Provision: every missing role NOLOGIN, nothing else, except that
# PostgreSQL requires an event trigger's owner to be a superuser: the owner
# of the schema-change audit event triggers (0026) is created NOLOGIN
# SUPERUSER. No other provisioned role is privileged.
sql "$src" "SELECT DISTINCT r.rolname FROM pg_event_trigger e JOIN pg_roles r ON r.oid = e.evtowner
            ORDER BY 1" >"$temp/event_owners"
while read -r role; do
  attrs=NOLOGIN
  grep -qx "$role" "$temp/event_owners" && attrs="NOLOGIN SUPERUSER"
  sql "$dst" "DO \$\$BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '$role') THEN
                  EXECUTE format('CREATE ROLE %I $attrs', '$role');
                END IF;
              END\$\$" >/dev/null
done <"$temp/roles"
in_list() { sed "s/.*/'&'/" "$1" | paste -sd,; }
[ "$(sql "$dst" "SELECT count(*) FROM pg_roles WHERE rolname IN ($(in_list "$temp/roles"))
                 AND rolname <> session_user
                 AND (rolcanlogin OR rolcreaterole OR rolcreatedb OR rolbypassrls
                      OR (rolsuper AND rolname NOT IN ($(in_list "$temp/event_owners"))))")" = 0 ] \
  || fail "a provisioned role can log in or is privileged beyond the event trigger owner"

"$restore_bin" --exit-on-error --single-transaction --dbname="$dst" "$temp/backup.dump" >"$temp/out" 2>&1 \
  || fail "restore into the provisioned fresh cluster failed"
fingerprint() { psql -X -q -A -t -v ON_ERROR_STOP=1 "$1" -f tests/revocation_restore_fingerprint.sql; }
# Extension members (pgcrypto) are recreated by CREATE EXTENSION and owned by
# the restoring superuser, not restored from the dump: compare the
# extensions and versions instead, and leave their functions out.
extensions() { sql "$1" "SELECT extname || ' ' || extversion FROM pg_extension ORDER BY 1"; }
[ "$(extensions "$src")" = "$(extensions "$dst")" ] || fail "extensions differ"
members() {
  sql "$1" "SELECT 'function ' || p.oid::regprocedure || ' owner='
            FROM pg_proc p JOIN pg_depend d ON d.classid = 'pg_proc'::regclass
                 AND d.objid = p.oid AND d.deptype = 'e'
            WHERE p.pronamespace = 'public'::regnamespace"
}
{ members "$src"; members "$dst"; } | sort -u >"$temp/members"
fingerprint "$src" | grep -v -F -f "$temp/members" >"$temp/source.fp"
fingerprint "$dst" | grep -v -F -f "$temp/members" >"$temp/restored.fp"
[ "$(wc -l <"$temp/source.fp")" -gt 100 ] || fail "fingerprint unexpectedly small"
diff -u "$temp/source.fp" "$temp/restored.fp" >"$temp/out" || fail "restored database differs from the source"
psql -X -q -v ON_ERROR_STOP=1 "$dst" -f tests/revocation_privileges.sql >"$temp/out" 2>&1 \
  || fail "privilege invariants fail on the fresh cluster"
ca="$(sql "$dst" "SELECT ca_id FROM ca_issuer_certificate ORDER BY ca_id LIMIT 1")"
[ -n "$ca" ] || fail "no CA with a registered issuer"
sql "$dst" "SELECT crl_number FROM reserve_crl('$ca', 'fresh-cluster', 'fresh-cluster-reserve')" >"$temp/out" \
  || fail "reserve_crl fails on the fresh cluster"
echo "PASS: revocation database restored into a fresh cluster ($(wc -l <"$temp/roles") roles provisioned NOLOGIN, the event trigger owner as superuser) with rows, owners, ACLs and privileges intact; a restore without the roles fails atomically"
