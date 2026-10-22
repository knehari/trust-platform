#!/usr/bin/env bash
# Disposable PostgreSQL 16 (lab only): logical backup and restore of a
# POPULATED revocation database, then re-verification of what the restore
# must preserve. Run it after signed_status_change_postgres and
# signed_evidence_audit_all.sh on the same database, so the source carries
# signed evidence (some deliberately altered), credentials, CRLs and audit
# history. Needs a superuser URL for the source and an EMPTY target database
# in the SAME cluster (roles are cluster-global: a restore into a fresh
# cluster needs the roles first, which this test does not cover):
#   TRUST_CI_DATABASE_URL=postgresql://... \
#   TRUST_RESTORE_TARGET_URL=postgresql://.../empty \
#     bash tests/revocation_backup_restore.sh
# It checks that the restore keeps:
# * every row, sequence position, owner, ACL, SECURITY DEFINER setting,
#   trigger state and event trigger (tests/revocation_restore_fingerprint.sql);
# * the privilege invariants (tests/revocation_privileges.sql);
# * the offline re-verification of signed evidence, with the same result;
# * the audit chain against a checkpoint exported before the backup; and
#   that a stale backup is refused against a later checkpoint;
# * no unreviewed schema change logged by the restore itself;
# * a working store: a restored database seals new audit records.
# This is not a disaster recovery procedure: CA keys, the checkpoint file
# and the CRL distribution point are outside the database.
set -euo pipefail
: "${TRUST_CI_DATABASE_URL:?TRUST_CI_DATABASE_URL is required}"
: "${TRUST_RESTORE_TARGET_URL:?TRUST_RESTORE_TARGET_URL must name an empty database}"
src="$TRUST_CI_DATABASE_URL"
dst="$TRUST_RESTORE_TARGET_URL"
dump_bin=${TRUST_PG_DUMP_BIN:-pg_dump}
restore_bin=${TRUST_PG_RESTORE_BIN:-pg_restore}
umask 077
temp="$(mktemp -d)"
trap 'rm -rf "$temp"' EXIT
fail() { echo "FAIL: $*" >&2; cat "$temp/out" 2>/dev/null >&2; exit 1; }
sql() { local db="$1"; shift; psql -X -q -A -t -v ON_ERROR_STOP=1 "$db" -c "$1"; }

[ "$(sql "$src" 'SELECT current_database()')" != "$(sql "$dst" 'SELECT current_database()')" ] \
  || fail "source and restore target must be different databases"
[ "$(sql "$dst" "SELECT count(*) FROM pg_class WHERE relnamespace = 'public'::regnamespace")" = 0 ] \
  || fail "restore target must be empty"
evidence_cas="$(sql "$src" 'SELECT count(*) FROM evidence_cas()')"
[ "$evidence_cas" -ge 2 ] || fail "source has $evidence_cas CAs with evidence (run after the signed tests)"

# One login per role (test-only password, lab only), as in the other jobs.
for role in trust_audit_sealer trust_audit_verifier; do
  sql "$src" "SET client_min_messages = warning;
              DO \$\$BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${role}_ci') THEN
                  CREATE ROLE ${role}_ci LOGIN PASSWORD 'test-only-not-secret';
                END IF;
              END\$\$;
              GRANT ${role} TO ${role}_ci" >/dev/null
done
login_url() { # <database url> <login>
  python3 - "$1" "$2" <<'PY'
import sys, urllib.parse
u = urllib.parse.urlsplit(sys.argv[1])
host = u.hostname + (f":{u.port}" if u.port else "")
print(urllib.parse.urlunsplit((u.scheme, f"{sys.argv[2]}:test-only-not-secret@{host}",
                               u.path, u.query, u.fragment)))
PY
}
cargo build -q --locked -p trust-pki-core --features postgres-store,lab-software --example audit_chain_anchor
cargo build -q --locked -p trust-management-api --bin signed_evidence_audit
anchor_bin="target/debug/examples/audit_chain_anchor"
audit_bin="target/debug/signed_evidence_audit"
anchor() { # <database url> <role> <args...>
  local db="$1" role="$2"; shift 2
  TRUST_DATABASE_TLS=disable-lab TRUST_DATABASE_URL="$(login_url "$db" "${role}_ci")" "$anchor_bin" "$@"
}
expect_status() { # <expected> <what> <command...>
  local expected="$1" what="$2"; shift 2
  set +e; "$@" >"$temp/out" 2>&1; local status=$?; set -e
  [ "$status" = "$expected" ] || fail "$what: exit $status, expected $expected"
}
evidence_audit() { # <database url> <output file>; prints the exit status
  set +e
  TRUST_DATABASE_TLS=disable-lab TRUST_DATABASE_URL="$(login_url "$1" trust_audit_verifier_ci)" \
  TRUST_WEBAUTHN_RP_ID=officer.lab.invalid TRUST_WEBAUTHN_ORIGIN=https://officer.lab.invalid \
    "$audit_bin" --all >"$2" 2>/dev/null
  local status=$?
  set -e
  echo "$status"
}
fingerprint() { psql -X -q -A -t -v ON_ERROR_STOP=1 "$1" -f tests/revocation_restore_fingerprint.sql; }

# Before the backup: seal, export a checkpoint, record the evidence audit.
expect_status 0 "seal the source" anchor "$src" trust_audit_sealer seal
expect_status 0 "anchor the source" anchor "$src" trust_audit_verifier verify "$temp/checkpoints"
[ "$(wc -l <"$temp/checkpoints")" = 1 ] || fail "no checkpoint exported"
source_audit_status="$(evidence_audit "$src" "$temp/source-audit")"
[ "$source_audit_status" = 3 ] || fail "source evidence audit exit $source_audit_status, expected 3"
fingerprint "$src" >"$temp/source.fp"
source_schema_changes="$(sql "$src" 'SELECT unreviewed_schema_changes()')"

"$dump_bin" --format=custom --file="$temp/revocation.dump" "$src"
test -s "$temp/revocation.dump"
# Owners and ACLs are kept: the SECURITY DEFINER functions run as their
# owner roles, and the capability roles hold only their grants.
"$restore_bin" --single-transaction --exit-on-error --dbname="$dst" "$temp/revocation.dump" >/dev/null

fingerprint "$dst" >"$temp/restored.fp"
if ! diff "$temp/source.fp" "$temp/restored.fp" >"$temp/out"; then
  fail "restored database differs from the source (rows, sequences, owners, ACLs or triggers)"
fi
psql -X -q -v ON_ERROR_STOP=1 "$dst" -f tests/revocation_privileges.sql >/dev/null 2>"$temp/out" \
  || fail "privilege invariants do not hold on the restored database"
[ "$(sql "$dst" 'SELECT unreviewed_schema_changes()')" = "$source_schema_changes" ] \
  || fail "the restore logged schema changes of its own"
restored_audit_status="$(evidence_audit "$dst" "$temp/restored-audit")"
[ "$restored_audit_status" = "$source_audit_status" ] \
  || fail "restored evidence audit exit $restored_audit_status, source $source_audit_status"
diff "$temp/source-audit" "$temp/restored-audit" >"$temp/out" \
  || fail "restored evidence audit differs from the source"

# The restored chain verifies against the checkpoint taken before the backup.
cp "$temp/checkpoints" "$temp/restored-checkpoints"
expect_status 0 "restored chain against the pre-backup checkpoint" \
  anchor "$dst" trust_audit_verifier verify "$temp/restored-checkpoints"
cmp -s "$temp/checkpoints" "$temp/restored-checkpoints" || fail "checkpoint appended without new entries"

# The source moves on; the backup is now stale and the later checkpoint
# refuses it (a restore would silently lose those records otherwise).
sql "$src" "INSERT INTO audit_event(event_id, actor_id, event_type, decision)
            VALUES (gen_random_uuid(), 'restore-test', 'audit.restore.probe', 'after-backup')" >/dev/null
expect_status 0 "seal the source again" anchor "$src" trust_audit_sealer seal
expect_status 0 "anchor the source again" anchor "$src" trust_audit_verifier verify "$temp/checkpoints"
[ "$(wc -l <"$temp/checkpoints")" = 2 ] || fail "second checkpoint missing"
expect_status 3 "stale backup against a later checkpoint" \
  anchor "$dst" trust_audit_verifier verify "$temp/checkpoints"
grep -q "Truncated" "$temp/out" || fail "stale backup not reported as truncated"

# The restored store keeps working: a new record is sealed and anchored.
sql "$dst" "INSERT INTO audit_event(event_id, actor_id, event_type, decision)
            VALUES (gen_random_uuid(), 'restore-test', 'audit.restore.probe', 'after-restore')" >/dev/null
expect_status 0 "seal the restored database" anchor "$dst" trust_audit_sealer seal
expect_status 0 "anchor the restored database" anchor "$dst" trust_audit_verifier verify "$temp/restored-checkpoints"
[ "$(wc -l <"$temp/restored-checkpoints")" = 2 ] || fail "restored database did not extend its checkpoint"

echo "PASS: populated revocation database restored with rows, privileges, evidence ($evidence_cas CAs) and audit chain intact; stale backup refused"
