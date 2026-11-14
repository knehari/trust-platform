#!/usr/bin/env bash
# The tamper-evident audit chain (migration 0036, ADR-0022) against the
# database owner. The owner can disable the append-only triggers, so these
# changes succeed; what matters is that lab_verify_audit_chain reports each
# one, and that a chain rebuilt by the owner is caught by a head exported
# earlier, but not without it (the limit the ADR states).
set -euo pipefail

# The URL must name an empty disposable PostgreSQL database; the login must
# own it (it applies every migration).
: "${TRUST_AUDIT_TAMPER_DATABASE_URL:?set an empty disposable PostgreSQL database URL}"
psql_bin=${TRUST_PSQL_BIN:-psql}
verify_bin=${TRUST_AUDIT_VERIFY_BIN:-target/debug/lab_verify_audit_chain}
database_url=$TRUST_AUDIT_TAMPER_DATABASE_URL
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

sql() { "$psql_bin" "$database_url" -XAtq -v ON_ERROR_STOP=1 "$@"; }

for migration in migrations/*.sql; do
  sql -f "$migration" >/dev/null
done

sql <<'SQL'
INSERT INTO ca (ca_id, display_name, policy_version)
VALUES ('7a7a7a7a-0000-4000-8000-00000000000a', 'Tamper fixture', 'v1');
INSERT INTO audit_event (event_id, ca_id, actor_id, event_type, decision, policy_version, recorded_at)
SELECT ('7a7a7a7a-0000-4000-8000-0000000000' || lpad(n::text, 2, '0'))::uuid,
       '7a7a7a7a-0000-4000-8000-00000000000a', 'lab-ra-officer', 'certificate.revoked', 'allow', 'v1',
       timestamptz '2026-11-09T12:00:00Z' + n * interval '1 second'
FROM generate_series(1, 5) AS n;
SELECT sealed FROM seal_audit_events_lab(1000) \g /dev/null
SQL

# verify NAME EXPECTATION [ENV...]: runs the tool, saves its manifest.
verify() {
  local name=$1 expectation=$2
  shift 2
  if env TRUST_VERIFY_DATABASE_URL="$database_url" "$@" "$verify_bin" \
      >"$scratch/$name.json" 2>"$scratch/$name.err"; then
    result=pass
  else
    result=fail
  fi
  if [[ $result != "$expectation" ]]; then
    echo "FAIL: $name: expected $expectation, got $result" >&2
    cat "$scratch/$name.err" >&2
    exit 1
  fi
}
field() { sed -E "s/.*\"$2\":(\"?)([^\",}]*)\1.*/\2/" "$scratch/$1.json"; }

verify clean pass TRUST_AUDIT_REQUIRE_SEALED=1
test "$(field clean head_seq)" = 5
exported="$(field clean head_seq):$(field clean head_hash)"

# An unsealed event is reported, and fails only when sealing is required.
sql -c "INSERT INTO audit_event (event_id, ca_id, actor_id, event_type, decision)
        VALUES ('7a7a7a7a-0000-4000-8000-000000000006', '7a7a7a7a-0000-4000-8000-00000000000a',
                'lab-ra-officer', 'crl.published', 'persisted')"
verify unsealed pass
test "$(field unsealed unsealed_events)" = 1
verify unsealed-required fail TRUST_AUDIT_REQUIRE_SEALED=1
sql -c "SELECT sealed FROM seal_audit_events_lab(1000)" >/dev/null
# The exported head is still part of the longer chain.
verify extended pass TRUST_AUDIT_REQUIRE_SEALED=1 TRUST_AUDIT_EXPECTED_HEAD="$exported"
test "$(field extended head_seq)" = 6

# 1. A sealed event altered in place.
sql <<'SQL'
ALTER TABLE audit_event DISABLE TRIGGER prevent_audit_update;
UPDATE audit_event SET decision = 'deny' WHERE event_id = '7a7a7a7a-0000-4000-8000-000000000002';
SQL
verify altered fail
grep -q 'link 2: the event differs from what was sealed' "$scratch/altered.err"
sql -c "UPDATE audit_event SET decision = 'allow' WHERE event_id = '7a7a7a7a-0000-4000-8000-000000000002'"
verify restored pass TRUST_AUDIT_EXPECTED_HEAD="$exported"

# 2. A link removed from the middle (its event kept).
sql <<'SQL'
ALTER TABLE audit_chain_link DISABLE TRIGGER prevent_audit_chain_update;
CREATE TABLE tamper_saved AS SELECT * FROM audit_chain_link WHERE seq = 3;
DELETE FROM audit_chain_link WHERE seq = 3;
SQL
verify gap fail
grep -q 'expected sequence 3' "$scratch/gap.err"
sql -c "INSERT INTO audit_chain_link SELECT * FROM tamper_saved; DROP TABLE tamper_saved"
verify relinked pass

# 3. A sealed event removed with its link, the later links re-numbered.
sql <<'SQL'
CREATE TABLE tamper_saved AS SELECT * FROM audit_chain_link;
DELETE FROM audit_chain_link WHERE seq = 4;
UPDATE audit_chain_link SET seq = seq - 1 WHERE seq > 4;
SQL
verify renumbered fail
grep -q 'does not name the previous link' "$scratch/renumbered.err"
sql -c "DELETE FROM audit_chain_link; INSERT INTO audit_chain_link SELECT * FROM tamper_saved; DROP TABLE tamper_saved"
verify reverted pass TRUST_AUDIT_EXPECTED_HEAD="$exported"

# 4. The owner alters an event and rebuilds the whole chain consistently:
# the database alone cannot tell, the exported head can.
sql <<'SQL'
DELETE FROM audit_chain_link;
UPDATE audit_event SET actor_id = 'someone-else' WHERE event_id = '7a7a7a7a-0000-4000-8000-000000000001';
SELECT sealed FROM seal_audit_events_lab(1000) \g /dev/null
ALTER TABLE audit_chain_link ENABLE TRIGGER prevent_audit_chain_update;
ALTER TABLE audit_event ENABLE TRIGGER prevent_audit_update;
SQL
verify rebuilt pass TRUST_AUDIT_REQUIRE_SEALED=1
verify rebuilt-against-export fail TRUST_AUDIT_EXPECTED_HEAD="$exported"
grep -q 'differs from the exported head' "$scratch/rebuilt-against-export.err"

# 5. A head that was never exported, or no longer exists, fails.
verify unknown-head fail TRUST_AUDIT_EXPECTED_HEAD="99:$(printf '0%.0s' {1..64})"
grep -q 'no longer in the chain' "$scratch/unknown-head.err"

echo 'PASS: the audit chain tool detects altered, unlinked, removed and rebuilt history (0036)'
