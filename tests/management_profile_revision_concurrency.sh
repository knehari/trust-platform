#!/usr/bin/env bash
set -euo pipefail

# Run only on a disposable, migrated database; the committed test rows remain.
: "${TRUST_PROFILE_SEQUENCE_DATABASE_URL:?set a disposable PostgreSQL database URL}"
psql_bin=${TRUST_PSQL_BIN:-psql}
database_url=$TRUST_PROFILE_SEQUENCE_DATABASE_URL
ca_id=55555555-5555-4555-8555-555555555555

"$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 -c \
  "INSERT INTO ca(ca_id,display_name,policy_version) VALUES ('$ca_id','Concurrent draft CA','v1')" >/dev/null

logs=$(mktemp -d "${TMPDIR:-/tmp}/trust-profile-sequence.XXXXXX")
trap 'rm -rf "$logs"' EXIT

PGAPPNAME=trust_revision_writer_a "$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 >"$logs/writer-a" 2>&1 <<SQL &
BEGIN;
INSERT INTO certificate_profile_draft
  (ca_id,profile_id,revision,display_name,policy_version,max_validity_days,
   max_dns_sans,proposed_dns_zones,proposed_signature_suites,created_by)
VALUES ('$ca_id','concurrent-server',1,'First','v1',90,5,
        ARRAY['lab.invalid'],ARRAY['P256-SHA256'],'synthetic-editor');
SELECT pg_sleep(3);
COMMIT;
SQL
writer_a=$!

ready=0
for _ in $(seq 1 100); do
  active=$("$psql_bin" "$database_url" -XAt -v ON_ERROR_STOP=1 -c \
    "SELECT count(*) FROM pg_stat_activity WHERE application_name='trust_revision_writer_a' AND state='active' AND query LIKE 'SELECT pg_sleep%'")
  if [[ "$active" == 1 ]]; then ready=1; break; fi
  sleep 0.02
done
if [[ "$ready" != 1 ]]; then
  wait "$writer_a" || true
  cat "$logs/writer-a" >&2
  echo 'First writer did not reach the held transaction' >&2
  exit 1
fi

# The second writer waits for the CA lock, then sees the committed revision 1.
"$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 -c \
  "INSERT INTO certificate_profile_draft (ca_id,profile_id,revision,display_name,policy_version,max_validity_days,max_dns_sans,proposed_dns_zones,proposed_signature_suites,created_by) VALUES ('$ca_id','concurrent-server',2,'Second','v1',90,5,ARRAY['lab.invalid'],ARRAY['P256-SHA256'],'synthetic-editor')" >"$logs/writer-b" 2>&1
wait "$writer_a"
count=$("$psql_bin" "$database_url" -XAt -v ON_ERROR_STOP=1 -c \
  "SELECT count(*) FROM certificate_profile_draft WHERE ca_id='$ca_id' AND profile_id='concurrent-server'")
test "$count" = 2
echo 'PASS: concurrent profile revisions serialize without a gap'
