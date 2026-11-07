#!/usr/bin/env bash
set -euo pipefail

# The URL must name an empty disposable PostgreSQL database.
: "${TRUST_PROFILE_GAP_DATABASE_URL:?set an empty disposable PostgreSQL database URL}"
psql_bin=${TRUST_PSQL_BIN:-psql}
database_url=$TRUST_PROFILE_GAP_DATABASE_URL

for migration in migrations/000*.sql migrations/0010*.sql migrations/0011*.sql \
  migrations/0012*.sql migrations/0013*.sql migrations/0014*.sql \
  migrations/0015*.sql migrations/0016*.sql migrations/0017*.sql \
  migrations/0018*.sql migrations/0019*.sql migrations/0020*.sql migrations/0021*.sql; do
  "$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 -f "$migration" >/dev/null
done

"$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
INSERT INTO ca(ca_id,display_name,policy_version)
VALUES ('44444444-4444-4444-8444-444444444444','Gap fixture','v1');
INSERT INTO certificate_profile_draft
  (ca_id,profile_id,revision,display_name,policy_version,max_validity_days,
   max_dns_sans,proposed_dns_zones,proposed_signature_suites,created_by)
VALUES ('44444444-4444-4444-8444-444444444444','gap-lab',2,'Gap','v1',
        90,5,ARRAY['lab.invalid'],ARRAY['P256-SHA256'],'synthetic-editor');
SQL

if output=$("$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
    -f migrations/0022_profile_draft_revision_sequence.sql 2>&1); then
  echo 'Migration 0022 accepted a pre-existing revision gap' >&2
  exit 1
fi
if [[ "$output" != *'existing profile draft revision sequence has gaps'* ]]; then
  echo "$output" >&2
  exit 1
fi
present=$("$psql_bin" "$database_url" -XAt -v ON_ERROR_STOP=1 \
  -c "SELECT to_regprocedure('public.enforce_profile_draft_revision_sequence()') IS NOT NULL")
test "$present" = f
echo 'PASS: migration 0022 refuses a gapped populated schema and rolls back'
