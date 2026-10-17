#!/bin/sh
set -eu

# Runs only on a fresh disposable PostgreSQL volume. Migrations fail fast.
migrations_dir=${TRUST_MIGRATIONS_DIR:-/lab/migrations}
for migration in "$migrations_dir"/*.sql; do
  echo "Applying $(basename "$migration")"
  psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -f "$migration"
done

psql -v ON_ERROR_STOP=1 -v api_password="$TRUST_LAB_API_PASSWORD" \
  -U "$POSTGRES_USER" -d "$POSTGRES_DB" <<'SQL'
SELECT format('CREATE ROLE trust_api_lab LOGIN INHERIT PASSWORD %L', :'api_password') \gexec
GRANT trust_api_reader TO trust_api_lab;
INSERT INTO ca(ca_id,display_name,policy_version) VALUES
  ('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','Allowed laboratory CA','v1'),
  ('ffffffff-ffff-4fff-8fff-ffffffffffff','Hidden laboratory CA','v1');
SQL
