#!/bin/sh
set -eu

# Runs after the shared demo seed, only on a new IAM-lab PostgreSQL volume.
psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" <<'SQL'
INSERT INTO management_reader_grant(issuer,subject,ca_id) VALUES
  ('http://127.0.0.1:8180/realms/trust-lab',
   'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
   'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'),
  ('http://127.0.0.1:8180/realms/trust-lab',
   'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
   'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee');
SQL
