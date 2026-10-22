#!/bin/sh
set -eu

# Runs only on a fresh disposable PostgreSQL volume. Migrations fail fast.
migrations_dir=${TRUST_MIGRATIONS_DIR:-/lab/migrations}
for migration in "$migrations_dir"/*.sql; do
  echo "Applying $(basename "$migration")"
  psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -f "$migration"
done

# One login per capability for the scheduled lab jobs (compose service
# "jobs"): CRL housekeeping, the offline evidence audit and audit chain
# verification, and audit chain sealing. None is a superuser or an owner
# role member; the jobs refuse such logins.
psql -v ON_ERROR_STOP=1 -v api_password="$TRUST_LAB_API_PASSWORD" \
  -v housekeeping_password="$TRUST_LAB_HOUSEKEEPING_PASSWORD" \
  -v auditor_password="$TRUST_LAB_AUDITOR_PASSWORD" \
  -v sealer_password="$TRUST_LAB_SEALER_PASSWORD" \
  -U "$POSTGRES_USER" -d "$POSTGRES_DB" <<'SQL'
SELECT format('CREATE ROLE trust_api_lab LOGIN INHERIT PASSWORD %L', :'api_password') \gexec
GRANT trust_api_reader TO trust_api_lab;
SELECT format('CREATE ROLE trust_housekeeping_lab LOGIN INHERIT PASSWORD %L', :'housekeeping_password') \gexec
GRANT trust_crl_operator TO trust_housekeeping_lab;
SELECT format('CREATE ROLE trust_auditor_lab LOGIN INHERIT PASSWORD %L', :'auditor_password') \gexec
GRANT trust_audit_verifier TO trust_auditor_lab;
SELECT format('CREATE ROLE trust_sealer_lab LOGIN INHERIT PASSWORD %L', :'sealer_password') \gexec
GRANT trust_audit_sealer TO trust_sealer_lab;
INSERT INTO ca(ca_id,display_name,policy_version) VALUES
  ('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','Allowed laboratory CA','v1'),
  ('ffffffff-ffff-4fff-8fff-ffffffffffff','Hidden laboratory CA','v1');
INSERT INTO management_reader_grant(issuer,subject,ca_id) VALUES
  ('http://127.0.0.1:8080','lab-operator','eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'),
  ('https://other-issuer.example.test','lab-operator','ffffffff-ffff-4fff-8fff-ffffffffffff');
-- These logins are the reviewed lab provisioning: acknowledge them, so the
-- housekeeping job alerts only on later role changes (migration 0057).
SELECT acknowledge_role_state('lab-init');
SQL
