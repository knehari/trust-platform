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
INSERT INTO management_reader_grant(issuer,subject,ca_id) VALUES
  ('http://127.0.0.1:8080','lab-operator','eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'),
  ('https://other-issuer.example.test','lab-operator','ffffffff-ffff-4fff-8fff-ffffffffffff');
-- Inert profile proposals; no revision can authorize issuance.
INSERT INTO certificate_profile_draft
  (ca_id,profile_id,revision,display_name,policy_version,max_validity_days,
   max_dns_sans,proposed_dns_zones,proposed_signature_suites,created_by) VALUES
  ('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','server-lab',1,'Laboratory server proposal','v1',90,5,ARRAY['lab.invalid'],ARRAY['P256-SHA256'],'synthetic-editor'),
  ('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','server-lab',2,'Laboratory server proposal','v2',60,3,ARRAY['lab.invalid','apps.lab.invalid'],ARRAY['P256-SHA256'],'synthetic-editor'),
  ('ffffffff-ffff-4fff-8fff-ffffffffffff','hidden-lab',1,'Hidden laboratory proposal','v1',90,5,ARRAY['hidden.lab.invalid'],ARRAY['P256-SHA256'],'synthetic-editor');
-- Synthetic metadata only: 3000 is a schema sentinel, not a signed X.509 certificate.
-- These CNs are display fixtures, not claims parsed from certificate DER.
INSERT INTO certificate_request(request_id,ca_id,idempotency_key,csr_sha256,requester_id,policy_version,state) VALUES
  ('11111111-1111-4111-8111-000000000001','eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','compose-allowed',decode(repeat('01',32),'hex'),'compose-fixture','v1','SIGNED'),
  ('11111111-1111-4111-8111-000000000002','ffffffff-ffff-4fff-8fff-ffffffffffff','compose-hidden',decode(repeat('01',32),'hex'),'compose-fixture','v1','SIGNED');
INSERT INTO serial_reservation(ca_id,serial_der_content,request_id) VALUES
  ('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',decode('010001','hex'),'11111111-1111-4111-8111-000000000001'),
  ('ffffffff-ffff-4fff-8fff-ffffffffffff',decode('010002','hex'),'11111111-1111-4111-8111-000000000002');
INSERT INTO certificate(ca_id,serial_der_content,request_id,fingerprint_sha256,certificate_der,signed_at,subject_cn) VALUES
  ('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',decode('010001','hex'),'11111111-1111-4111-8111-000000000001',decode(repeat('02',32),'hex'),decode('3000','hex'),'2026-10-01T12:00:00Z','compose-allowed.lab.invalid'),
  ('ffffffff-ffff-4fff-8fff-ffffffffffff',decode('010002','hex'),'11111111-1111-4111-8111-000000000002',decode(repeat('03',32),'hex'),decode('3000','hex'),'2026-10-01T12:00:00Z','compose-hidden.lab.invalid');
INSERT INTO audit_event(event_id,ca_id,actor_id,event_type,decision,policy_version,recorded_at) VALUES
  ('33333333-3333-4333-8333-000000000001','eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','private-compose-actor','certificate.signed','allow','v1','2026-10-01T12:00:00Z'),
  ('33333333-3333-4333-8333-000000000002','ffffffff-ffff-4fff-8fff-ffffffffffff','hidden-compose-actor','certificate.signed','allow','v1','2026-10-01T12:00:00Z');
SQL
