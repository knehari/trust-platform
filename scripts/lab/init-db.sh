#!/bin/sh
set -eu

# Runs only on a fresh disposable PostgreSQL volume. Migrations fail fast.
migrations_dir=${TRUST_MIGRATIONS_DIR:-/lab/migrations}
for migration in "$migrations_dir"/*.sql; do
  echo "Applying $(basename "$migration")"
  psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -f "$migration"
done

psql -v ON_ERROR_STOP=1 -v api_password="$TRUST_LAB_API_PASSWORD" -v writer_password="$TRUST_LAB_WRITER_PASSWORD" \
  -v approver1_sec1="$TRUST_LAB_APPROVER_1_SEC1" -v approver2_sec1="$TRUST_LAB_APPROVER_2_SEC1" \
  -U "$POSTGRES_USER" -d "$POSTGRES_DB" <<'SQL'
SELECT format('CREATE ROLE trust_api_lab LOGIN INHERIT PASSWORD %L', :'api_password') \gexec
GRANT trust_api_reader TO trust_api_lab;
-- A separate login for profile writes (migration 0022): it can only execute
-- the two lifecycle functions, and holds no table or view privilege.
SELECT format('CREATE ROLE trust_api_writer_lab LOGIN INHERIT PASSWORD %L', :'writer_password') \gexec
GRANT trust_profile_writer TO trust_api_writer_lab;
INSERT INTO ca(ca_id,display_name,policy_version) VALUES
  ('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','Allowed laboratory CA','v1'),
  ('ffffffff-ffff-4fff-8fff-ffffffffffff','Hidden laboratory CA','v1');
-- Reader grants for the laboratory Keycloak realm (scripts/lab/keycloak). The
-- subjects are the realm's fixed user IDs. Grants never confer a role: the
-- API also requires trust-ca-reader in the token and the CA in its scope.
-- Grants that must NOT authorize anything:
--   * lab-editor, lab-outsider and lab-disabled are granted CA E, but have no
--     reader role or cannot sign in;
--   * lab-other-ca's token names CA F, which is granted to nobody under this
--     issuer;
--   * the foreign realm's reader is granted CA E under its own issuer, which
--     the API does not trust;
--   * the workload's service account is granted CA E, but its tokens are not
--     issued to the console client.
INSERT INTO management_reader_grant(issuer,subject,ca_id) VALUES
  ('http://127.0.0.1:8080/realms/trust-lab','7c1a0000-0000-4000-8000-000000000001','eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'),
  ('http://127.0.0.1:8080/realms/trust-lab','7c1a0000-0000-4000-8000-000000000002','eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'),
  ('http://127.0.0.1:8080/realms/trust-lab','7c1a0000-0000-4000-8000-000000000003','eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'),
  ('http://127.0.0.1:8080/realms/trust-lab','7c1a0000-0000-4000-8000-000000000004','eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'),
  ('http://127.0.0.1:8080/realms/trust-lab','7c1a0000-0000-4000-8000-000000000005','eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'),
  ('http://127.0.0.1:8080/realms/trust-lab','7c1a0000-0000-4000-8000-000000000006','eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'),
  ('http://127.0.0.1:8080/realms/trust-lab','7c1a0000-0000-4000-8000-000000000007','eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'),
  ('http://127.0.0.1:8080/realms/trust-lab','7c1a0000-0000-4000-8000-000000000009','eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'),
  ('http://127.0.0.1:8080/realms/trust-lab-foreign','7c1a0000-0000-4000-8000-000000000010','eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'),
  ('http://127.0.0.1:8080/realms/trust-lab','7c1a0000-0000-4000-8000-000000000011','eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee');
-- Lifecycle role grants (migrations 0022–0024). lab-author (reader and
-- editor) and lab-editor (editor only) may record and submit drafts for CA E;
-- lab-approver-1 and lab-approver-2 may decide on them, and lab-operator may
-- activate and retire them. Nobody holds a grant for CA F.
INSERT INTO management_role_grant(issuer,subject,ca_id,lifecycle_role) VALUES
  ('http://127.0.0.1:8080/realms/trust-lab','7c1a0000-0000-4000-8000-000000000011','eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','profile-editor'),
  ('http://127.0.0.1:8080/realms/trust-lab','7c1a0000-0000-4000-8000-000000000002','eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','profile-editor'),
  ('http://127.0.0.1:8080/realms/trust-lab','7c1a0000-0000-4000-8000-000000000003','eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','policy-approver'),
  ('http://127.0.0.1:8080/realms/trust-lab','7c1a0000-0000-4000-8000-000000000004','eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','policy-approver'),
  ('http://127.0.0.1:8080/realms/trust-lab','7c1a0000-0000-4000-8000-000000000005','eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','ca-operator');
-- CA proposals (migration 0025): lab-ca-admin may propose CAs and register
-- their issuer certificates. A proposal is not a CA and issues nothing.
INSERT INTO management_platform_grant(issuer,subject,platform_role) VALUES
  ('http://127.0.0.1:8080/realms/trust-lab','7c1a0000-0000-4000-8000-000000000012','ca-administrator');
-- Signing capabilities the owner declares for the allowed CA (migration
-- 0024). A declaration is not evidence that a provider or key can issue.
INSERT INTO ca_signing_capability(ca_id,suite_id) VALUES
  ('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','ecdsa-p256-sha256');
-- Approver keys (migration 0023): the public halves of the keys init-env.sh
-- generated into .lab-keys/. The private keys never reach the database.
INSERT INTO profile_approver_key(key_id,issuer,subject,public_key_sec1) VALUES
  ('lab-approver-1-p256','http://127.0.0.1:8080/realms/trust-lab','7c1a0000-0000-4000-8000-000000000003',decode(:'approver1_sec1','hex')),
  ('lab-approver-2-p256','http://127.0.0.1:8080/realms/trust-lab','7c1a0000-0000-4000-8000-000000000004',decode(:'approver2_sec1','hex'));
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
