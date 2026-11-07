-- Grants and public keys for the API decision test (migration 0023). The keys are
-- the public halves of the deterministic test scalars [0x11; 32], [0x22; 32] and
-- [0x33; 32] in crates/management-api/src/main.rs; no private key is stored here.
-- "operator" authors and submits the test revisions, so its approver grant must
-- not let it decide on them.
INSERT INTO management_role_grant(issuer,subject,ca_id,lifecycle_role) VALUES
  ('https://issuer.example.test','operator','eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','policy-approver'),
  ('https://issuer.example.test','approver-http-1','eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','policy-approver'),
  ('https://issuer.example.test','approver-http-2','eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','policy-approver');
INSERT INTO profile_approver_key(key_id,issuer,subject,public_key_sec1) VALUES
  ('approver-http-1-p256','https://issuer.example.test','approver-http-1',decode('040217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed194a7debcb97712d2dda3ca85aa8765a56f45fc758599652f2897c65306e5794','hex')),
  ('approver-http-2-p256','https://issuer.example.test','approver-http-2',decode('04d65a93977caa3d1b081852ff57a79e465f1660577304baead505dd3a48589cf350185e895372df6221ea3a137557e473fddb6755f05bd507c3c533fce9c91285','hex')),
  ('operator-p256','https://issuer.example.test','operator',decode('0451a7580833898ea1b183cbd7350a4099078c6ef1c1e18e970cd7683035f25e7d0110522712b0b5a7cff081685486984a94e6831edac46e7360fa9d834a7a81a1','hex'));
-- Activation test (migration 0024): an independent operator, and the
-- signing capabilities declared for CA E. "p256-sha256" is declared but is
-- not a catalogue identifier, so the API must refuse to activate it.
INSERT INTO management_role_grant(issuer,subject,ca_id,lifecycle_role) VALUES
  ('https://issuer.example.test','operator-http','eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','ca-operator');
INSERT INTO ca_signing_capability(ca_id,suite_id) VALUES
  ('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','ecdsa-p256-sha256'),
  ('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','p256-sha256');
-- CA proposals (migration 0025): one platform administrator.
INSERT INTO management_platform_grant(issuer,subject,platform_role) VALUES
  ('https://issuer.example.test','ca-admin-http','ca-administrator');
