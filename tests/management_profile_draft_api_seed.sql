-- Disposable, inert proposals for the scoped API pagination contract.
INSERT INTO certificate_profile_draft
  (ca_id, profile_id, revision, display_name, policy_version,
   max_validity_days, max_dns_sans, proposed_dns_zones,
   proposed_signature_suites, created_by)
SELECT 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
       'server-' || lpad(n::text, 3, '0'), 1,
       'Synthetic server proposal ' || n, 'v1', 90, 5,
       ARRAY['lab.invalid'], ARRAY['P256-SHA256'], 'synthetic-editor'
FROM generate_series(1, 102) AS n;

INSERT INTO certificate_profile_draft
  (ca_id, profile_id, revision, display_name, policy_version,
   max_validity_days, max_dns_sans, proposed_dns_zones,
   proposed_signature_suites, created_by)
VALUES ('ffffffff-ffff-4fff-8fff-ffffffffffff', 'hidden-server', 1,
        'Hidden proposal', 'v1', 90, 5, ARRAY['hidden.lab.invalid'],
        ARRAY['P256-SHA256'], 'synthetic-editor');
