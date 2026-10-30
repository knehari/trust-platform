-- Add 102 scoped CA metadata rows to the disposable history pagination database.
-- The history fixture's eeeeeeee CA remains outside the token used by this test.
INSERT INTO ca (ca_id, display_name, policy_version)
SELECT ('55555555-5555-4555-8555-' || lpad(to_hex(n), 12, '0'))::uuid,
       'Same name lab CA', 'v1'
FROM generate_series(1, 102) AS n;

INSERT INTO management_reader_grant (issuer, subject, ca_id)
SELECT 'https://issuer.example.test', 'ca-page-operator',
       ('55555555-5555-4555-8555-' || lpad(to_hex(n), 12, '0'))::uuid
FROM generate_series(1, 102) AS n;
