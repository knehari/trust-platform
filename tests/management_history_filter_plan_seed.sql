-- Extend only the disposable 102-certificate pagination fixture for query plans.
-- DER and subject names are synthetic; no certificate issuance is exercised.
DO $seed$ BEGIN
  IF (SELECT count(*) FROM certificate
      WHERE ca_id = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee') <> 102 THEN
    RAISE EXCEPTION 'query-plan seed requires the untouched 102-row pagination fixture';
  END IF;
END $seed$;

INSERT INTO certificate_request
    (request_id, ca_id, idempotency_key, csr_sha256, requester_id, policy_version, state)
SELECT ('55555555-5555-4555-8555-' || lpad(to_hex(n), 12, '0'))::uuid,
       'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', 'plan-' || n,
       decode(repeat('01', 32), 'hex'), 'query-plan-fixture', 'v1', 'SIGNED'
FROM generate_series(1000, 10999) AS n;

INSERT INTO serial_reservation (ca_id, serial_der_content, request_id)
SELECT 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
       decode('02' || lpad(to_hex(n), 4, '0'), 'hex'),
       ('55555555-5555-4555-8555-' || lpad(to_hex(n), 12, '0'))::uuid
FROM generate_series(1000, 10999) AS n;

INSERT INTO certificate
    (ca_id, serial_der_content, request_id, fingerprint_sha256,
     certificate_der, signed_at, subject_cn)
SELECT 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
       decode('02' || lpad(to_hex(n), 4, '0'), 'hex'),
       ('55555555-5555-4555-8555-' || lpad(to_hex(n), 12, '0'))::uuid,
       decode(repeat('02', 32), 'hex'), decode('3000', 'hex'),
       '2026-10-02T00:00:00Z'::timestamptz + n * interval '1 second',
       'plan-' || n || '.lab.invalid'
FROM generate_series(1000, 10999) AS n;

UPDATE certificate SET
    not_before_utc = '2026-10-01T00:00:00Z',
    not_after_utc = '2027-10-01T00:00:00Z',
    san_dns = ARRAY['plan-sample.lab.invalid']
WHERE request_id IN (
    SELECT ('55555555-5555-4555-8555-' || lpad(to_hex(n), 12, '0'))::uuid
    FROM generate_series(1000, 10999, 1000) AS n
);

ANALYZE certificate_request;
ANALYZE certificate;
