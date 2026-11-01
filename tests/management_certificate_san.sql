-- Migration 0018: the SAN table follows certificate.san_dns through every
-- write, and the API role reads it only through its security-barrier view.
-- Run as the migration owner after 0018 on a disposable database; every
-- change is rolled back.
BEGIN;

INSERT INTO ca (ca_id, display_name, policy_version) VALUES
    ('5a5a5a5a-0000-4000-8000-00000000005a', 'SAN Lab CA', 'v1');
INSERT INTO certificate_request (request_id, ca_id, idempotency_key, csr_sha256, requester_id, policy_version, state)
VALUES ('5a5a5a5a-0000-4000-8000-000000000001', '5a5a5a5a-0000-4000-8000-00000000005a', 'san-1',
        decode(repeat('01', 32), 'hex'), 'san-test', 'v1', 'SIGNED');
INSERT INTO serial_reservation (ca_id, serial_der_content, request_id)
VALUES ('5a5a5a5a-0000-4000-8000-00000000005a', decode('7001', 'hex'), '5a5a5a5a-0000-4000-8000-000000000001');

-- Insert without SANs (a historical row), then with SANs: case variants
-- collapse to one lowered row and a NULL element is ignored.
INSERT INTO certificate (ca_id, serial_der_content, request_id, fingerprint_sha256, certificate_der, signed_at)
VALUES ('5a5a5a5a-0000-4000-8000-00000000005a', decode('7001', 'hex'), '5a5a5a5a-0000-4000-8000-000000000001',
        decode(repeat('02', 32), 'hex'), decode('3000', 'hex'), '2026-01-01T00:00:00Z');
DO $test$ BEGIN
    IF EXISTS (SELECT 1 FROM certificate_san_dns WHERE request_id = '5a5a5a5a-0000-4000-8000-000000000001') THEN
        RAISE EXCEPTION 'a certificate without SANs has SAN rows';
    END IF;
END $test$;

UPDATE certificate SET not_before_utc = '2026-01-01T00:00:00Z', not_after_utc = '2027-01-01T00:00:00Z',
       san_dns = ARRAY['A.Lab.Invalid', 'a.lab.invalid', 'b.lab.invalid', NULL]
WHERE request_id = '5a5a5a5a-0000-4000-8000-000000000001';
DO $test$ BEGIN
    IF (SELECT array_agg(name_lower ORDER BY name_lower) FROM certificate_san_dns
        WHERE request_id = '5a5a5a5a-0000-4000-8000-000000000001') IS DISTINCT FROM
       ARRAY['a.lab.invalid', 'b.lab.invalid'] THEN
        RAISE EXCEPTION 'SAN rows are not the distinct lowered names';
    END IF;
END $test$;

-- A new array replaces the rows; a new signing time is copied.
UPDATE certificate SET san_dns = ARRAY['c.lab.invalid'], signed_at = '2026-02-01T00:00:00Z'
WHERE request_id = '5a5a5a5a-0000-4000-8000-000000000001';
DO $test$ BEGIN
    IF (SELECT array_agg(name_lower || '@' || signed_at::text) FROM certificate_san_dns
        WHERE request_id = '5a5a5a5a-0000-4000-8000-000000000001') IS DISTINCT FROM
       ARRAY['c.lab.invalid@' || '2026-02-01T00:00:00Z'::timestamptz::text] THEN
        RAISE EXCEPTION 'SAN rows did not follow the updated array and time';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM management_certificate_san s JOIN management_certificate c USING (ca_id, request_id)
        WHERE s.request_id = '5a5a5a5a-0000-4000-8000-000000000001'
          AND s.signed_at = c.signed_at AND s.signed_at_window = c.signed_at_window
          AND s.san_dns = 'c.lab.invalid'
    ) THEN
        RAISE EXCEPTION 'SAN view time differs from management_certificate';
    END IF;
END $test$;

-- The API role reads the view, not the table, and cannot write either.
SET LOCAL ROLE trust_api_reader;
DO $test$ BEGIN
    PERFORM count(*) FROM management_certificate_san;
    BEGIN
        PERFORM count(*) FROM certificate_san_dns;
        RAISE EXCEPTION 'API role unexpectedly reads the SAN table';
    EXCEPTION WHEN insufficient_privilege THEN NULL;
    END;
    BEGIN
        INSERT INTO certificate_san_dns VALUES
            ('5a5a5a5a-0000-4000-8000-000000000001', '5a5a5a5a-0000-4000-8000-00000000005a', now(), 'forged.lab.invalid');
        RAISE EXCEPTION 'API role unexpectedly writes the SAN table';
    EXCEPTION WHEN insufficient_privilege THEN NULL;
    END;
END $test$;
RESET ROLE;

-- Removing the certificate removes its SAN rows.
DELETE FROM certificate WHERE request_id = '5a5a5a5a-0000-4000-8000-000000000001';
DO $test$ BEGIN
    IF EXISTS (SELECT 1 FROM certificate_san_dns WHERE request_id = '5a5a5a5a-0000-4000-8000-000000000001') THEN
        RAISE EXCEPTION 'SAN rows outlived their certificate';
    END IF;
END $test$;

ROLLBACK;
\echo 'PASS: certificate_san_dns follows certificate.san_dns and stays behind its view'
