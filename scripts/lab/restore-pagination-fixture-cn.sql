-- Disposable 102-row pagination fixture only. The DER sentinel 3000 has no
-- X.509 subject; these names are synthetic UI samples, not verified CNs.
-- Apply migration 0014 first. Never run against a real certificate database.
BEGIN;
DO $fixture$
DECLARE fixture_count INTEGER;
BEGIN
    SELECT count(*) INTO fixture_count FROM certificate
    WHERE ca_id='eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
    IF fixture_count <> 102 OR EXISTS (
        SELECT 1 FROM certificate
        WHERE ca_id='eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'
          AND (certificate_der <> decode('3000','hex')
               OR request_id::text NOT LIKE '11111111-1111-4111-8111-%'
               OR encode(serial_der_content,'hex') NOT LIKE '01____')
    ) THEN
        RAISE EXCEPTION 'not the disposable 102-row pagination fixture';
    END IF;

    UPDATE certificate
    SET subject_cn='paged-' || right(encode(serial_der_content,'hex'),4) || '.lab.invalid'
    WHERE ca_id='eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee' AND subject_cn IS NULL;
END
$fixture$;
COMMIT;
