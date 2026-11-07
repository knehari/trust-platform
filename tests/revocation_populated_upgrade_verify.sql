-- Verify pre-existing rows survived 0014 and 0015 and that the new lifecycle
-- and CRL functions work on the upgraded data. The reservation is a probe:
-- the transaction is rolled back.
BEGIN;
DO $test$
DECLARE
    v_number BIGINT;
    v_expired TIMESTAMPTZ;
    v_digest BYTEA;
BEGIN
    IF (SELECT count(*) FROM ca) <> 2 OR
       (SELECT count(*) FROM certificate_request) <> 2 OR
       (SELECT count(*) FROM serial_reservation) <> 2 OR
       (SELECT count(*) FROM certificate) <> 2 OR
       (SELECT count(*) FROM audit_event) <> 1 OR
       (SELECT count(*) FROM revocation) <> 1 OR
       (SELECT count(*) FROM crl_publication) <> 0 THEN
        RAISE EXCEPTION 'pre-existing rows changed during the 0014/0015 upgrade';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM revocation
        WHERE ca_id = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'
          AND serial_der_content = '\x01' AND reason_code = 1
          AND revoked_at = '2026-10-03T12:00:00Z'
          AND invalidity_at = '2026-10-02T00:00:00Z'
          AND actor_id = 'legacy-officer' AND change_id IS NULL
    ) THEN
        RAISE EXCEPTION 'legacy revocation row was not preserved verbatim';
    END IF;

    IF certificate_status('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', '\x01') <> 'REVOKED'
       OR certificate_status('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', '\x02') <> 'VALID' THEN
        RAISE EXCEPTION 'certificate_status disagrees with the upgraded rows';
    END IF;

    -- The legacy row is now under the irreversibility guard.
    BEGIN
        DELETE FROM revocation
        WHERE ca_id = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'
          AND serial_der_content = '\x01';
        RAISE EXCEPTION 'legacy definitive revocation could be deleted';
    EXCEPTION WHEN check_violation THEN NULL;
    END;

    -- No policy row: defaults (RFC5280, no ExpiredCertsOnCRL), number 1, and
    -- the snapshot freezes the legacy row with the canonical entry digest.
    SELECT r.crl_number, r.expired_certs_on_crl_since INTO v_number, v_expired
    FROM reserve_crl('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
                     'upgrade-probe', 'upgrade-probe-1') r;
    IF v_number <> 1 OR v_expired IS NOT NULL THEN
        RAISE EXCEPTION 'reserve_crl on upgraded CA returned % / %', v_number, v_expired;
    END IF;
    IF (SELECT count(*) FROM crl_snapshot_entries(
            'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', 1)) <> 1 THEN
        RAISE EXCEPTION 'CRL snapshot does not hold exactly the legacy revocation';
    END IF;
    SELECT sha256(crl_entry_encoding('\x01', '2026-10-03T12:00:00Z', 1::SMALLINT,
                                     '2026-10-02T00:00:00Z'))
    INTO v_digest;
    IF (SELECT entries_sha256 FROM crl_publication
        WHERE ca_id = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee' AND crl_number = 1)
       <> v_digest THEN
        RAISE EXCEPTION 'reservation digest does not cover the legacy revocation';
    END IF;
END $test$;
ROLLBACK;
