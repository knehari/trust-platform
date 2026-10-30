-- Verify pre-existing rows survived both management migrations and their
-- projections remain deliberately narrower than the underlying tables.
DO $test$ BEGIN
    IF (SELECT count(*) FROM ca) <> 2 OR
       (SELECT count(*) FROM certificate_request) <> 1 OR
       (SELECT count(*) FROM serial_reservation) <> 1 OR
       (SELECT count(*) FROM certificate) <> 1 OR
       (SELECT count(*) FROM audit_event) <> 1 THEN
        RAISE EXCEPTION 'pre-existing management rows changed during upgrade';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM management_ca
        WHERE ca_id = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'
          AND display_name = 'Existing Lab CA' AND policy_version = 'v1'
    ) OR (SELECT count(*) FROM management_ca) <> 2 THEN
        RAISE EXCEPTION 'management CA view did not project both existing CAs';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM management_certificate
        WHERE ca_id = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'
          AND serial_hex = '01' AND fingerprint_sha256 = repeat('02', 32)
          AND request_id = '11111111-1111-4111-8111-111111111111'
          AND state = 'SIGNED' AND subject_cn IS NULL
          AND not_before IS NULL AND not_after IS NULL AND san_dns IS NULL
    ) OR (SELECT count(*) FROM management_certificate) <> 1 OR
       (SELECT certificate_der FROM certificate) <> decode('3000', 'hex') THEN
        RAISE EXCEPTION 'existing certificate or management projection changed';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM management_audit
        WHERE event_id = '33333333-3333-4333-8333-333333333333'
          AND event_type = 'certificate.signed' AND decision = 'allow'
    ) OR (SELECT count(*) FROM management_audit) <> 1 OR
       (SELECT actor_id FROM audit_event) <> 'existing-private-actor' THEN
        RAISE EXCEPTION 'existing audit event or management projection changed';
    END IF;

    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'management_certificate'
          AND column_name = 'certificate_der'
    ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'management_audit'
          AND column_name = 'actor_id'
    ) THEN
        RAISE EXCEPTION 'management view exposes protected raw fields';
    END IF;

    -- 0016: the window columns are the same instant as the text times, at
    -- the same millisecond precision, so slicing on them cannot reorder or
    -- drop rows relative to the text cursor.
    IF EXISTS (
        SELECT 1 FROM management_certificate
        WHERE to_char(signed_at_window, 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') IS DISTINCT FROM signed_at
    ) OR EXISTS (
        SELECT 1 FROM management_audit
        WHERE to_char(recorded_at_window, 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') IS DISTINCT FROM recorded_at
    ) THEN
        RAISE EXCEPTION 'management window column differs from the text time';
    END IF;
END $test$;

INSERT INTO management_reader_grant (issuer, subject, ca_id) VALUES (
    'https://issuer.example.test', 'upgrade-operator',
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'
);

DO $test$ BEGIN
    IF (SELECT count(*) FROM management_reader_scope) <> 1 OR NOT EXISTS (
        SELECT 1 FROM management_reader_scope
        WHERE issuer = 'https://issuer.example.test'
          AND subject = 'upgrade-operator'
          AND ca_id = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'
    ) THEN
        RAISE EXCEPTION 'new management grant projection is not exact';
    END IF;
END $test$;
