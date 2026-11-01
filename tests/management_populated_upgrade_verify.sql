-- Verify pre-existing rows survived the management migrations and their
-- projections remain deliberately narrower than the underlying tables: fewer
-- columns, and since 0021 only the rows of CAs granted to the declared reader.
DO $test$ BEGIN
    IF (SELECT count(*) FROM ca) <> 2 OR
       (SELECT count(*) FROM certificate_request) <> 1 OR
       (SELECT count(*) FROM serial_reservation) <> 1 OR
       (SELECT count(*) FROM certificate) <> 1 OR
       (SELECT count(*) FROM audit_event) <> 1 THEN
        RAISE EXCEPTION 'pre-existing management rows changed during upgrade';
    END IF;

    -- 0021: without a declared reader principal the views show nothing.
    IF EXISTS (SELECT 1 FROM management_ca) OR EXISTS (SELECT 1 FROM management_certificate)
       OR EXISTS (SELECT 1 FROM management_audit) OR EXISTS (SELECT 1 FROM management_reader_scope)
       OR EXISTS (SELECT 1 FROM management_certificate_san)
       OR EXISTS (SELECT 1 FROM management_history_bounds) THEN
        RAISE EXCEPTION 'management views return rows without a declared reader principal';
    END IF;
END $test$;

-- Grant the fixture's first CA to one principal and declare it, as the API
-- does from a verified token (0021).
INSERT INTO management_reader_grant (issuer, subject, ca_id) VALUES (
    'https://issuer.example.test', 'upgrade-operator',
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'
) ON CONFLICT DO NOTHING;
SELECT set_config('trust.reader_issuer', 'https://issuer.example.test', false),
       set_config('trust.reader_subject', 'upgrade-operator', false);

DO $test$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM management_ca
        WHERE ca_id = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'
          AND display_name = 'Existing Lab CA' AND policy_version = 'v1'
    ) OR (SELECT count(*) FROM management_ca) <> 1 THEN
        RAISE EXCEPTION 'management CA view did not project exactly the granted CA';
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

    -- 0017: the window columns are the same instant as the text times, at
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

    -- 0018: the SAN table holds exactly the lowered, distinct names of each
    -- certificate's array, with the certificate's CA and time.
    IF EXISTS (
        (SELECT request_id, ca_id, signed_at, name_lower FROM certificate_san_dns
         EXCEPT
         SELECT DISTINCT c.request_id, c.ca_id, c.signed_at, lower(e.name)
         FROM certificate c, unnest(c.san_dns) AS e(name) WHERE e.name IS NOT NULL)
        UNION ALL
        (SELECT DISTINCT c.request_id, c.ca_id, c.signed_at, lower(e.name)
         FROM certificate c, unnest(c.san_dns) AS e(name) WHERE e.name IS NOT NULL
         EXCEPT
         SELECT request_id, ca_id, signed_at, name_lower FROM certificate_san_dns)
    ) THEN
        RAISE EXCEPTION 'certificate_san_dns differs from certificate.san_dns';
    END IF;

    -- 0019: the stored lowered CN is lower(subject_cn) on every row.
    IF EXISTS (
        SELECT 1 FROM certificate WHERE subject_cn_lower IS DISTINCT FROM lower(subject_cn)
    ) THEN
        RAISE EXCEPTION 'subject_cn_lower differs from lower(subject_cn)';
    END IF;

    -- 0020: the bounds are each authority's first and last row times.
    IF EXISTS (
        SELECT 1 FROM management_history_bounds b JOIN ca ON ca.ca_id::text = b.ca_id
        WHERE b.newest_signed_window IS DISTINCT FROM
              (SELECT max(date_trunc('milliseconds', c.signed_at AT TIME ZONE 'UTC')) FROM certificate c WHERE c.ca_id = ca.ca_id)
           OR b.oldest_signed_window IS DISTINCT FROM
              (SELECT min(date_trunc('milliseconds', c.signed_at AT TIME ZONE 'UTC')) FROM certificate c WHERE c.ca_id = ca.ca_id)
           OR b.newest_recorded_window IS DISTINCT FROM
              (SELECT max(date_trunc('milliseconds', a.recorded_at AT TIME ZONE 'UTC')) FROM audit_event a WHERE a.ca_id = ca.ca_id)
           OR b.oldest_recorded_window IS DISTINCT FROM
              (SELECT min(date_trunc('milliseconds', a.recorded_at AT TIME ZONE 'UTC')) FROM audit_event a WHERE a.ca_id = ca.ca_id)
    ) OR (SELECT count(*) FROM management_history_bounds) <> 1 THEN
        RAISE EXCEPTION 'management_history_bounds differs from the authorities'' rows';
    END IF;

    IF (SELECT count(*) FROM management_reader_scope) <> 1 OR NOT EXISTS (
        SELECT 1 FROM management_reader_scope
        WHERE issuer = 'https://issuer.example.test'
          AND subject = 'upgrade-operator'
          AND ca_id = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'
    ) THEN
        RAISE EXCEPTION 'new management grant projection is not exact';
    END IF;
END $test$;

-- A principal without grants, or the same subject under another issuer,
-- sees nothing.
SELECT set_config('trust.reader_issuer', 'https://other-issuer.example.test', false);
DO $test$ BEGIN
    IF EXISTS (SELECT 1 FROM management_ca) OR EXISTS (SELECT 1 FROM management_certificate)
       OR EXISTS (SELECT 1 FROM management_audit) OR EXISTS (SELECT 1 FROM management_reader_scope) THEN
        RAISE EXCEPTION 'management views leak rows to a principal without grants';
    END IF;
END $test$;
SELECT set_config('trust.reader_issuer', '', false), set_config('trust.reader_subject', '', false);
