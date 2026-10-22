-- v0.55 (lab): backfill certificate.not_after for certificates stored
-- before 0031, so expired-entry pruning can cover them. LAB ONLY.
-- 0031 records not_after at issuance; older rows have NULL and were never
-- pruned (follow-up "no backfill"). The database cannot parse DER, so the
-- Rust core reads notAfter from the stored certificate and records it:
-- * certificates_without_not_after(ca, limit): serial and stored DER of the
--   CA's certificates whose not_after is NULL (1..1000 at a time).
-- * record_certificate_not_after(ca, serial, not_after): sets it only where
--   it is still NULL (false otherwise), within the CHECK bounds, with an
--   audit event. guard_certificate_not_after now allows exactly this
--   NULL -> value transition, and only inside that function (a
--   transaction-local flag it sets and clears); a direct UPDATE is still
--   refused and a set value never changes.
-- A wrong value cannot shorten a CRL silently: before a pruned entry is
-- left out, crl::check_pruned_entry re-reads notAfter from the DER (0032).
-- Granted to trust_crl_operator; crl_housekeeping runs the backfill.
-- Apply after 0054 as a superuser.
BEGIN;

CREATE OR REPLACE FUNCTION guard_certificate_not_after() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    IF NEW.not_after IS DISTINCT FROM OLD.not_after
       AND NOT (OLD.not_after IS NULL
                AND coalesce(current_setting('trust.backfill_not_after', true), '') = 'on') THEN
        RAISE EXCEPTION 'certificate not_after is set once, at issuance or by the backfill'
          USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $fn$;
ALTER FUNCTION guard_certificate_not_after() SET search_path = pg_catalog, public, pg_temp;

CREATE FUNCTION certificates_without_not_after(p_ca UUID, p_limit INTEGER)
RETURNS TABLE (serial_der_content BYTEA, certificate_der BYTEA)
LANGUAGE plpgsql STABLE AS $fn$
BEGIN
    IF p_ca IS NULL OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 1000 THEN
        RAISE EXCEPTION 'limit must be 1 to 1000' USING ERRCODE = '22023';
    END IF;
    RETURN QUERY
        SELECT c.serial_der_content, c.certificate_der FROM certificate c
        WHERE c.ca_id = p_ca AND c.not_after IS NULL
        ORDER BY c.serial_der_content
        LIMIT p_limit;
END $fn$;

CREATE FUNCTION record_certificate_not_after(
    p_ca UUID, p_serial BYTEA, p_not_after TIMESTAMPTZ
)
RETURNS BOOLEAN
LANGUAGE plpgsql AS $fn$
DECLARE
    v_rows BIGINT;
BEGIN
    IF p_ca IS NULL OR p_serial IS NULL OR p_not_after IS NULL
       OR p_not_after >= TIMESTAMPTZ '10000-01-01 00:00:00+00' THEN
        RAISE EXCEPTION 'invalid not_after' USING ERRCODE = '22023';
    END IF;
    PERFORM set_config('trust.backfill_not_after', 'on', true);
    UPDATE certificate SET not_after = p_not_after
    WHERE ca_id = p_ca AND serial_der_content = p_serial AND not_after IS NULL;
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    PERFORM set_config('trust.backfill_not_after', 'off', true);
    IF v_rows = 0 THEN
        RETURN false;
    END IF;
    INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), p_ca, NULL, session_user, 'certificate.not_after.backfilled',
            'serial=' || encode(p_serial, 'hex') || ':not_after=' || p_not_after);
    RETURN true;
END $fn$;

DO $fns$
DECLARE
    f TEXT;
BEGIN
    FOREACH f IN ARRAY ARRAY['certificates_without_not_after(uuid,integer)',
                             'record_certificate_not_after(uuid,bytea,timestamptz)'] LOOP
        EXECUTE format('ALTER FUNCTION %s OWNER TO trust_revocation_owner', f);
        EXECUTE format('ALTER FUNCTION %s SECURITY DEFINER', f);
        EXECUTE format('ALTER FUNCTION %s SET search_path = pg_catalog, public, pg_temp', f);
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
        EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO trust_crl_operator', f);
    END LOOP;
END $fns$;

SELECT acknowledge_schema_changes('0055_backfill_certificate_not_after');

COMMIT;
