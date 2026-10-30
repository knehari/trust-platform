-- v0.60 (lab): re-apply revocations from the last published CRL after a
-- restore from an older backup. LAB ONLY.
-- A database restored from a backup older than the last published CRL has
-- lost every status change made since: a certificate revoked since then
-- reads VALID again and leaves the next CRL. The external audit checkpoint
-- detects the rollback (tests/revocation_backup_restore.sh) and 0058 keeps
-- CRL numbers from being reused; nothing put the revocations back.
-- The last published CRL is signed evidence of those decisions. The Rust
-- tool (crl_restore_revocations) verifies it against the CA's registered
-- issuer certificate and passes its entries here; the database cannot check
-- ECDSA, so only a superuser may call this (no grant, like 0058).
-- * crl_restore: append-only; the CRL bytes, digest, number and who
--   restored them, kept as evidence of every run.
-- * restore_revocations_from_crl(ca, number, crl_der, serials, reasons,
--   revoked_at, invalidity_at, reason) under the CA row lock. Refuses a CRL
--   not newer than the database's latest stored complete CRL (an old CRL
--   would re-apply holds released since). Per certificate:
--   RESTORED          no revocation here: inserted with the CRL's date and
--                     reason (actor crl-restore:<number>, no status change);
--   UPGRADED          on hold here, definitive on the CRL: reason changed,
--                     original date kept (the hold-to-definitive rule);
--   PRESENT           same reason here;
--   CONFLICT          definitive here with another reason, or definitive
--                     here and on hold on the CRL: nothing changes
--                     (definitive revocations are irreversible);
--   UNKNOWN_CERTIFICATE  the certificate is not in this database (issued
--                     after the backup): nothing can be written, it must be
--                     handled by hand;
--   HOLD_NOT_ON_CRL   on hold here but not on the CRL, perhaps released
--                     since: kept on hold, a release needs dual control.
--   It raises the CRL number floor to the CRL's number when lower and
--   writes a revocation.restored_from_crl audit event with the counts.
-- Apply after 0059 as a superuser.
BEGIN;

CREATE TABLE crl_restore (
    restore_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ca_id UUID NOT NULL REFERENCES ca(ca_id),
    crl_number BIGINT NOT NULL CHECK (crl_number BETWEEN 1 AND 9223372036854775805),
    crl_der BYTEA NOT NULL CHECK (octet_length(crl_der) > 0),
    crl_sha256 BYTEA NOT NULL CHECK (octet_length(crl_sha256) = 32),
    reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 500),
    restored_by TEXT NOT NULL DEFAULT session_user,
    restored_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK (crl_sha256 = sha256(crl_der))
);
ALTER TABLE crl_restore OWNER TO trust_revocation_owner;
REVOKE ALL ON crl_restore FROM PUBLIC;

CREATE FUNCTION guard_crl_restore() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    RAISE EXCEPTION 'crl_restore is append-only' USING ERRCODE = '23514';
END $fn$;
ALTER FUNCTION guard_crl_restore() OWNER TO trust_revocation_owner;
ALTER FUNCTION guard_crl_restore() SET search_path = pg_catalog, public, pg_temp;
REVOKE ALL ON FUNCTION guard_crl_restore() FROM PUBLIC;
CREATE TRIGGER crl_restore_append_only
    BEFORE UPDATE OR DELETE ON crl_restore
    FOR EACH ROW EXECUTE FUNCTION guard_crl_restore();
CREATE TRIGGER crl_restore_no_truncate
    BEFORE TRUNCATE ON crl_restore
    FOR EACH STATEMENT EXECUTE FUNCTION guard_crl_restore();

CREATE FUNCTION restore_revocations_from_crl(
    p_ca UUID, p_crl_number BIGINT, p_crl_der BYTEA, p_serials BYTEA[],
    p_reasons SMALLINT[], p_revoked_at BIGINT[], p_invalidity_at BIGINT[], p_reason TEXT)
RETURNS TABLE(serial_der_content BYTEA, outcome TEXT)
LANGUAGE plpgsql AS $fn$
#variable_conflict use_column
DECLARE
    v_n INT := cardinality(p_serials);
    v_latest BIGINT;
    v_floor BIGINT;
    v_actor TEXT := 'crl-restore:' || p_crl_number;
    v_existing SMALLINT;
    v_outcome TEXT;
    v_counts JSONB := '{}'::jsonb;
    i INT;
BEGIN
    IF p_ca IS NULL OR p_crl_number IS NULL OR p_crl_der IS NULL OR p_reason IS NULL
       OR p_serials IS NULL OR p_reasons IS NULL OR p_revoked_at IS NULL OR p_invalidity_at IS NULL
       OR p_crl_number NOT BETWEEN 1 AND 9223372036854775805
       OR octet_length(p_crl_der) = 0
       OR length(p_reason) NOT BETWEEN 1 AND 500
       OR cardinality(p_reasons) <> v_n OR cardinality(p_revoked_at) <> v_n
       OR cardinality(p_invalidity_at) <> v_n
       OR EXISTS (SELECT 1 FROM unnest(p_serials) s WHERE s IS NULL
                  OR octet_length(s) NOT BETWEEN 1 AND 20)
       OR (SELECT count(DISTINCT s) FROM unnest(p_serials) s) <> v_n
       OR EXISTS (SELECT 1 FROM unnest(p_reasons) r
                  WHERE r IS NULL OR r NOT IN (0,1,2,3,4,5,6,9,10))
       OR EXISTS (SELECT 1 FROM unnest(p_revoked_at) t
                  WHERE t IS NULL OR t NOT BETWEEN 0 AND 253402300799)
       OR EXISTS (SELECT 1 FROM unnest(p_invalidity_at) t
                  WHERE t IS NOT NULL AND t NOT BETWEEN 0 AND 253402300799)
    THEN
        RAISE EXCEPTION 'invalid CRL restore input' USING ERRCODE = '22023';
    END IF;
    PERFORM 1 FROM public.ca c WHERE c.ca_id = p_ca FOR NO KEY UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown CA' USING ERRCODE = '22023';
    END IF;
    SELECT max(cp.crl_number) INTO v_latest FROM public.crl_publication cp
    WHERE cp.ca_id = p_ca AND cp.status = 'STORED' AND cp.base_crl_number IS NULL;
    IF p_crl_number <= COALESCE(v_latest, 0) THEN
        RAISE EXCEPTION 'CRL % is not newer than the latest stored CRL % of this CA',
            p_crl_number, v_latest USING ERRCODE = '23514';
    END IF;

    INSERT INTO public.crl_restore (ca_id, crl_number, crl_der, crl_sha256, reason)
    VALUES (p_ca, p_crl_number, p_crl_der, sha256(p_crl_der), p_reason);

    FOR i IN 1 .. COALESCE(v_n, 0) LOOP
        IF NOT EXISTS (SELECT 1 FROM public.certificate c
                       WHERE c.ca_id = p_ca AND c.serial_der_content = p_serials[i]) THEN
            v_outcome := 'UNKNOWN_CERTIFICATE';
        ELSE
            SELECT r.reason_code INTO v_existing FROM public.revocation r
            WHERE r.ca_id = p_ca AND r.serial_der_content = p_serials[i] FOR UPDATE;
            IF NOT FOUND THEN
                INSERT INTO public.revocation (ca_id, serial_der_content, reason_code, revoked_at,
                                               invalidity_at, actor_id, change_id)
                VALUES (p_ca, p_serials[i], p_reasons[i], to_timestamp(p_revoked_at[i]),
                        to_timestamp(p_invalidity_at[i]), v_actor, NULL);
                v_outcome := 'RESTORED';
            ELSIF v_existing = p_reasons[i] THEN
                v_outcome := 'PRESENT';
            ELSIF v_existing = 6 THEN
                UPDATE public.revocation r
                SET reason_code = p_reasons[i], invalidity_at = to_timestamp(p_invalidity_at[i]),
                    actor_id = v_actor, change_id = NULL
                WHERE r.ca_id = p_ca AND r.serial_der_content = p_serials[i];
                v_outcome := 'UPGRADED';
            ELSE
                v_outcome := 'CONFLICT';
            END IF;
        END IF;
        v_counts := jsonb_set(v_counts, ARRAY[v_outcome],
                              to_jsonb(COALESCE((v_counts ->> v_outcome)::int, 0) + 1));
        serial_der_content := p_serials[i];
        outcome := v_outcome;
        RETURN NEXT;
    END LOOP;

    FOR serial_der_content IN
        SELECT r.serial_der_content FROM public.revocation r
        WHERE r.ca_id = p_ca AND r.reason_code = 6
          AND r.serial_der_content <> ALL (p_serials)
        ORDER BY r.serial_der_content
    LOOP
        outcome := 'HOLD_NOT_ON_CRL';
        v_counts := jsonb_set(v_counts, ARRAY[outcome],
                              to_jsonb(COALESCE((v_counts ->> outcome)::int, 0) + 1));
        RETURN NEXT;
    END LOOP;

    SELECT GREATEST(COALESCE((SELECT max(cp.crl_number) FROM public.crl_publication cp
                              WHERE cp.ca_id = p_ca), 0),
                    COALESCE((SELECT max(f.floor) FROM public.crl_number_floor f
                              WHERE f.ca_id = p_ca), 0))
    INTO v_floor;
    IF p_crl_number > v_floor THEN
        PERFORM public.raise_crl_number_floor(p_ca, p_crl_number, left(p_reason, 500));
    END IF;

    INSERT INTO public.audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), p_ca, NULL, session_user, 'revocation.restored_from_crl',
            'CRL:' || p_crl_number
            || ':restored=' || COALESCE(v_counts ->> 'RESTORED', '0')
            || ':upgraded=' || COALESCE(v_counts ->> 'UPGRADED', '0')
            || ':conflict=' || COALESCE(v_counts ->> 'CONFLICT', '0')
            || ':hold_not_on_crl=' || COALESCE(v_counts ->> 'HOLD_NOT_ON_CRL', '0')
            || ':unknown=' || COALESCE(v_counts ->> 'UNKNOWN_CERTIFICATE', '0'));
END $fn$;
ALTER FUNCTION restore_revocations_from_crl(uuid, bigint, bytea, bytea[], smallint[], bigint[],
                                            bigint[], text)
    SET search_path = pg_catalog, public, pg_temp;
REVOKE ALL ON FUNCTION restore_revocations_from_crl(uuid, bigint, bytea, bytea[], smallint[],
                                                    bigint[], bigint[], text) FROM PUBLIC;

SELECT acknowledge_schema_changes('0060_revocation_restore_from_crl');

COMMIT;
