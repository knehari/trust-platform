-- v0.38 (lab): per-officer cap on open precautionary holds (ADR-0007 §6,
-- Proposed; implemented in lab at the owner's request). LAB ONLY.
-- 0036 let one signed officer hold any number of certificates as a
-- precaution: a stolen authenticator (or a careless officer) could suspend
-- a whole CA's population before anyone confirmed anything.
-- * ca_revocation_policy.precautionary_hold_limit (1..100, default 3): how
--   many precautionary holds one officer may have open on the CA at once.
--   A hold stops counting once a dual-controlled revocation or release
--   follows it (the same "open" as precautionary_holds).
-- * Enforced on the row apply_precautionary_hold inserts, under a
--   per-(CA, officer) transaction advisory lock so two concurrent holds by
--   one officer cannot both pass the count.
-- Apply after 0037 as a superuser.
BEGIN;

ALTER TABLE ca_revocation_policy
    ADD COLUMN precautionary_hold_limit SMALLINT NOT NULL DEFAULT 3
        CHECK (precautionary_hold_limit BETWEEN 1 AND 100);

CREATE FUNCTION guard_precautionary_hold_limit() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
DECLARE
    v_limit SMALLINT;
    v_open BIGINT;
BEGIN
    IF NEW.confirm_by IS NULL THEN
        RETURN NEW;
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'precautionary_hold:' || NEW.ca_id || ':' || NEW.maker_issuer || '|' || NEW.maker_subject, 0));
    SELECT precautionary_hold_limit INTO v_limit FROM ca_revocation_policy
    WHERE ca_id = NEW.ca_id;
    SELECT count(*) INTO v_open
    FROM certificate_status_change s
    JOIN revocation r ON r.change_id = s.change_id AND r.reason_code = 6
    WHERE s.ca_id = NEW.ca_id AND s.confirm_by IS NOT NULL
      AND (s.maker_issuer, s.maker_subject) = (NEW.maker_issuer, NEW.maker_subject);
    IF v_open >= coalesce(v_limit, 1) THEN
        RAISE EXCEPTION 'precautionary hold limit reached for this officer (% open)', v_open
          USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $fn$;
ALTER FUNCTION guard_precautionary_hold_limit() OWNER TO trust_revocation_owner;
ALTER FUNCTION guard_precautionary_hold_limit() SET search_path = pg_catalog, public, pg_temp;
REVOKE ALL ON FUNCTION guard_precautionary_hold_limit() FROM PUBLIC;
CREATE TRIGGER certificate_status_change_precaution_limit
    BEFORE INSERT ON certificate_status_change
    FOR EACH ROW EXECUTE FUNCTION guard_precautionary_hold_limit();

SELECT acknowledge_schema_changes('0038_precautionary_hold_limit');

COMMIT;
