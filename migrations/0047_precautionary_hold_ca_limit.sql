-- v0.47 (lab): per-CA cap on open precautionary holds (ADR-0007 §6,
-- Proposed). LAB ONLY.
-- 0038 capped one officer's open holds, but several officers (or several
-- stolen authenticators) still added up: N officers could suspend N times
-- the per-officer limit before anyone confirmed anything.
-- * ca_revocation_policy.precautionary_hold_ca_limit (1..1000, default 10):
--   how many precautionary holds may be open on the CA at once, all
--   officers together. "Open" is as in 0038 and precautionary_holds: the
--   revocation row is still the hold's (no dual-controlled revocation or
--   release followed it).
-- * guard_precautionary_hold_limit now serialises on one per-CA advisory
--   lock (instead of one per officer) and checks both caps, so concurrent
--   holds by different officers cannot all pass the CA count.
-- Apply after 0046 as a superuser.
BEGIN;

ALTER TABLE ca_revocation_policy
    ADD COLUMN precautionary_hold_ca_limit SMALLINT NOT NULL DEFAULT 10
        CHECK (precautionary_hold_ca_limit BETWEEN 1 AND 1000);

CREATE OR REPLACE FUNCTION guard_precautionary_hold_limit() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
DECLARE
    v_limit SMALLINT;
    v_ca_limit SMALLINT;
    v_open BIGINT;
    v_open_ca BIGINT;
BEGIN
    IF NEW.confirm_by IS NULL THEN
        RETURN NEW;
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('precautionary_hold:' || NEW.ca_id, 0));
    SELECT precautionary_hold_limit, precautionary_hold_ca_limit
    INTO v_limit, v_ca_limit
    FROM ca_revocation_policy WHERE ca_id = NEW.ca_id;
    SELECT count(*),
           count(*) FILTER (WHERE (s.maker_issuer, s.maker_subject)
                                  = (NEW.maker_issuer, NEW.maker_subject))
    INTO v_open_ca, v_open
    FROM certificate_status_change s
    JOIN revocation r ON r.change_id = s.change_id AND r.reason_code = 6
    WHERE s.ca_id = NEW.ca_id AND s.confirm_by IS NOT NULL;
    IF v_open >= coalesce(v_limit, 1) THEN
        RAISE EXCEPTION 'precautionary hold limit reached for this officer (% open)', v_open
          USING ERRCODE = '23514';
    END IF;
    IF v_open_ca >= coalesce(v_ca_limit, 1) THEN
        RAISE EXCEPTION 'precautionary hold limit reached for this CA (% open)', v_open_ca
          USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $fn$;
ALTER FUNCTION guard_precautionary_hold_limit() SET search_path = pg_catalog, public, pg_temp;

SELECT acknowledge_schema_changes('0047_precautionary_hold_ca_limit');

COMMIT;
