-- Migration 0046: hardening of the RA channel (ADR-0039, Proposed).
--
-- Until now an enabled RA system with a granted profile could:
-- - submit as many signed issuance and revocation requests as it wanted:
--   a stolen RA key could mass-issue within the profile, or mass-revoke what
--   the RA obtained, as fast as the API answered;
-- - ask for any name the profile's zones allow, even when the RA serves only
--   part of them;
-- - sign requests up to five minutes in the future, which lets a captured
--   request stay usable for up to ten minutes.
--
-- The owner now sets, per RA, an issuance and a revocation quota per rolling
-- hour, and optionally the DNS zones the RA may ask for (within the
-- profile's). Without a policy row the defaults apply: 100 issuances and 20
-- revocations per hour, the profile's zones. Signatures dated more than 30
-- seconds ahead of the database clock are refused.
--
-- The checks run in BEFORE INSERT triggers on the recorded requests, inside
-- the submission's transaction: a refusal rolls the whole submission back,
-- and a replay of the same signed bytes (which inserts nothing) never
-- consumes quota. Errors: TP429 quota exceeded; 42501 a name outside the
-- RA's zones; TP422 a signature dated in the future.
BEGIN;

CREATE TABLE ra_system_policy (
    ra_id TEXT PRIMARY KEY REFERENCES ra_system (ra_id),
    max_issuance_per_hour INTEGER NOT NULL CHECK (max_issuance_per_hour BETWEEN 0 AND 100000),
    max_revocation_per_hour INTEGER NOT NULL CHECK (max_revocation_per_hour BETWEEN 0 AND 100000),
    -- NULL: the profile's zones. Otherwise the RA may ask only for names in
    -- these zones (and the profile's rules still apply).
    allowed_dns_zones TEXT[] CHECK (allowed_dns_zones IS NULL OR (
        cardinality(allowed_dns_zones) BETWEEN 1 AND 100
        AND array_position(allowed_dns_zones, NULL) IS NULL)),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON ra_system_policy FROM PUBLIC;
CREATE FUNCTION ra_system_policy_zones_valid() RETURNS TRIGGER
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $fn$
BEGIN
    IF NEW.allowed_dns_zones IS NOT NULL AND EXISTS (
        SELECT 1 FROM unnest(NEW.allowed_dns_zones) z
        WHERE z !~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$'
           OR length(z) > 253) THEN
        RAISE EXCEPTION 'allowed_dns_zones holds an invalid zone' USING ERRCODE = '22023';
    END IF;
    NEW.updated_at := clock_timestamp();
    RETURN NEW;
END
$fn$;
CREATE TRIGGER ra_system_policy_zones_valid
    BEFORE INSERT OR UPDATE ON ra_system_policy
    FOR EACH ROW EXECUTE FUNCTION ra_system_policy_zones_valid();

-- The effective policy of an RA: its row, or the defaults.
CREATE FUNCTION ra_effective_policy(p_ra TEXT)
RETURNS TABLE (max_issuance_per_hour INTEGER, max_revocation_per_hour INTEGER, allowed_dns_zones TEXT[])
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $fn$
    SELECT coalesce(p.max_issuance_per_hour, 100), coalesce(p.max_revocation_per_hour, 20), p.allowed_dns_zones
    FROM (SELECT p_ra AS ra_id) r LEFT JOIN ra_system_policy p ON p.ra_id = r.ra_id
$fn$;
REVOKE ALL ON FUNCTION ra_effective_policy(TEXT) FROM PUBLIC;

-- How far ahead of the database clock a request may be dated.
CREATE FUNCTION ra_signed_in_future(p_signed_at TIMESTAMPTZ) RETURNS BOOLEAN
LANGUAGE sql STABLE SET search_path = pg_catalog AS $fn$
    SELECT p_signed_at > clock_timestamp() + interval '30 seconds'
$fn$;
REVOKE ALL ON FUNCTION ra_signed_in_future(TIMESTAMPTZ) FROM PUBLIC;

CREATE FUNCTION enforce_ra_issuance_policy() RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_policy RECORD;
    v_outside TEXT[];
BEGIN
    IF ra_signed_in_future(NEW.signed_at) THEN
        RAISE EXCEPTION 'the request is dated in the future' USING ERRCODE = 'TP422';
    END IF;
    SELECT * INTO v_policy FROM ra_effective_policy(NEW.ra_id);
    -- One RA's submissions are counted one at a time.
    PERFORM pg_advisory_xact_lock(hashtextextended('ra-quota:' || NEW.ra_id, 0));
    IF (SELECT count(*) FROM ra_issuance_request q
        WHERE q.ra_id = NEW.ra_id AND q.recorded_at > clock_timestamp() - interval '1 hour')
       >= v_policy.max_issuance_per_hour THEN
        RAISE EXCEPTION 'the RA issuance quota is exhausted for this hour' USING ERRCODE = 'TP429';
    END IF;
    IF v_policy.allowed_dns_zones IS NOT NULL THEN
        SELECT array_agg(n) INTO v_outside
        FROM certificate_application a, unnest(a.dns_names) n
        WHERE a.application_id = NEW.application_id
          AND NOT EXISTS (SELECT 1 FROM unnest(v_policy.allowed_dns_zones) z WHERE certificate_name_in_zone(n, z));
        IF v_outside IS NOT NULL THEN
            RAISE EXCEPTION 'DNS names outside the RA''s zones: %', v_outside USING ERRCODE = '42501';
        END IF;
    END IF;
    RETURN NEW;
END
$fn$;
REVOKE ALL ON FUNCTION enforce_ra_issuance_policy() FROM PUBLIC;
CREATE TRIGGER enforce_ra_issuance_policy
    BEFORE INSERT ON ra_issuance_request
    FOR EACH ROW EXECUTE FUNCTION enforce_ra_issuance_policy();

CREATE FUNCTION enforce_ra_revocation_policy() RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
BEGIN
    IF ra_signed_in_future(NEW.signed_at) THEN
        RAISE EXCEPTION 'the request is dated in the future' USING ERRCODE = 'TP422';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('ra-quota:' || NEW.ra_id, 0));
    IF (SELECT count(*) FROM ra_revocation_request q
        WHERE q.ra_id = NEW.ra_id AND q.recorded_at > clock_timestamp() - interval '1 hour')
       >= (SELECT max_revocation_per_hour FROM ra_effective_policy(NEW.ra_id)) THEN
        RAISE EXCEPTION 'the RA revocation quota is exhausted for this hour' USING ERRCODE = 'TP429';
    END IF;
    RETURN NEW;
END
$fn$;
REVOKE ALL ON FUNCTION enforce_ra_revocation_policy() FROM PUBLIC;
CREATE TRIGGER enforce_ra_revocation_policy
    BEFORE INSERT ON ra_revocation_request
    FOR EACH ROW EXECUTE FUNCTION enforce_ra_revocation_policy();

-- Counting the last hour stays an index range scan per RA.
CREATE INDEX ra_issuance_request_recent ON ra_issuance_request (ra_id, recorded_at);
CREATE INDEX ra_revocation_request_recent ON ra_revocation_request (ra_id, recorded_at);

CREATE FUNCTION management_ra_hardening_version() RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $fn$ SELECT 1 $fn$;
REVOKE ALL ON FUNCTION management_ra_hardening_version() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION management_ra_hardening_version() TO trust_api_reader, trust_profile_writer;

COMMIT;
