-- v0.49 (lab): cap the open signing challenges of one actor per CA
-- (ADR-0007 §4, Proposed). LAB ONLY.
-- Issuing a challenge writes a row and needs only an officer or admin
-- grant, so one authenticated actor (or a stolen token) could insert rows
-- without bound. Challenges are append-only evidence and are never purged.
-- * guard_open_challenges(): before a status-change or CA-admin challenge
--   is inserted, the actor's unexpired, unconsumed challenges of the same
--   kind on the CA must number fewer than 16, else 23514. Expired or
--   consumed challenges stop counting. Serialised per (table, CA, actor)
--   by a transaction advisory lock, so concurrent issues cannot overshoot.
-- * Partial indexes on the open challenges keep the count cheap.
-- Apply after 0048 as a superuser.
BEGIN;

CREATE INDEX status_change_challenge_open
    ON status_change_challenge (ca_id, actor_issuer, actor_subject)
    WHERE consumed_at IS NULL;
CREATE INDEX ca_admin_challenge_open
    ON ca_admin_challenge (ca_id, actor_issuer, actor_subject)
    WHERE consumed_at IS NULL;

CREATE FUNCTION guard_open_challenges() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
DECLARE
    v_open BIGINT;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'open_challenges:' || TG_TABLE_NAME || ':' || NEW.ca_id || ':'
        || NEW.actor_issuer || '|' || NEW.actor_subject, 0));
    IF TG_TABLE_NAME = 'status_change_challenge' THEN
        SELECT count(*) INTO v_open FROM status_change_challenge
        WHERE ca_id = NEW.ca_id
          AND (actor_issuer, actor_subject) = (NEW.actor_issuer, NEW.actor_subject)
          AND consumed_at IS NULL AND expires_at > clock_timestamp();
    ELSE
        SELECT count(*) INTO v_open FROM ca_admin_challenge
        WHERE ca_id = NEW.ca_id
          AND (actor_issuer, actor_subject) = (NEW.actor_issuer, NEW.actor_subject)
          AND consumed_at IS NULL AND expires_at > clock_timestamp();
    END IF;
    IF v_open >= 16 THEN
        RAISE EXCEPTION 'too many open challenges for this actor on this CA (%)', v_open
          USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $fn$;
ALTER FUNCTION guard_open_challenges() OWNER TO trust_revocation_owner;
ALTER FUNCTION guard_open_challenges() SET search_path = pg_catalog, public, pg_temp;
REVOKE ALL ON FUNCTION guard_open_challenges() FROM PUBLIC;

CREATE TRIGGER status_change_challenge_open_cap
    BEFORE INSERT ON status_change_challenge
    FOR EACH ROW EXECUTE FUNCTION guard_open_challenges();
CREATE TRIGGER ca_admin_challenge_open_cap
    BEFORE INSERT ON ca_admin_challenge
    FOR EACH ROW EXECUTE FUNCTION guard_open_challenges();

SELECT acknowledge_schema_changes('0049_open_challenge_cap');

COMMIT;
