-- v0.53 (lab): purge challenges that expired unused (ADR-0007 §4,
-- Proposed). LAB ONLY.
-- Status-change and CA-admin challenges were append-only. A consumed one
-- is evidence (the signature rows reference it) and must stay, but one
-- that expired without being answered proves nothing and only grows the
-- table (0049 caps how many one actor holds open, not how many accumulate).
-- * The challenge guards now allow exactly one kind of DELETE: a challenge
--   never consumed whose expiry is more than 7 days past. Consumed or
--   recent challenges still refuse every DELETE, including a superuser's;
--   TRUNCATE is still refused.
-- * purge_expired_challenges(ca, retention_days): deletes the CA's
--   challenges (both tables) that expired unused more than retention_days
--   ago (7..3650), writes one challenge.purged audit event with the count,
--   returns it. Granted to trust_crl_operator; crl_housekeeping runs it
--   with a 30-day retention.
-- Apply after 0052 as a superuser.
BEGIN;

CREATE OR REPLACE FUNCTION guard_status_change_challenge() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    IF TG_OP = 'DELETE' AND OLD.consumed_at IS NULL
       AND OLD.expires_at < clock_timestamp() - interval '7 days' THEN
        RETURN OLD;
    END IF;
    IF TG_OP IN ('DELETE', 'TRUNCATE')
       OR OLD.consumed_at IS NOT NULL OR NEW.consumed_at IS NULL
       OR (NEW.challenge_id, NEW.ca_id, NEW.purpose, NEW.change_id, NEW.serial_der_content,
           NEW.action, NEW.reason_code, NEW.invalidity_at, NEW.actor_issuer,
           NEW.actor_subject, NEW.issuer_certificate_sha256, NEW.policy_edition,
           NEW.challenge_sha256, NEW.issued_at, NEW.expires_at)
          IS DISTINCT FROM
          (OLD.challenge_id, OLD.ca_id, OLD.purpose, OLD.change_id, OLD.serial_der_content,
           OLD.action, OLD.reason_code, OLD.invalidity_at, OLD.actor_issuer,
           OLD.actor_subject, OLD.issuer_certificate_sha256, OLD.policy_edition,
           OLD.challenge_sha256, OLD.issued_at, OLD.expires_at)
    THEN
        RAISE EXCEPTION 'a challenge is consumed once and never changed' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $fn$;
ALTER FUNCTION guard_status_change_challenge() SET search_path = pg_catalog, public, pg_temp;

CREATE OR REPLACE FUNCTION guard_ca_admin_challenge() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    IF TG_OP = 'DELETE' AND OLD.consumed_at IS NULL
       AND OLD.expires_at < clock_timestamp() - interval '7 days' THEN
        RETURN OLD;
    END IF;
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'ca_admin_challenge is append-only' USING ERRCODE = '23514';
    END IF;
    IF OLD.consumed_at IS NOT NULL OR NEW.consumed_at IS NULL
       OR (NEW.challenge_id, NEW.ca_id, NEW.purpose, NEW.family, NEW.kind, NEW.change_id,
           NEW.content_sha256, NEW.actor_issuer, NEW.actor_subject,
           NEW.issuer_certificate_sha256, NEW.policy_edition, NEW.challenge_sha256,
           NEW.issued_at, NEW.expires_at)
          IS DISTINCT FROM
          (OLD.challenge_id, OLD.ca_id, OLD.purpose, OLD.family, OLD.kind, OLD.change_id,
           OLD.content_sha256, OLD.actor_issuer, OLD.actor_subject,
           OLD.issuer_certificate_sha256, OLD.policy_edition, OLD.challenge_sha256,
           OLD.issued_at, OLD.expires_at)
    THEN
        RAISE EXCEPTION 'a challenge is only consumed, once' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $fn$;
ALTER FUNCTION guard_ca_admin_challenge() SET search_path = pg_catalog, public, pg_temp;

CREATE FUNCTION purge_expired_challenges(p_ca UUID, p_retention_days INTEGER)
RETURNS BIGINT
LANGUAGE plpgsql AS $fn$
DECLARE
    v_before TIMESTAMPTZ;
    v_status BIGINT;
    v_admin BIGINT;
BEGIN
    IF p_ca IS NULL OR p_retention_days IS NULL OR p_retention_days NOT BETWEEN 7 AND 3650 THEN
        RAISE EXCEPTION 'retention must be 7 to 3650 days' USING ERRCODE = '22023';
    END IF;
    v_before := clock_timestamp() - make_interval(days => p_retention_days);
    DELETE FROM status_change_challenge
    WHERE ca_id = p_ca AND consumed_at IS NULL AND expires_at < v_before;
    GET DIAGNOSTICS v_status = ROW_COUNT;
    DELETE FROM ca_admin_challenge
    WHERE ca_id = p_ca AND consumed_at IS NULL AND expires_at < v_before;
    GET DIAGNOSTICS v_admin = ROW_COUNT;
    IF v_status + v_admin > 0 THEN
        INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
        VALUES (gen_random_uuid(), p_ca, NULL, session_user, 'challenge.purged',
                'expired_unused:status=' || v_status || ':admin=' || v_admin
                || ':retention_days=' || p_retention_days);
    END IF;
    RETURN v_status + v_admin;
END $fn$;
ALTER FUNCTION purge_expired_challenges(uuid, integer) OWNER TO trust_revocation_owner;
ALTER FUNCTION purge_expired_challenges(uuid, integer) SECURITY DEFINER;
ALTER FUNCTION purge_expired_challenges(uuid, integer)
    SET search_path = pg_catalog, public, pg_temp;
REVOKE ALL ON FUNCTION purge_expired_challenges(uuid, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION purge_expired_challenges(uuid, integer) TO trust_crl_operator;

SELECT acknowledge_schema_changes('0053_purge_expired_challenges');

COMMIT;
