-- v0.52 (lab): CA-admin proposals expire (ADR-0006 and ADR-0007, Proposed).
-- LAB ONLY.
-- An issuer registration, officer grant or credential change could be
-- approved any time after it was proposed: months later, when the person
-- had left or the key was no longer theirs, a checker could still approve
-- exactly the reviewed content.
-- * ca_revocation_policy.admin_proposal_max_age_hours (1..2160, default
--   168): a proposal older than this is no longer approved (23514), in
--   all three families (ca_admin_change, officer_credential_change,
--   ca_admin_credential_change) and on the signed and unsigned paths
--   alike, by a trigger on the PROPOSED -> APPROVED transition. A CA
--   without a policy row uses the default.
-- * Rejection and withdrawal stay possible, so a stale proposal is closed
--   and proposed again rather than left pending.
-- Apply after 0051 as a superuser.
BEGIN;

ALTER TABLE ca_revocation_policy
    ADD COLUMN admin_proposal_max_age_hours SMALLINT NOT NULL DEFAULT 168
        CHECK (admin_proposal_max_age_hours BETWEEN 1 AND 2160);

CREATE FUNCTION guard_admin_proposal_age() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
DECLARE
    v_hours SMALLINT;
BEGIN
    IF OLD.status = 'PROPOSED' AND NEW.status = 'APPROVED' THEN
        SELECT admin_proposal_max_age_hours INTO v_hours
        FROM ca_revocation_policy WHERE ca_id = NEW.ca_id;
        IF OLD.proposed_at + make_interval(hours => coalesce(v_hours, 168))
           < clock_timestamp() THEN
            RAISE EXCEPTION 'proposal older than % hours: reject it and propose again',
                coalesce(v_hours, 168)
              USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END $fn$;
ALTER FUNCTION guard_admin_proposal_age() OWNER TO trust_revocation_owner;
ALTER FUNCTION guard_admin_proposal_age() SET search_path = pg_catalog, public, pg_temp;
REVOKE ALL ON FUNCTION guard_admin_proposal_age() FROM PUBLIC;

CREATE TRIGGER ca_admin_change_proposal_age
    BEFORE UPDATE ON ca_admin_change
    FOR EACH ROW EXECUTE FUNCTION guard_admin_proposal_age();
CREATE TRIGGER officer_credential_change_proposal_age
    BEFORE UPDATE ON officer_credential_change
    FOR EACH ROW EXECUTE FUNCTION guard_admin_proposal_age();
CREATE TRIGGER ca_admin_credential_change_proposal_age
    BEFORE UPDATE ON ca_admin_credential_change
    FOR EACH ROW EXECUTE FUNCTION guard_admin_proposal_age();

SELECT acknowledge_schema_changes('0052_admin_proposal_max_age');

COMMIT;
