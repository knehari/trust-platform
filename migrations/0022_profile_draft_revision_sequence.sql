-- Draft revisions must start at 1 and remain contiguous per CA/profile.
-- This does not approve, activate or authorize a profile for issuance.
BEGIN;

DO $guard$ BEGIN
    IF EXISTS (
        SELECT 1 FROM certificate_profile_draft
        GROUP BY ca_id, profile_id
        HAVING min(revision) <> 1 OR count(*) <> max(revision)
    ) THEN
        RAISE EXCEPTION 'existing profile draft revision sequence has gaps';
    END IF;
END $guard$;

CREATE FUNCTION enforce_profile_draft_revision_sequence() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
DECLARE
    v_profile RECORD;
    v_count BIGINT;
    v_first INTEGER;
    v_last INTEGER;
BEGIN
    -- A CA row lock serializes writers, including different transactions that
    -- insert the same profile's next revision concurrently. Lock order is fixed.
    FOR v_profile IN
        SELECT DISTINCT ca_id, profile_id FROM inserted_drafts
        ORDER BY ca_id, profile_id
    LOOP
        -- NO KEY UPDATE does not conflict with the FK's KEY SHARE check.
        PERFORM 1 FROM ca WHERE ca_id = v_profile.ca_id FOR NO KEY UPDATE;
        SELECT count(*), min(revision), max(revision)
          INTO v_count, v_first, v_last
          FROM certificate_profile_draft
         WHERE ca_id = v_profile.ca_id AND profile_id = v_profile.profile_id;
        IF v_first <> 1 OR v_count <> v_last THEN
            RAISE EXCEPTION 'profile draft revisions must start at 1 and be contiguous';
        END IF;
    END LOOP;
    RETURN NULL;
END
$fn$;

REVOKE ALL ON FUNCTION enforce_profile_draft_revision_sequence() FROM PUBLIC;

CREATE TRIGGER enforce_profile_draft_revision_sequence_after_insert
    AFTER INSERT ON certificate_profile_draft
    REFERENCING NEW TABLE AS inserted_drafts
    FOR EACH STATEMENT EXECUTE FUNCTION enforce_profile_draft_revision_sequence();

COMMIT;
