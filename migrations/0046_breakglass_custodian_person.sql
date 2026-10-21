-- v0.46 (lab): the break-glass custodian is a person who never signs on the
-- CA (ADR-0007 §6, Proposed). LAB ONLY.
-- 0045 named the custodian with a free label, so a custodian who was also
-- a CA admin could enrol an admin key for themselves with the emergency
-- key; only the after-the-fact reviews would catch it.
-- * ca_breakglass_credential.holder_person_id: the custodian's person
--   identifier (same namespace as officer and admin credentials). Required
--   for every ACTIVE key and immutable. ACTIVE keys enrolled under 0045
--   without one are retired here (audited); the DBA re-enrols them.
-- * enroll_breakglass_credential(ca, credential, label, person, key)
--   replaces the 4-argument form (DBA only, no service grant).
-- * One person is never both custodian and signer on a CA: an active
--   custodian's person cannot hold an active officer or admin credential
--   of the CA, in either order of enrolment (guard_breakglass_keys). This
--   also stops the emergency key enrolling an admin key for its custodian.
-- The person identifier remains caller-supplied until the IAM decision.
-- Apply after 0045 as a superuser.
BEGIN;

ALTER TABLE ca_breakglass_credential
    ADD COLUMN holder_person_id TEXT CHECK (length(holder_person_id) BETWEEN 1 AND 256);

-- Fail closed: keys without a custodian person stop working.
WITH retired AS (
    UPDATE ca_breakglass_credential SET status = 'REMOVED', removed_at = clock_timestamp()
    WHERE status = 'ACTIVE' AND holder_person_id IS NULL
    RETURNING ca_id, credential_id
)
INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
SELECT gen_random_uuid(), ca_id, NULL, session_user, 'ca_admin.breakglass.removed',
       'MIGRATION_0046:no_custodian_person:credential='
       || encode(sha256(credential_id), 'hex')
FROM retired;

ALTER TABLE ca_breakglass_credential
    ADD CONSTRAINT ca_breakglass_credential_person
        CHECK (status = 'REMOVED' OR holder_person_id IS NOT NULL);

CREATE OR REPLACE FUNCTION guard_breakglass_credential() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'ca_breakglass_credential is append-only' USING ERRCODE = '23514';
    END IF;
    IF (NEW.credential_id, NEW.ca_id, NEW.holder_label, NEW.holder_person_id,
        NEW.public_key_sec1, NEW.enrolled_at)
       IS DISTINCT FROM (OLD.credential_id, OLD.ca_id, OLD.holder_label, OLD.holder_person_id,
                         OLD.public_key_sec1, OLD.enrolled_at)
       OR NEW.sign_count < OLD.sign_count
       OR (OLD.status = 'REMOVED' AND NEW IS DISTINCT FROM OLD)
    THEN
        RAISE EXCEPTION 'only the counter may advance and an active key be removed'
          USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $fn$;

-- Keys stay disjoint (0045); persons too, per CA, while active.
CREATE OR REPLACE FUNCTION guard_breakglass_keys() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    IF TG_TABLE_NAME = 'ca_breakglass_credential' THEN
        IF EXISTS (SELECT 1 FROM officer_credential
                   WHERE public_key_sha256 = sha256(NEW.public_key_sec1))
           OR EXISTS (SELECT 1 FROM ca_admin_credential
                      WHERE public_key_sha256 = sha256(NEW.public_key_sec1)) THEN
            RAISE EXCEPTION 'key already enrolled as an officer or admin key'
              USING ERRCODE = '23514';
        END IF;
        IF EXISTS (SELECT 1 FROM officer_credential
                   WHERE ca_id = NEW.ca_id AND status = 'ACTIVE'
                     AND person_id = NEW.holder_person_id)
           OR EXISTS (SELECT 1 FROM ca_admin_credential
                      WHERE ca_id = NEW.ca_id AND status = 'ACTIVE'
                        AND person_id = NEW.holder_person_id) THEN
            RAISE EXCEPTION 'custodian person holds an officer or admin credential of this CA'
              USING ERRCODE = '23514';
        END IF;
    ELSE
        IF EXISTS (SELECT 1 FROM ca_breakglass_credential
                   WHERE public_key_sha256 = sha256(NEW.public_key_sec1)) THEN
            RAISE EXCEPTION 'key already enrolled as a break-glass key' USING ERRCODE = '23514';
        END IF;
        IF EXISTS (SELECT 1 FROM ca_breakglass_credential
                   WHERE ca_id = NEW.ca_id AND status = 'ACTIVE'
                     AND holder_person_id = NEW.person_id) THEN
            RAISE EXCEPTION 'person is the break-glass custodian of this CA'
              USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END $fn$;

DROP FUNCTION enroll_breakglass_credential(uuid, bytea, text, bytea);

CREATE FUNCTION enroll_breakglass_credential(
    p_ca UUID, p_credential_id BYTEA, p_holder_label TEXT, p_holder_person_id TEXT,
    p_public_key_sec1 BYTEA
)
RETURNS VOID
LANGUAGE plpgsql AS $fn$
BEGIN
    IF p_holder_person_id IS NULL THEN
        RAISE EXCEPTION 'a custodian person is required' USING ERRCODE = '22023';
    END IF;
    -- Serialise against credential enrolment on the same CA.
    PERFORM 1 FROM ca WHERE ca_id = p_ca FOR NO KEY UPDATE;
    BEGIN
        INSERT INTO ca_breakglass_credential(credential_id, ca_id, holder_label,
                                             holder_person_id, public_key_sec1)
        VALUES (p_credential_id, p_ca, p_holder_label, p_holder_person_id, p_public_key_sec1);
    EXCEPTION WHEN unique_violation THEN
        RAISE EXCEPTION 'credential id or public key already enrolled' USING ERRCODE = '23514';
    END;
    INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), p_ca, NULL, session_user, 'ca_admin.breakglass.enrolled',
            'BOOTSTRAP:holder=' || p_holder_label
            || ':key=' || encode(sha256(p_public_key_sec1), 'hex'));
END $fn$;
ALTER FUNCTION enroll_breakglass_credential(uuid,bytea,text,text,bytea)
    OWNER TO trust_revocation_owner;
ALTER FUNCTION enroll_breakglass_credential(uuid,bytea,text,text,bytea) SECURITY DEFINER;
ALTER FUNCTION enroll_breakglass_credential(uuid,bytea,text,text,bytea)
    SET search_path = pg_catalog, public, pg_temp;
REVOKE ALL ON FUNCTION enroll_breakglass_credential(uuid,bytea,text,text,bytea) FROM PUBLIC;
ALTER FUNCTION guard_breakglass_credential() SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION guard_breakglass_keys() SET search_path = pg_catalog, public, pg_temp;

SELECT acknowledge_schema_changes('0046_breakglass_custodian_person');

COMMIT;
