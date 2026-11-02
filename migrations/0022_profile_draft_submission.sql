-- Migration 0022: authoring and submission of certificate-profile drafts
-- (MVP criterion 6, first slice; ADR-0010, Proposed). Laboratory only.
--
-- A profile editor can record a new immutable draft revision and submit the
-- latest revision of a profile for approval. Nothing here approves,
-- activates or issues: a SUBMITTED revision has no effect on issuance.
--
-- Trust boundary:
--   * the API login holding trust_profile_writer can only EXECUTE the two
--     functions below; it has no privilege on any table or view;
--   * each function re-checks a server-owned role grant for the declared
--     principal and CA, recomputes the revision digest itself, serializes
--     per profile, and records an append-only lifecycle event and an audit
--     event in the same transaction;
--   * the declared principal comes from the API's verified token. As in
--     ADR-0008, the database cannot authenticate it: a compromised API, or a
--     holder of the writer login, can act as any granted editor.
BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trust_profile_writer') THEN
        CREATE ROLE trust_profile_writer NOLOGIN;
    END IF;
END
$$;

-- Owner-managed role grants: which issuer-qualified subject may act in which
-- lifecycle role for which CA. A token role alone is never enough.
CREATE TABLE management_role_grant (
    issuer TEXT NOT NULL CHECK (length(issuer) BETWEEN 1 AND 1024),
    subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 256),
    ca_id UUID NOT NULL REFERENCES ca(ca_id),
    lifecycle_role TEXT NOT NULL CHECK (lifecycle_role IN ('profile-editor', 'policy-approver', 'ca-operator')),
    granted_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (issuer, subject, ca_id, lifecycle_role)
);
REVOKE ALL ON management_role_grant FROM PUBLIC;

-- One row per lifecycle operation. operation_id is the client's idempotency
-- key: a replay with the same request returns the recorded result, and any
-- other use of the same key is refused.
CREATE TABLE profile_lifecycle_event (
    event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    operation_id UUID NOT NULL UNIQUE,
    request_sha256 BYTEA NOT NULL CHECK (octet_length(request_sha256) = 32),
    action TEXT NOT NULL CHECK (action IN ('draft.created', 'draft.submitted')),
    ca_id UUID NOT NULL,
    profile_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    snapshot_sha256 BYTEA NOT NULL CHECK (octet_length(snapshot_sha256) = 32),
    policy_version TEXT NOT NULL,
    actor_issuer TEXT NOT NULL CHECK (length(actor_issuer) BETWEEN 1 AND 1024),
    actor_subject TEXT NOT NULL CHECK (length(actor_subject) BETWEEN 1 AND 256),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (ca_id, profile_id, revision)
        REFERENCES certificate_profile_draft (ca_id, profile_id, revision)
);
REVOKE ALL ON profile_lifecycle_event FROM PUBLIC;
CREATE TRIGGER immutable_profile_lifecycle_event
    BEFORE UPDATE OR DELETE ON profile_lifecycle_event
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

-- A revision is SUBMITTED once, by the event that submitted it.
CREATE TABLE certificate_profile_submission (
    ca_id UUID NOT NULL,
    profile_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    snapshot_sha256 BYTEA NOT NULL CHECK (octet_length(snapshot_sha256) = 32),
    event_id UUID NOT NULL UNIQUE REFERENCES profile_lifecycle_event (event_id),
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (ca_id, profile_id, revision),
    FOREIGN KEY (ca_id, profile_id, revision)
        REFERENCES certificate_profile_draft (ca_id, profile_id, revision)
);
REVOKE ALL ON certificate_profile_submission FROM PUBLIC;
CREATE TRIGGER immutable_profile_submission
    BEFORE UPDATE OR DELETE ON certificate_profile_submission
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

-- The digest of a revision, in the exact v1 envelope the API computes
-- (crates/management-api/src/profile_proposal.rs, snapshot_sha256): a
-- domain tag, then each field as a big-endian length or integer followed by
-- its UTF-8 bytes. SHA-256 comes from pgcrypto; no primitive is defined here.
CREATE FUNCTION profile_draft_snapshot_sha256(p_ca UUID, p_profile TEXT, p_revision INTEGER)
RETURNS BYTEA LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $fn$
    SELECT digest(
        convert_to('trust-platform/profile-draft/v1', 'UTF8') || '\x00'::bytea
        || int8send(octet_length(d.ca_id::text)::bigint) || convert_to(d.ca_id::text, 'UTF8')
        || int8send(octet_length(d.profile_id)::bigint) || convert_to(d.profile_id, 'UTF8')
        || int4send(d.revision)
        || int8send(octet_length(d.display_name)::bigint) || convert_to(d.display_name, 'UTF8')
        || int8send(octet_length(d.policy_version)::bigint) || convert_to(d.policy_version, 'UTF8')
        || int4send(d.max_validity_days)
        || int4send(d.max_dns_sans)
        || int8send(cardinality(d.proposed_dns_zones)::bigint)
        || coalesce((SELECT string_agg(int8send(octet_length(z)::bigint) || convert_to(z, 'UTF8'), ''::bytea ORDER BY o)
                     FROM unnest(d.proposed_dns_zones) WITH ORDINALITY AS u(z, o)), ''::bytea)
        || int8send(cardinality(d.proposed_signature_suites)::bigint)
        || coalesce((SELECT string_agg(int8send(octet_length(s)::bigint) || convert_to(s, 'UTF8'), ''::bytea ORDER BY o)
                     FROM unnest(d.proposed_signature_suites) WITH ORDINALITY AS u(s, o)), ''::bytea),
        'sha256')
    FROM certificate_profile_draft d
    WHERE d.ca_id = p_ca AND d.profile_id = p_profile AND d.revision = p_revision
$fn$;
REVOKE ALL ON FUNCTION profile_draft_snapshot_sha256(UUID, TEXT, INTEGER) FROM PUBLIC;

-- Errors the API maps to HTTP: 42501 forbidden (403), P0002 unknown
-- revision (404), TP409 conflict (409: idempotency key reuse, stale or
-- already submitted revision, digest mismatch), 22023 and 23514 invalid
-- input (400).
CREATE FUNCTION profile_editor_granted(p_issuer TEXT, p_subject TEXT, p_ca UUID)
RETURNS BOOLEAN LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $fn$
    SELECT EXISTS (SELECT 1 FROM management_role_grant g
                   WHERE g.issuer = p_issuer AND g.subject = p_subject
                     AND g.ca_id = p_ca AND g.lifecycle_role = 'profile-editor')
$fn$;
REVOKE ALL ON FUNCTION profile_editor_granted(TEXT, TEXT, UUID) FROM PUBLIC;

CREATE FUNCTION create_profile_draft_lab(
    p_issuer TEXT, p_subject TEXT, p_ca UUID, p_profile TEXT,
    p_display_name TEXT, p_policy_version TEXT, p_max_validity_days INTEGER, p_max_dns_sans INTEGER,
    p_zones TEXT[], p_suites TEXT[], p_operation UUID, p_request_sha256 BYTEA
) RETURNS TABLE (revision INTEGER, created_at TEXT, replayed BOOLEAN)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_prior profile_lifecycle_event%ROWTYPE;
    v_revision INTEGER;
    v_event UUID;
    v_digest BYTEA;
BEGIN
    IF p_issuer IS NULL OR p_subject IS NULL OR p_ca IS NULL OR p_profile IS NULL
       OR p_operation IS NULL OR p_request_sha256 IS NULL OR octet_length(p_request_sha256) <> 32
       OR length(p_subject) NOT BETWEEN 1 AND 256 OR length(p_issuer) NOT BETWEEN 1 AND 1024 THEN
        RAISE EXCEPTION 'invalid profile draft parameters' USING ERRCODE = '22023';
    END IF;
    IF NOT profile_editor_granted(p_issuer, p_subject, p_ca) THEN
        RAISE EXCEPTION 'no profile-editor grant for this CA' USING ERRCODE = '42501';
    END IF;
    -- One writer at a time per profile: revision numbers are dense and the
    -- idempotency lookup below cannot race with its own insert.
    PERFORM pg_advisory_xact_lock(hashtextextended('profile:' || p_ca::text || '/' || p_profile, 0));

    SELECT * INTO v_prior FROM profile_lifecycle_event e WHERE e.operation_id = p_operation;
    IF FOUND THEN
        IF v_prior.action = 'draft.created' AND v_prior.request_sha256 = p_request_sha256
           AND v_prior.ca_id = p_ca AND v_prior.profile_id = p_profile
           AND v_prior.actor_issuer = p_issuer AND v_prior.actor_subject = p_subject THEN
            RETURN QUERY SELECT v_prior.revision,
                to_char(d.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'), true
                FROM certificate_profile_draft d
                WHERE d.ca_id = p_ca AND d.profile_id = p_profile AND d.revision = v_prior.revision;
            RETURN;
        END IF;
        RAISE EXCEPTION 'idempotency key already used for another request' USING ERRCODE = 'TP409';
    END IF;

    SELECT coalesce(max(d.revision), 0) + 1 INTO v_revision
    FROM certificate_profile_draft d WHERE d.ca_id = p_ca AND d.profile_id = p_profile;
    INSERT INTO certificate_profile_draft
        (ca_id, profile_id, revision, display_name, policy_version, max_validity_days, max_dns_sans,
         proposed_dns_zones, proposed_signature_suites, created_by)
    VALUES (p_ca, p_profile, v_revision, p_display_name, p_policy_version, p_max_validity_days, p_max_dns_sans,
            p_zones, p_suites, p_subject);
    v_digest := profile_draft_snapshot_sha256(p_ca, p_profile, v_revision);
    INSERT INTO profile_lifecycle_event
        (operation_id, request_sha256, action, ca_id, profile_id, revision, snapshot_sha256, policy_version,
         actor_issuer, actor_subject)
    VALUES (p_operation, p_request_sha256, 'draft.created', p_ca, p_profile, v_revision, v_digest,
            p_policy_version, p_issuer, p_subject)
    RETURNING event_id INTO v_event;
    INSERT INTO audit_event (event_id, ca_id, actor_id, event_type, decision, policy_version)
    VALUES (v_event, p_ca, p_subject, 'profile.draft.created', 'allow', p_policy_version);

    RETURN QUERY SELECT v_revision,
        to_char(d.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'), false
        FROM certificate_profile_draft d
        WHERE d.ca_id = p_ca AND d.profile_id = p_profile AND d.revision = v_revision;
END
$fn$;
REVOKE ALL ON FUNCTION create_profile_draft_lab(TEXT, TEXT, UUID, TEXT, TEXT, TEXT, INTEGER, INTEGER,
    TEXT[], TEXT[], UUID, BYTEA) FROM PUBLIC;

-- Submits the latest revision of a profile, if the caller's digest is that
-- revision's digest. Returns the fields the API needs to refuse a revision
-- with syntax warnings; the API then commits or rolls back.
CREATE FUNCTION submit_profile_draft_lab(
    p_issuer TEXT, p_subject TEXT, p_ca UUID, p_profile TEXT, p_revision INTEGER,
    p_snapshot_sha256 BYTEA, p_operation UUID, p_request_sha256 BYTEA
) RETURNS TABLE (submitted_at TEXT, replayed BOOLEAN, display_name TEXT, policy_version TEXT,
                 proposed_dns_zones TEXT[], proposed_signature_suites TEXT[])
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_prior profile_lifecycle_event%ROWTYPE;
    v_draft certificate_profile_draft%ROWTYPE;
    v_digest BYTEA;
    v_event UUID;
BEGIN
    IF p_issuer IS NULL OR p_subject IS NULL OR p_ca IS NULL OR p_profile IS NULL OR p_revision IS NULL
       OR p_operation IS NULL OR p_request_sha256 IS NULL OR octet_length(p_request_sha256) <> 32
       OR p_snapshot_sha256 IS NULL OR octet_length(p_snapshot_sha256) <> 32
       OR length(p_subject) NOT BETWEEN 1 AND 256 OR length(p_issuer) NOT BETWEEN 1 AND 1024 THEN
        RAISE EXCEPTION 'invalid profile submission parameters' USING ERRCODE = '22023';
    END IF;
    IF NOT profile_editor_granted(p_issuer, p_subject, p_ca) THEN
        RAISE EXCEPTION 'no profile-editor grant for this CA' USING ERRCODE = '42501';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('profile:' || p_ca::text || '/' || p_profile, 0));

    SELECT * INTO v_draft FROM certificate_profile_draft d
    WHERE d.ca_id = p_ca AND d.profile_id = p_profile AND d.revision = p_revision;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown profile revision' USING ERRCODE = 'P0002';
    END IF;

    SELECT * INTO v_prior FROM profile_lifecycle_event e WHERE e.operation_id = p_operation;
    IF FOUND THEN
        IF v_prior.action = 'draft.submitted' AND v_prior.request_sha256 = p_request_sha256
           AND v_prior.ca_id = p_ca AND v_prior.profile_id = p_profile AND v_prior.revision = p_revision
           AND v_prior.actor_issuer = p_issuer AND v_prior.actor_subject = p_subject THEN
            RETURN QUERY SELECT to_char(s.submitted_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'), true,
                v_draft.display_name, v_draft.policy_version, v_draft.proposed_dns_zones,
                v_draft.proposed_signature_suites
                FROM certificate_profile_submission s WHERE s.event_id = v_prior.event_id;
            RETURN;
        END IF;
        RAISE EXCEPTION 'idempotency key already used for another request' USING ERRCODE = 'TP409';
    END IF;

    IF EXISTS (SELECT 1 FROM certificate_profile_draft d
               WHERE d.ca_id = p_ca AND d.profile_id = p_profile AND d.revision > p_revision) THEN
        RAISE EXCEPTION 'a newer revision of this profile exists' USING ERRCODE = 'TP409';
    END IF;
    IF EXISTS (SELECT 1 FROM certificate_profile_submission s
               WHERE s.ca_id = p_ca AND s.profile_id = p_profile AND s.revision = p_revision) THEN
        RAISE EXCEPTION 'revision already submitted' USING ERRCODE = 'TP409';
    END IF;
    v_digest := profile_draft_snapshot_sha256(p_ca, p_profile, p_revision);
    IF v_digest IS DISTINCT FROM p_snapshot_sha256 THEN
        RAISE EXCEPTION 'snapshot digest does not match the revision' USING ERRCODE = 'TP409';
    END IF;

    INSERT INTO profile_lifecycle_event
        (operation_id, request_sha256, action, ca_id, profile_id, revision, snapshot_sha256, policy_version,
         actor_issuer, actor_subject)
    VALUES (p_operation, p_request_sha256, 'draft.submitted', p_ca, p_profile, p_revision, v_digest,
            v_draft.policy_version, p_issuer, p_subject)
    RETURNING event_id INTO v_event;
    INSERT INTO certificate_profile_submission (ca_id, profile_id, revision, snapshot_sha256, event_id)
    VALUES (p_ca, p_profile, p_revision, v_digest, v_event);
    INSERT INTO audit_event (event_id, ca_id, actor_id, event_type, decision, policy_version)
    VALUES (v_event, p_ca, p_subject, 'profile.draft.submitted', 'allow', v_draft.policy_version);

    RETURN QUERY SELECT to_char(s.submitted_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'), false,
        v_draft.display_name, v_draft.policy_version, v_draft.proposed_dns_zones, v_draft.proposed_signature_suites
        FROM certificate_profile_submission s WHERE s.event_id = v_event;
END
$fn$;
REVOKE ALL ON FUNCTION submit_profile_draft_lab(TEXT, TEXT, UUID, TEXT, INTEGER, BYTEA, UUID, BYTEA) FROM PUBLIC;

GRANT USAGE ON SCHEMA public TO trust_profile_writer;
GRANT EXECUTE ON FUNCTION create_profile_draft_lab(TEXT, TEXT, UUID, TEXT, TEXT, TEXT, INTEGER, INTEGER,
    TEXT[], TEXT[], UUID, BYTEA) TO trust_profile_writer;
GRANT EXECUTE ON FUNCTION submit_profile_draft_lab(TEXT, TEXT, UUID, TEXT, INTEGER, BYTEA, UUID, BYTEA)
    TO trust_profile_writer;

-- Readers see each revision's state. Same principal filter as 0021.
CREATE OR REPLACE VIEW management_profile_draft WITH (security_barrier = true) AS
SELECT d.ca_id::text AS ca_id, d.profile_id, d.revision, d.display_name,
       d.policy_version, d.max_validity_days, d.max_dns_sans,
       d.proposed_dns_zones, d.proposed_signature_suites,
       d.created_by,
       to_char(d.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
       CASE WHEN s.revision IS NULL THEN 'DRAFT' ELSE 'SUBMITTED' END AS lifecycle_status,
       to_char(s.submitted_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS submitted_at
FROM certificate_profile_draft d
LEFT JOIN certificate_profile_submission s
    ON s.ca_id = d.ca_id AND s.profile_id = d.profile_id AND s.revision = d.revision
WHERE EXISTS (
    SELECT 1 FROM management_reader_grant g
    WHERE g.issuer = current_setting('trust.reader_issuer', true)
      AND g.subject = current_setting('trust.reader_subject', true)
      AND g.ca_id = d.ca_id
);

-- Lets the API refuse to enable write routes against a database without
-- this migration.
CREATE FUNCTION management_profile_lifecycle_version() RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $fn$ SELECT 1 $fn$;
REVOKE ALL ON FUNCTION management_profile_lifecycle_version() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION management_profile_lifecycle_version() TO trust_api_reader, trust_profile_writer;

COMMIT;
