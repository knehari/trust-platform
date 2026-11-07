-- Migration 0024: activation and retirement of approved certificate-profile
-- revisions (MVP criterion 6, third slice; ADR-0012, Proposed). Laboratory
-- only. No issuance path reads the active pointer: an ACTIVE revision
-- authorizes nothing yet.
--
-- A CA operator, with a ca-operator grant and who neither wrote, submitted
-- nor decided on the revision, activates an APPROVED revision by naming its
-- exact digest. Activation is refused unless the revision's policy version
-- is the CA's and every proposed signature suite is a capability the owner
-- declared for that CA. The API also requires each suite to be in the typed
-- catalogue of trust-pki-crypto. At most one revision of a profile is
-- active: activating another supersedes it. Retirement ends the active one.
--
-- Declared capabilities are the owner's statement, not evidence that a
-- provider and key can issue under the profile; the issuer certificate is
-- not checked (no CA key or certificate binding exists yet).
BEGIN;

CREATE TABLE ca_signing_capability (
    ca_id UUID NOT NULL REFERENCES ca (ca_id),
    suite_id TEXT NOT NULL CHECK (suite_id ~ '^[a-z0-9][a-z0-9-]{2,63}$'),
    declared_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    revoked_at TIMESTAMPTZ CHECK (revoked_at IS NULL OR revoked_at >= declared_at),
    PRIMARY KEY (ca_id, suite_id)
);
REVOKE ALL ON ca_signing_capability FROM PUBLIC;

CREATE FUNCTION ca_signing_capability_guard() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    IF TG_OP = 'DELETE' OR OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL
       OR (NEW.ca_id, NEW.suite_id, NEW.declared_at) IS DISTINCT FROM (OLD.ca_id, OLD.suite_id, OLD.declared_at) THEN
        RAISE EXCEPTION 'CA signing capabilities are append-only; only a single revocation is allowed';
    END IF;
    RETURN NEW;
END
$fn$;
REVOKE ALL ON FUNCTION ca_signing_capability_guard() FROM PUBLIC;
CREATE TRIGGER ca_signing_capability_append_only
    BEFORE UPDATE OR DELETE ON ca_signing_capability
    FOR EACH ROW EXECUTE FUNCTION ca_signing_capability_guard();

ALTER TABLE profile_lifecycle_event DROP CONSTRAINT profile_lifecycle_event_action_check;
ALTER TABLE profile_lifecycle_event ADD CONSTRAINT profile_lifecycle_event_action_check
    CHECK (action IN ('draft.created', 'draft.submitted', 'draft.approval', 'draft.rejection',
                      'revision.activation', 'revision.retirement'));

-- The only mutable lifecycle state: which revision of a profile is active.
-- The primary key is the "at most one active revision" invariant; only the
-- two functions below change it, and every change has a history row.
CREATE TABLE certificate_profile_active (
    ca_id UUID NOT NULL,
    profile_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    activated_event_id UUID NOT NULL REFERENCES profile_lifecycle_event (event_id),
    activated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (ca_id, profile_id),
    FOREIGN KEY (ca_id, profile_id, revision)
        REFERENCES certificate_profile_submission (ca_id, profile_id, revision)
);
REVOKE ALL ON certificate_profile_active FROM PUBLIC;

CREATE TABLE certificate_profile_activation (
    activation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id UUID NOT NULL REFERENCES profile_lifecycle_event (event_id),
    ca_id UUID NOT NULL,
    profile_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('activate', 'supersede', 'retire')),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (ca_id, profile_id, revision, action),
    FOREIGN KEY (ca_id, profile_id, revision)
        REFERENCES certificate_profile_submission (ca_id, profile_id, revision)
);
REVOKE ALL ON certificate_profile_activation FROM PUBLIC;
CREATE TRIGGER immutable_profile_activation
    BEFORE UPDATE OR DELETE ON certificate_profile_activation
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

-- DRAFT → SUBMITTED → APPROVED → ACTIVE → SUPERSEDED or RETIRED; REJECTED.
CREATE FUNCTION profile_revision_status(p_ca UUID, p_profile TEXT, p_revision INTEGER) RETURNS TEXT
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $fn$
    SELECT CASE
        WHEN EXISTS (SELECT 1 FROM certificate_profile_active a
                     WHERE a.ca_id = p_ca AND a.profile_id = p_profile AND a.revision = p_revision) THEN 'ACTIVE'
        WHEN EXISTS (SELECT 1 FROM certificate_profile_activation h
                     WHERE h.ca_id = p_ca AND h.profile_id = p_profile AND h.revision = p_revision
                       AND h.action = 'retire') THEN 'RETIRED'
        WHEN EXISTS (SELECT 1 FROM certificate_profile_activation h
                     WHERE h.ca_id = p_ca AND h.profile_id = p_profile AND h.revision = p_revision
                       AND h.action = 'supersede') THEN 'SUPERSEDED'
        ELSE profile_lifecycle_status(p_ca, p_profile, p_revision)
    END
$fn$;
REVOKE ALL ON FUNCTION profile_revision_status(UUID, TEXT, INTEGER) FROM PUBLIC;

-- Errors as in 0022–0023, plus TP422: the revision is incompatible with the
-- CA (policy version or an undeclared suite).
CREATE FUNCTION activate_profile_revision_lab(
    p_issuer TEXT, p_subject TEXT, p_ca UUID, p_profile TEXT, p_revision INTEGER,
    p_snapshot_sha256 BYTEA, p_operation UUID, p_request_sha256 BYTEA
) RETURNS TABLE (status TEXT, superseded_revision INTEGER, proposed_signature_suites TEXT[], replayed BOOLEAN)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_prior profile_lifecycle_event%ROWTYPE;
    v_draft certificate_profile_draft%ROWTYPE;
    v_submission certificate_profile_submission%ROWTYPE;
    v_previous INTEGER;
    v_event UUID;
    v_missing TEXT;
BEGIN
    IF p_issuer IS NULL OR p_subject IS NULL OR p_ca IS NULL OR p_profile IS NULL OR p_revision IS NULL
       OR p_operation IS NULL OR p_request_sha256 IS NULL OR octet_length(p_request_sha256) <> 32
       OR p_snapshot_sha256 IS NULL OR octet_length(p_snapshot_sha256) <> 32
       OR length(p_subject) NOT BETWEEN 1 AND 256 OR length(p_issuer) NOT BETWEEN 1 AND 1024 THEN
        RAISE EXCEPTION 'invalid profile activation parameters' USING ERRCODE = '22023';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM management_role_grant g
                   WHERE g.issuer = p_issuer AND g.subject = p_subject AND g.ca_id = p_ca
                     AND g.lifecycle_role = 'ca-operator') THEN
        RAISE EXCEPTION 'no ca-operator grant for this CA' USING ERRCODE = '42501';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('profile:' || p_ca::text || '/' || p_profile, 0));

    SELECT * INTO v_prior FROM profile_lifecycle_event e WHERE e.operation_id = p_operation;
    IF FOUND THEN
        IF v_prior.action = 'revision.activation' AND v_prior.request_sha256 = p_request_sha256
           AND v_prior.ca_id = p_ca AND v_prior.profile_id = p_profile AND v_prior.revision = p_revision
           AND v_prior.actor_issuer = p_issuer AND v_prior.actor_subject = p_subject THEN
            RETURN QUERY SELECT profile_revision_status(p_ca, p_profile, p_revision),
                (SELECT h.revision FROM certificate_profile_activation h
                 WHERE h.event_id = v_prior.event_id AND h.action = 'supersede'),
                d.proposed_signature_suites, true
                FROM certificate_profile_draft d
                WHERE d.ca_id = p_ca AND d.profile_id = p_profile AND d.revision = p_revision;
            RETURN;
        END IF;
        RAISE EXCEPTION 'idempotency key already used for another request' USING ERRCODE = 'TP409';
    END IF;

    SELECT * INTO v_draft FROM certificate_profile_draft d
    WHERE d.ca_id = p_ca AND d.profile_id = p_profile AND d.revision = p_revision;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown profile revision' USING ERRCODE = 'P0002';
    END IF;
    -- Separation of duties: no one activates what they wrote, submitted or
    -- decided on.
    IF EXISTS (SELECT 1 FROM profile_lifecycle_event e
               WHERE e.ca_id = p_ca AND e.profile_id = p_profile AND e.revision = p_revision
                 AND e.action IN ('draft.created', 'draft.submitted', 'draft.approval', 'draft.rejection')
                 AND e.actor_issuer = p_issuer AND e.actor_subject = p_subject) THEN
        RAISE EXCEPTION 'the author, submitter or an approver of a revision cannot activate it' USING ERRCODE = '42501';
    END IF;
    IF profile_revision_status(p_ca, p_profile, p_revision) <> 'APPROVED' THEN
        RAISE EXCEPTION 'only an approved, never activated revision can be activated' USING ERRCODE = 'TP409';
    END IF;
    SELECT * INTO v_submission FROM certificate_profile_submission s
    WHERE s.ca_id = p_ca AND s.profile_id = p_profile AND s.revision = p_revision;
    IF v_submission.snapshot_sha256 IS DISTINCT FROM p_snapshot_sha256 THEN
        RAISE EXCEPTION 'snapshot digest does not match the approved revision' USING ERRCODE = 'TP409';
    END IF;
    IF v_draft.policy_version IS DISTINCT FROM (SELECT c.policy_version FROM ca c WHERE c.ca_id = p_ca) THEN
        RAISE EXCEPTION 'the revision policy version is not the CA policy version' USING ERRCODE = 'TP422';
    END IF;
    SELECT string_agg(s, ', ') INTO v_missing
    FROM unnest(v_draft.proposed_signature_suites) AS s
    WHERE NOT EXISTS (SELECT 1 FROM ca_signing_capability k
                      WHERE k.ca_id = p_ca AND k.suite_id = s AND k.revoked_at IS NULL);
    IF v_missing IS NOT NULL THEN
        RAISE EXCEPTION 'suites not declared for this CA: %', v_missing USING ERRCODE = 'TP422';
    END IF;

    INSERT INTO profile_lifecycle_event
        (operation_id, request_sha256, action, ca_id, profile_id, revision, snapshot_sha256, policy_version,
         actor_issuer, actor_subject)
    VALUES (p_operation, p_request_sha256, 'revision.activation', p_ca, p_profile, p_revision,
            v_submission.snapshot_sha256, v_draft.policy_version, p_issuer, p_subject)
    RETURNING event_id INTO v_event;
    SELECT a.revision INTO v_previous FROM certificate_profile_active a
    WHERE a.ca_id = p_ca AND a.profile_id = p_profile;
    IF FOUND THEN
        INSERT INTO certificate_profile_activation (event_id, ca_id, profile_id, revision, action)
        VALUES (v_event, p_ca, p_profile, v_previous, 'supersede');
        DELETE FROM certificate_profile_active a WHERE a.ca_id = p_ca AND a.profile_id = p_profile;
    END IF;
    INSERT INTO certificate_profile_active (ca_id, profile_id, revision, activated_event_id)
    VALUES (p_ca, p_profile, p_revision, v_event);
    INSERT INTO certificate_profile_activation (event_id, ca_id, profile_id, revision, action)
    VALUES (v_event, p_ca, p_profile, p_revision, 'activate');
    INSERT INTO audit_event (event_id, ca_id, actor_id, event_type, decision, policy_version)
    VALUES (v_event, p_ca, p_subject, 'profile.revision.activation', 'allow', v_draft.policy_version);

    RETURN QUERY SELECT 'ACTIVE'::text, v_previous, v_draft.proposed_signature_suites, false;
END
$fn$;
REVOKE ALL ON FUNCTION activate_profile_revision_lab(TEXT, TEXT, UUID, TEXT, INTEGER, BYTEA, UUID, BYTEA) FROM PUBLIC;

-- Ends the active revision of a profile. Nothing replaces it.
CREATE FUNCTION retire_profile_revision_lab(
    p_issuer TEXT, p_subject TEXT, p_ca UUID, p_profile TEXT, p_revision INTEGER,
    p_operation UUID, p_request_sha256 BYTEA
) RETURNS TABLE (status TEXT, replayed BOOLEAN)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_prior profile_lifecycle_event%ROWTYPE;
    v_draft certificate_profile_draft%ROWTYPE;
    v_event UUID;
BEGIN
    IF p_issuer IS NULL OR p_subject IS NULL OR p_ca IS NULL OR p_profile IS NULL OR p_revision IS NULL
       OR p_operation IS NULL OR p_request_sha256 IS NULL OR octet_length(p_request_sha256) <> 32
       OR length(p_subject) NOT BETWEEN 1 AND 256 OR length(p_issuer) NOT BETWEEN 1 AND 1024 THEN
        RAISE EXCEPTION 'invalid profile retirement parameters' USING ERRCODE = '22023';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM management_role_grant g
                   WHERE g.issuer = p_issuer AND g.subject = p_subject AND g.ca_id = p_ca
                     AND g.lifecycle_role = 'ca-operator') THEN
        RAISE EXCEPTION 'no ca-operator grant for this CA' USING ERRCODE = '42501';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('profile:' || p_ca::text || '/' || p_profile, 0));

    SELECT * INTO v_prior FROM profile_lifecycle_event e WHERE e.operation_id = p_operation;
    IF FOUND THEN
        IF v_prior.action = 'revision.retirement' AND v_prior.request_sha256 = p_request_sha256
           AND v_prior.ca_id = p_ca AND v_prior.profile_id = p_profile AND v_prior.revision = p_revision
           AND v_prior.actor_issuer = p_issuer AND v_prior.actor_subject = p_subject THEN
            RETURN QUERY SELECT profile_revision_status(p_ca, p_profile, p_revision), true;
            RETURN;
        END IF;
        RAISE EXCEPTION 'idempotency key already used for another request' USING ERRCODE = 'TP409';
    END IF;

    SELECT * INTO v_draft FROM certificate_profile_draft d
    WHERE d.ca_id = p_ca AND d.profile_id = p_profile AND d.revision = p_revision;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown profile revision' USING ERRCODE = 'P0002';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM certificate_profile_active a
                   WHERE a.ca_id = p_ca AND a.profile_id = p_profile AND a.revision = p_revision) THEN
        RAISE EXCEPTION 'only the active revision can be retired' USING ERRCODE = 'TP409';
    END IF;

    INSERT INTO profile_lifecycle_event
        (operation_id, request_sha256, action, ca_id, profile_id, revision, snapshot_sha256, policy_version,
         actor_issuer, actor_subject)
    SELECT p_operation, p_request_sha256, 'revision.retirement', p_ca, p_profile, p_revision,
           s.snapshot_sha256, v_draft.policy_version, p_issuer, p_subject
    FROM certificate_profile_submission s
    WHERE s.ca_id = p_ca AND s.profile_id = p_profile AND s.revision = p_revision
    RETURNING event_id INTO v_event;
    DELETE FROM certificate_profile_active a WHERE a.ca_id = p_ca AND a.profile_id = p_profile;
    INSERT INTO certificate_profile_activation (event_id, ca_id, profile_id, revision, action)
    VALUES (v_event, p_ca, p_profile, p_revision, 'retire');
    INSERT INTO audit_event (event_id, ca_id, actor_id, event_type, decision, policy_version)
    VALUES (v_event, p_ca, p_subject, 'profile.revision.retirement', 'allow', v_draft.policy_version);

    RETURN QUERY SELECT 'RETIRED'::text, false;
END
$fn$;
REVOKE ALL ON FUNCTION retire_profile_revision_lab(TEXT, TEXT, UUID, TEXT, INTEGER, UUID, BYTEA) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION activate_profile_revision_lab(TEXT, TEXT, UUID, TEXT, INTEGER, BYTEA, UUID, BYTEA)
    TO trust_profile_writer;
GRANT EXECUTE ON FUNCTION retire_profile_revision_lab(TEXT, TEXT, UUID, TEXT, INTEGER, UUID, BYTEA)
    TO trust_profile_writer;

-- Readers see the full state; the logic is inlined as in 0023 because
-- functions called by a view run with the reader's privileges.
CREATE OR REPLACE VIEW management_profile_draft WITH (security_barrier = true) AS
SELECT d.ca_id::text AS ca_id, d.profile_id, d.revision, d.display_name,
       d.policy_version, d.max_validity_days, d.max_dns_sans,
       d.proposed_dns_zones, d.proposed_signature_suites,
       d.created_by,
       to_char(d.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
       CASE WHEN a.revision IS NOT NULL THEN 'ACTIVE'
            WHEN h.retired THEN 'RETIRED'
            WHEN h.superseded THEN 'SUPERSEDED'
            WHEN x.rejections > 0 THEN 'REJECTED'
            WHEN x.approvals >= 2 THEN 'APPROVED'
            WHEN s.revision IS NOT NULL THEN 'SUBMITTED'
            ELSE 'DRAFT' END AS lifecycle_status,
       to_char(s.submitted_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS submitted_at,
       x.approvals AS approval_count,
       CASE WHEN x.rejections > 0 OR x.approvals >= 2
            THEN to_char(x.last_decided_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END AS decided_at,
       to_char(h.activated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS activated_at,
       to_char(h.ended_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS ended_at
FROM certificate_profile_draft d
LEFT JOIN certificate_profile_submission s
    ON s.ca_id = d.ca_id AND s.profile_id = d.profile_id AND s.revision = d.revision
LEFT JOIN certificate_profile_active a
    ON a.ca_id = d.ca_id AND a.profile_id = d.profile_id AND a.revision = d.revision
CROSS JOIN LATERAL (
    SELECT count(*) FILTER (WHERE c.decision = 'approve')::integer AS approvals,
           count(*) FILTER (WHERE c.decision = 'reject')::integer AS rejections,
           max(c.decided_at) AS last_decided_at
    FROM certificate_profile_decision c
    WHERE c.ca_id = d.ca_id AND c.profile_id = d.profile_id AND c.revision = d.revision
) x
CROSS JOIN LATERAL (
    SELECT bool_or(v.action = 'retire') IS TRUE AS retired,
           bool_or(v.action = 'supersede') IS TRUE AS superseded,
           max(v.recorded_at) FILTER (WHERE v.action = 'activate') AS activated_at,
           max(v.recorded_at) FILTER (WHERE v.action IN ('retire', 'supersede')) AS ended_at
    FROM certificate_profile_activation v
    WHERE v.ca_id = d.ca_id AND v.profile_id = d.profile_id AND v.revision = d.revision
) h
WHERE EXISTS (
    SELECT 1 FROM management_reader_grant g
    WHERE g.issuer = current_setting('trust.reader_issuer', true)
      AND g.subject = current_setting('trust.reader_subject', true)
      AND g.ca_id = d.ca_id
);

CREATE FUNCTION management_profile_activation_version() RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $fn$ SELECT 1 $fn$;
REVOKE ALL ON FUNCTION management_profile_activation_version() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION management_profile_activation_version() TO trust_api_reader, trust_profile_writer;

COMMIT;
