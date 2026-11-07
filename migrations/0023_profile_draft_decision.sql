-- Migration 0023: signed approval and rejection of submitted certificate-
-- profile revisions (MVP criterion 6, second slice; ADR-0011, Proposed).
-- Laboratory only. APPROVED has no effect on issuance: nothing activates a
-- profile, and no issuance path reads this state.
--
-- Two separately authenticated approvers, each with a profile-approver
-- grant and their own registered P-256 key, must each sign the exact
-- decision claim the database builds for the submitted revision. One
-- rejection ends the revision. Neither approver may be the revision's
-- author or submitter, and the two approvals must use different keys.
--
-- PostgreSQL does not verify ECDSA. The API verifies each signature inside
-- the transaction that records it and rolls back on failure; the stored
-- claim, signature and public key let anyone verify every decision again
-- (lab_verify_profile_decisions). A compromised API could record a decision
-- without a valid signature: that independent check is what detects it.
BEGIN;

-- Owner-registered approver keys: one active uncompressed P-256 point per
-- approver, and no point registered twice. Private keys never reach the
-- database.
CREATE TABLE profile_approver_key (
    key_id TEXT PRIMARY KEY CHECK (key_id ~ '^[A-Za-z0-9._-]{1,64}$'),
    issuer TEXT NOT NULL CHECK (length(issuer) BETWEEN 1 AND 1024),
    subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 256),
    public_key_sec1 BYTEA NOT NULL UNIQUE
        CHECK (octet_length(public_key_sec1) = 65 AND get_byte(public_key_sec1, 0) = 4),
    registered_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    revoked_at TIMESTAMPTZ CHECK (revoked_at IS NULL OR revoked_at >= registered_at)
);
CREATE UNIQUE INDEX profile_approver_key_one_active
    ON profile_approver_key (issuer, subject) WHERE revoked_at IS NULL;
REVOKE ALL ON profile_approver_key FROM PUBLIC;

-- A key is never deleted or changed; it can only be revoked once.
CREATE FUNCTION profile_approver_key_guard() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    IF TG_OP = 'DELETE' OR OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL
       OR (NEW.key_id, NEW.issuer, NEW.subject, NEW.public_key_sec1, NEW.registered_at)
          IS DISTINCT FROM (OLD.key_id, OLD.issuer, OLD.subject, OLD.public_key_sec1, OLD.registered_at) THEN
        RAISE EXCEPTION 'approver keys are append-only; only a single revocation is allowed';
    END IF;
    RETURN NEW;
END
$fn$;
REVOKE ALL ON FUNCTION profile_approver_key_guard() FROM PUBLIC;
CREATE TRIGGER profile_approver_key_append_only
    BEFORE UPDATE OR DELETE ON profile_approver_key
    FOR EACH ROW EXECUTE FUNCTION profile_approver_key_guard();

ALTER TABLE profile_lifecycle_event DROP CONSTRAINT profile_lifecycle_event_action_check;
ALTER TABLE profile_lifecycle_event ADD CONSTRAINT profile_lifecycle_event_action_check
    CHECK (action IN ('draft.created', 'draft.submitted', 'draft.approval', 'draft.rejection'));

CREATE TABLE certificate_profile_decision (
    ca_id UUID NOT NULL,
    profile_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    approver_issuer TEXT NOT NULL,
    approver_subject TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('approve', 'reject')),
    key_id TEXT NOT NULL REFERENCES profile_approver_key (key_id),
    public_key_sec1 BYTEA NOT NULL,
    claim TEXT NOT NULL CHECK (length(claim) BETWEEN 1 AND 4096),
    signature_der BYTEA NOT NULL CHECK (octet_length(signature_der) BETWEEN 8 AND 80),
    claim_issued_at TIMESTAMPTZ NOT NULL,
    event_id UUID NOT NULL UNIQUE REFERENCES profile_lifecycle_event (event_id),
    decided_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (ca_id, profile_id, revision, approver_issuer, approver_subject),
    -- Two decisions on one revision never share a key.
    UNIQUE (ca_id, profile_id, revision, public_key_sec1),
    FOREIGN KEY (ca_id, profile_id, revision)
        REFERENCES certificate_profile_submission (ca_id, profile_id, revision)
);
REVOKE ALL ON certificate_profile_decision FROM PUBLIC;
CREATE TRIGGER immutable_profile_decision
    BEFORE UPDATE OR DELETE ON certificate_profile_decision
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

-- The exact text an approver signs: one line, fields in a fixed order. The
-- functions refuse identities containing ';' or control characters, so the
-- line has one parse.
CREATE FUNCTION profile_decision_claim(
    p_decision TEXT, p_ca UUID, p_profile TEXT, p_revision INTEGER, p_snapshot_sha256 BYTEA,
    p_submission_event UUID, p_issuer TEXT, p_subject TEXT, p_key_id TEXT, p_issued_at TIMESTAMPTZ
) RETURNS TEXT LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $fn$
    SELECT concat_ws(';',
        'trust-platform/profile-decision/v1',
        'decision=' || p_decision,
        'ca_id=' || p_ca::text,
        'profile_id=' || p_profile,
        'revision=' || p_revision::text,
        'snapshot_sha256=' || encode(p_snapshot_sha256, 'hex'),
        'submission_event_id=' || p_submission_event::text,
        'approver_issuer=' || p_issuer,
        'approver_subject=' || p_subject,
        'key_id=' || p_key_id,
        'issued_at=' || to_char(p_issued_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))
$fn$;
REVOKE ALL ON FUNCTION profile_decision_claim(TEXT, UUID, TEXT, INTEGER, BYTEA, UUID, TEXT, TEXT, TEXT, TIMESTAMPTZ)
    FROM PUBLIC;

-- Checks shared by preparing and recording a decision. Returns the
-- submission it applies to, the approver's active key, and the claim.
CREATE FUNCTION profile_decision_context(
    p_issuer TEXT, p_subject TEXT, p_ca UUID, p_profile TEXT, p_revision INTEGER, p_decision TEXT,
    p_issued_at TIMESTAMPTZ
) RETURNS TABLE (claim TEXT, key_id TEXT, public_key_sec1 BYTEA, snapshot_sha256 BYTEA, policy_version TEXT)
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_submission certificate_profile_submission%ROWTYPE;
    v_key profile_approver_key%ROWTYPE;
    v_policy TEXT;
BEGIN
    IF p_issuer IS NULL OR p_subject IS NULL OR p_ca IS NULL OR p_profile IS NULL OR p_revision IS NULL
       OR p_decision IS NULL OR p_decision NOT IN ('approve', 'reject') OR p_issued_at IS NULL
       OR length(p_subject) NOT BETWEEN 1 AND 256 OR length(p_issuer) NOT BETWEEN 1 AND 1024
       OR p_issuer ~ '[;[:cntrl:]]' OR p_subject ~ '[;[:cntrl:]]' THEN
        RAISE EXCEPTION 'invalid profile decision parameters' USING ERRCODE = '22023';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM management_role_grant g
                   WHERE g.issuer = p_issuer AND g.subject = p_subject AND g.ca_id = p_ca
                     AND g.lifecycle_role = 'policy-approver') THEN
        RAISE EXCEPTION 'no policy-approver grant for this CA' USING ERRCODE = '42501';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM certificate_profile_draft d
                   WHERE d.ca_id = p_ca AND d.profile_id = p_profile AND d.revision = p_revision) THEN
        RAISE EXCEPTION 'unknown profile revision' USING ERRCODE = 'P0002';
    END IF;
    SELECT * INTO v_submission FROM certificate_profile_submission s
    WHERE s.ca_id = p_ca AND s.profile_id = p_profile AND s.revision = p_revision;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'revision is not submitted' USING ERRCODE = 'TP409';
    END IF;
    IF EXISTS (SELECT 1 FROM certificate_profile_decision x
               WHERE x.ca_id = p_ca AND x.profile_id = p_profile AND x.revision = p_revision
                 AND (x.decision = 'reject'
                      OR (SELECT count(*) FROM certificate_profile_decision y
                          WHERE y.ca_id = p_ca AND y.profile_id = p_profile AND y.revision = p_revision
                            AND y.decision = 'approve') >= 2)) THEN
        RAISE EXCEPTION 'revision already decided' USING ERRCODE = 'TP409';
    END IF;
    IF EXISTS (SELECT 1 FROM certificate_profile_decision x
               WHERE x.ca_id = p_ca AND x.profile_id = p_profile AND x.revision = p_revision
                 AND x.approver_issuer = p_issuer AND x.approver_subject = p_subject) THEN
        RAISE EXCEPTION 'this approver already decided on the revision' USING ERRCODE = 'TP409';
    END IF;
    -- Separation of duties: the author and the submitter cannot decide.
    IF EXISTS (SELECT 1 FROM profile_lifecycle_event e
               WHERE e.ca_id = p_ca AND e.profile_id = p_profile AND e.revision = p_revision
                 AND e.action IN ('draft.created', 'draft.submitted')
                 AND e.actor_issuer = p_issuer AND e.actor_subject = p_subject)
       OR EXISTS (SELECT 1 FROM certificate_profile_draft d
                  WHERE d.ca_id = p_ca AND d.profile_id = p_profile AND d.revision = p_revision
                    AND d.created_by = p_subject
                    AND NOT EXISTS (SELECT 1 FROM profile_lifecycle_event e
                                    WHERE e.ca_id = d.ca_id AND e.profile_id = d.profile_id
                                      AND e.revision = d.revision AND e.action = 'draft.created')) THEN
        RAISE EXCEPTION 'the author or submitter of a revision cannot decide on it' USING ERRCODE = '42501';
    END IF;
    SELECT * INTO v_key FROM profile_approver_key k
    WHERE k.issuer = p_issuer AND k.subject = p_subject AND k.revoked_at IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no active approver key' USING ERRCODE = '42501';
    END IF;
    SELECT d.policy_version INTO v_policy FROM certificate_profile_draft d
    WHERE d.ca_id = p_ca AND d.profile_id = p_profile AND d.revision = p_revision;
    RETURN QUERY SELECT
        profile_decision_claim(p_decision, p_ca, p_profile, p_revision, v_submission.snapshot_sha256,
                               v_submission.event_id, p_issuer, p_subject, v_key.key_id, p_issued_at),
        v_key.key_id, v_key.public_key_sec1, v_submission.snapshot_sha256, v_policy;
END
$fn$;
REVOKE ALL ON FUNCTION profile_decision_context(TEXT, TEXT, UUID, TEXT, INTEGER, TEXT, TIMESTAMPTZ) FROM PUBLIC;

-- Returns the claim to sign now. Records nothing.
CREATE FUNCTION prepare_profile_decision_lab(
    p_issuer TEXT, p_subject TEXT, p_ca UUID, p_profile TEXT, p_revision INTEGER, p_decision TEXT
) RETURNS TABLE (claim TEXT, key_id TEXT, issued_at TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_now TIMESTAMPTZ := date_trunc('milliseconds', clock_timestamp());
BEGIN
    RETURN QUERY SELECT c.claim, c.key_id,
        to_char(v_now AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
        FROM profile_decision_context(p_issuer, p_subject, p_ca, p_profile, p_revision, p_decision, v_now) c;
END
$fn$;
REVOKE ALL ON FUNCTION prepare_profile_decision_lab(TEXT, TEXT, UUID, TEXT, INTEGER, TEXT) FROM PUBLIC;

-- Records a decision whose claim was issued less than ten minutes ago. The
-- API verifies the returned signature against the returned claim and key in
-- the same transaction, and rolls back when it does not verify.
CREATE FUNCTION record_profile_decision_lab(
    p_issuer TEXT, p_subject TEXT, p_ca UUID, p_profile TEXT, p_revision INTEGER, p_decision TEXT,
    p_issued_at TIMESTAMPTZ, p_signature_der BYTEA, p_operation UUID, p_request_sha256 BYTEA
) RETURNS TABLE (claim TEXT, public_key_sec1 BYTEA, signature_der BYTEA, lifecycle_status TEXT,
                 approval_count INTEGER, replayed BOOLEAN)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_prior profile_lifecycle_event%ROWTYPE;
    v_context RECORD;
    v_event UUID;
    v_now TIMESTAMPTZ := clock_timestamp();
    -- Computed before any IF: plpgsql ends an IF condition at the first THEN.
    v_action TEXT := CASE p_decision WHEN 'approve' THEN 'draft.approval' ELSE 'draft.rejection' END;
    v_audit_type TEXT := CASE p_decision WHEN 'approve' THEN 'profile.draft.approval' ELSE 'profile.draft.rejection' END;
BEGIN
    IF p_operation IS NULL OR p_request_sha256 IS NULL OR octet_length(p_request_sha256) <> 32
       OR p_signature_der IS NULL OR octet_length(p_signature_der) NOT BETWEEN 8 AND 80 THEN
        RAISE EXCEPTION 'invalid profile decision parameters' USING ERRCODE = '22023';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('profile:' || p_ca::text || '/' || p_profile, 0));

    SELECT * INTO v_prior FROM profile_lifecycle_event e WHERE e.operation_id = p_operation;
    IF FOUND THEN
        IF v_prior.action = v_action
           AND v_prior.request_sha256 = p_request_sha256 AND v_prior.ca_id = p_ca
           AND v_prior.profile_id = p_profile AND v_prior.revision = p_revision
           AND v_prior.actor_issuer = p_issuer AND v_prior.actor_subject = p_subject THEN
            RETURN QUERY SELECT x.claim, x.public_key_sec1, x.signature_der,
                profile_lifecycle_status(p_ca, p_profile, p_revision),
                profile_approval_count(p_ca, p_profile, p_revision), true
                FROM certificate_profile_decision x WHERE x.event_id = v_prior.event_id;
            RETURN;
        END IF;
        RAISE EXCEPTION 'idempotency key already used for another request' USING ERRCODE = 'TP409';
    END IF;

    IF p_issued_at IS NULL OR p_issued_at > v_now + interval '5 seconds'
       OR p_issued_at < v_now - interval '10 minutes' THEN
        RAISE EXCEPTION 'decision claim expired or not yet valid' USING ERRCODE = 'TP409';
    END IF;
    SELECT * INTO v_context
    FROM profile_decision_context(p_issuer, p_subject, p_ca, p_profile, p_revision, p_decision, p_issued_at);

    INSERT INTO profile_lifecycle_event
        (operation_id, request_sha256, action, ca_id, profile_id, revision, snapshot_sha256, policy_version,
         actor_issuer, actor_subject)
    VALUES (p_operation, p_request_sha256, v_action,
            p_ca, p_profile, p_revision, v_context.snapshot_sha256, v_context.policy_version, p_issuer, p_subject)
    RETURNING event_id INTO v_event;
    INSERT INTO certificate_profile_decision
        (ca_id, profile_id, revision, approver_issuer, approver_subject, decision, key_id, public_key_sec1,
         claim, signature_der, claim_issued_at, event_id)
    VALUES (p_ca, p_profile, p_revision, p_issuer, p_subject, p_decision, v_context.key_id,
            v_context.public_key_sec1, v_context.claim, p_signature_der, p_issued_at, v_event);
    INSERT INTO audit_event (event_id, ca_id, actor_id, event_type, decision, policy_version)
    VALUES (v_event, p_ca, p_subject, v_audit_type, 'allow', v_context.policy_version);

    RETURN QUERY SELECT v_context.claim, v_context.public_key_sec1, p_signature_der,
        profile_lifecycle_status(p_ca, p_profile, p_revision),
        profile_approval_count(p_ca, p_profile, p_revision), false;
END
$fn$;

CREATE FUNCTION profile_approval_count(p_ca UUID, p_profile TEXT, p_revision INTEGER) RETURNS INTEGER
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $fn$
    SELECT count(*)::integer FROM certificate_profile_decision x
    WHERE x.ca_id = p_ca AND x.profile_id = p_profile AND x.revision = p_revision AND x.decision = 'approve'
$fn$;
REVOKE ALL ON FUNCTION profile_approval_count(UUID, TEXT, INTEGER) FROM PUBLIC;

-- DRAFT → SUBMITTED → APPROVED (two approvals) or REJECTED (one rejection).
CREATE FUNCTION profile_lifecycle_status(p_ca UUID, p_profile TEXT, p_revision INTEGER) RETURNS TEXT
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $fn$
    SELECT CASE
        WHEN EXISTS (SELECT 1 FROM certificate_profile_decision x
                     WHERE x.ca_id = p_ca AND x.profile_id = p_profile AND x.revision = p_revision
                       AND x.decision = 'reject') THEN 'REJECTED'
        WHEN profile_approval_count(p_ca, p_profile, p_revision) >= 2 THEN 'APPROVED'
        WHEN EXISTS (SELECT 1 FROM certificate_profile_submission s
                     WHERE s.ca_id = p_ca AND s.profile_id = p_profile AND s.revision = p_revision) THEN 'SUBMITTED'
        ELSE 'DRAFT'
    END
$fn$;
REVOKE ALL ON FUNCTION profile_lifecycle_status(UUID, TEXT, INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION record_profile_decision_lab(TEXT, TEXT, UUID, TEXT, INTEGER, TEXT, TIMESTAMPTZ, BYTEA, UUID, BYTEA)
    FROM PUBLIC;

GRANT EXECUTE ON FUNCTION prepare_profile_decision_lab(TEXT, TEXT, UUID, TEXT, INTEGER, TEXT) TO trust_profile_writer;
GRANT EXECUTE ON FUNCTION record_profile_decision_lab(TEXT, TEXT, UUID, TEXT, INTEGER, TEXT, TIMESTAMPTZ, BYTEA, UUID, BYTEA)
    TO trust_profile_writer;

-- Readers see the decided state and the number of approvals; the
-- approvers' identities, claims and signatures stay owner-only. The status
-- logic is inlined: functions called by a view run with the reader's
-- privileges, which do not reach the decision table.
CREATE OR REPLACE VIEW management_profile_draft WITH (security_barrier = true) AS
SELECT d.ca_id::text AS ca_id, d.profile_id, d.revision, d.display_name,
       d.policy_version, d.max_validity_days, d.max_dns_sans,
       d.proposed_dns_zones, d.proposed_signature_suites,
       d.created_by,
       to_char(d.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
       CASE WHEN x.rejections > 0 THEN 'REJECTED'
            WHEN x.approvals >= 2 THEN 'APPROVED'
            WHEN s.revision IS NOT NULL THEN 'SUBMITTED'
            ELSE 'DRAFT' END AS lifecycle_status,
       to_char(s.submitted_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS submitted_at,
       x.approvals AS approval_count,
       CASE WHEN x.rejections > 0 OR x.approvals >= 2
            THEN to_char(x.last_decided_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END AS decided_at
FROM certificate_profile_draft d
LEFT JOIN certificate_profile_submission s
    ON s.ca_id = d.ca_id AND s.profile_id = d.profile_id AND s.revision = d.revision
CROSS JOIN LATERAL (
    SELECT count(*) FILTER (WHERE c.decision = 'approve')::integer AS approvals,
           count(*) FILTER (WHERE c.decision = 'reject')::integer AS rejections,
           max(c.decided_at) AS last_decided_at
    FROM certificate_profile_decision c
    WHERE c.ca_id = d.ca_id AND c.profile_id = d.profile_id AND c.revision = d.revision
) x
WHERE EXISTS (
    SELECT 1 FROM management_reader_grant g
    WHERE g.issuer = current_setting('trust.reader_issuer', true)
      AND g.subject = current_setting('trust.reader_subject', true)
      AND g.ca_id = d.ca_id
);

CREATE FUNCTION management_profile_decision_version() RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $fn$ SELECT 1 $fn$;
REVOKE ALL ON FUNCTION management_profile_decision_version() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION management_profile_decision_version() TO trust_api_reader, trust_profile_writer;

COMMIT;
