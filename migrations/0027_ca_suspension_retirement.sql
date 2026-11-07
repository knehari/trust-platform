-- Migration 0027: suspension, reactivation and retirement of activated CAs
-- (MVP criterion 6, CA lifecycle, third slice; ADR-0015, Proposed).
-- Laboratory only.
--
-- Stopping is easy, resuming or ending is controlled:
-- * one CA administrator suspends an ACTIVE CA immediately;
-- * reactivating a SUSPENDED CA, or retiring a CA, needs a change request
--   by an administrator, two signed approvals by distinct CA approvers with
--   distinct registered keys (as in 0026; the requester cannot decide), then
--   its application by an administrator who did not decide. RETIRED is
--   final.
--
-- While a CA is not ACTIVE, no profile revision can be activated for it.
-- Retiring a CA retires its active profile revisions in the same
-- transaction; nothing is deleted from history. CAs the owner created
-- directly (not through 0026) have no operational state and are unchanged.
--
-- PostgreSQL does not verify ECDSA: the API verifies each signature in the
-- recording transaction, and lab_verify_ca_lifecycle re-checks every stored
-- decision and applied change.
BEGIN;

ALTER TABLE ca_lifecycle_event DROP CONSTRAINT ca_lifecycle_event_action_check;
ALTER TABLE ca_lifecycle_event ADD CONSTRAINT ca_lifecycle_event_action_check
    CHECK (action IN ('ca.proposed', 'ca.certificate_registered', 'ca.approval', 'ca.rejection', 'ca.activation',
                      'ca.suspension', 'ca.change_requested', 'ca.change_approval', 'ca.change_rejection',
                      'ca.reactivation', 'ca.retirement'));

-- The only mutable CA state: the operational state of an activated CA. Only
-- the functions below change it, and every change has a history row.
CREATE TABLE ca_operational_state (
    ca_id UUID PRIMARY KEY REFERENCES ca_activation (ca_id),
    state TEXT NOT NULL CHECK (state IN ('ACTIVE', 'SUSPENDED', 'RETIRED')),
    changed_event_id UUID NOT NULL REFERENCES ca_lifecycle_event (event_id),
    changed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON ca_operational_state FROM PUBLIC;

-- CAs activated before this migration start ACTIVE, from their activation.
INSERT INTO ca_operational_state (ca_id, state, changed_event_id, changed_at)
SELECT a.ca_id, 'ACTIVE', a.event_id, a.activated_at FROM ca_activation a;

-- Activation (0026) starts every new CA ACTIVE.
CREATE FUNCTION ca_activation_starts_active() RETURNS TRIGGER
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $fn$
BEGIN
    INSERT INTO ca_operational_state (ca_id, state, changed_event_id) VALUES (NEW.ca_id, 'ACTIVE', NEW.event_id);
    RETURN NEW;
END
$fn$;
REVOKE ALL ON FUNCTION ca_activation_starts_active() FROM PUBLIC;
CREATE TRIGGER ca_activation_starts_active AFTER INSERT ON ca_activation
    FOR EACH ROW EXECUTE FUNCTION ca_activation_starts_active();

CREATE TABLE ca_state_change (
    change_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ca_id UUID NOT NULL REFERENCES ca_activation (ca_id),
    action TEXT NOT NULL CHECK (action IN ('suspend', 'reactivate', 'retire')),
    from_state TEXT NOT NULL,
    to_state TEXT NOT NULL,
    event_id UUID NOT NULL UNIQUE REFERENCES ca_lifecycle_event (event_id),
    reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 500 AND reason !~ '[[:cntrl:]]'),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON ca_state_change FROM PUBLIC;
CREATE TRIGGER immutable_ca_state_change
    BEFORE UPDATE OR DELETE ON ca_state_change
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

-- A request to reactivate or retire a CA, from the state it was made in.
-- At most one open request per CA: not rejected, not applied, and made in
-- the CA's current state. A request overtaken by a state change (for
-- example a suspension after approval) is stale: it can no longer be
-- decided or applied, and does not block a new request.
CREATE TABLE ca_change_request (
    request_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ca_id UUID NOT NULL REFERENCES ca_activation (ca_id),
    action TEXT NOT NULL CHECK (action IN ('reactivate', 'retire')),
    from_state TEXT NOT NULL CHECK (from_state IN ('ACTIVE', 'SUSPENDED')),
    reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 500 AND reason !~ '[[:cntrl:]]'),
    reason_sha256 BYTEA GENERATED ALWAYS AS (digest(reason, 'sha256')) STORED,
    requested_event_id UUID NOT NULL UNIQUE REFERENCES ca_lifecycle_event (event_id),
    requested_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON ca_change_request FROM PUBLIC;
CREATE TRIGGER immutable_ca_change_request
    BEFORE UPDATE OR DELETE ON ca_change_request
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

CREATE TABLE ca_change_decision (
    request_id UUID NOT NULL REFERENCES ca_change_request (request_id),
    approver_issuer TEXT NOT NULL,
    approver_subject TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('approve', 'reject')),
    key_id TEXT NOT NULL REFERENCES ca_approver_key (key_id),
    public_key_sec1 BYTEA NOT NULL,
    claim TEXT NOT NULL CHECK (length(claim) BETWEEN 1 AND 4096),
    signature_der BYTEA NOT NULL CHECK (octet_length(signature_der) BETWEEN 8 AND 80),
    claim_issued_at TIMESTAMPTZ NOT NULL,
    event_id UUID NOT NULL UNIQUE REFERENCES ca_lifecycle_event (event_id),
    decided_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (request_id, approver_issuer, approver_subject),
    UNIQUE (request_id, public_key_sec1)
);
REVOKE ALL ON ca_change_decision FROM PUBLIC;
CREATE TRIGGER immutable_ca_change_decision
    BEFORE UPDATE OR DELETE ON ca_change_decision
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

CREATE TABLE ca_change_application (
    request_id UUID PRIMARY KEY REFERENCES ca_change_request (request_id),
    change_id UUID NOT NULL UNIQUE REFERENCES ca_state_change (change_id),
    -- Active profile revisions the change retired (retirement only).
    retired_revisions INTEGER NOT NULL CHECK (retired_revisions >= 0),
    applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON ca_change_application FROM PUBLIC;
CREATE TRIGGER immutable_ca_change_application
    BEFORE UPDATE OR DELETE ON ca_change_application
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

-- OPEN → APPROVED (two approvals) or REJECTED (one rejection) → APPLIED.
CREATE FUNCTION ca_change_request_status(p_request UUID) RETURNS TEXT
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $fn$
    SELECT CASE
        WHEN NOT EXISTS (SELECT 1 FROM ca_change_request r WHERE r.request_id = p_request) THEN NULL
        WHEN EXISTS (SELECT 1 FROM ca_change_application a WHERE a.request_id = p_request) THEN 'APPLIED'
        WHEN EXISTS (SELECT 1 FROM ca_change_decision d WHERE d.request_id = p_request AND d.decision = 'reject')
            THEN 'REJECTED'
        WHEN (SELECT count(*) FROM ca_change_decision d WHERE d.request_id = p_request AND d.decision = 'approve') >= 2
            THEN 'APPROVED'
        ELSE 'OPEN'
    END
$fn$;
REVOKE ALL ON FUNCTION ca_change_request_status(UUID) FROM PUBLIC;

-- No profile revision is activated for a CA that is not ACTIVE. CAs without
-- an operational state (created directly by the owner) are not affected.
CREATE FUNCTION profile_activation_needs_active_ca() RETURNS TRIGGER
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $fn$
BEGIN
    IF EXISTS (SELECT 1 FROM ca_operational_state s WHERE s.ca_id = NEW.ca_id AND s.state <> 'ACTIVE') THEN
        RAISE EXCEPTION 'the CA is suspended or retired' USING ERRCODE = 'TP409';
    END IF;
    RETURN NEW;
END
$fn$;
REVOKE ALL ON FUNCTION profile_activation_needs_active_ca() FROM PUBLIC;
CREATE TRIGGER profile_activation_needs_active_ca BEFORE INSERT ON certificate_profile_active
    FOR EACH ROW EXECUTE FUNCTION profile_activation_needs_active_ca();

-- Suspends an ACTIVE CA at once. Errors: 42501 forbidden, P0002 unknown,
-- TP409 not ACTIVE, 22023/23514 invalid input.
CREATE FUNCTION suspend_ca_lab(
    p_issuer TEXT, p_subject TEXT, p_ca UUID, p_reason TEXT, p_operation UUID, p_request_sha256 BYTEA
) RETURNS TABLE (operational_state TEXT, replayed BOOLEAN)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_prior ca_lifecycle_event%ROWTYPE;
    v_state ca_operational_state%ROWTYPE;
    v_event UUID;
BEGIN
    IF p_issuer IS NULL OR p_subject IS NULL OR p_ca IS NULL OR p_reason IS NULL OR p_operation IS NULL
       OR p_request_sha256 IS NULL OR octet_length(p_request_sha256) <> 32
       OR length(p_subject) NOT BETWEEN 1 AND 256 OR length(p_issuer) NOT BETWEEN 1 AND 1024 THEN
        RAISE EXCEPTION 'invalid CA suspension parameters' USING ERRCODE = '22023';
    END IF;
    IF NOT ca_platform_granted(p_issuer, p_subject, 'ca-administrator') THEN
        RAISE EXCEPTION 'no ca-administrator grant' USING ERRCODE = '42501';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('ca:' || p_ca::text, 0));

    SELECT * INTO v_prior FROM ca_lifecycle_event e WHERE e.operation_id = p_operation;
    IF FOUND THEN
        IF v_prior.action = 'ca.suspension' AND v_prior.request_sha256 = p_request_sha256 AND v_prior.ca_id = p_ca
           AND v_prior.actor_issuer = p_issuer AND v_prior.actor_subject = p_subject THEN
            RETURN QUERY SELECT c.to_state, true FROM ca_state_change c WHERE c.event_id = v_prior.event_id;
            RETURN;
        END IF;
        RAISE EXCEPTION 'idempotency key already used for another request' USING ERRCODE = 'TP409';
    END IF;

    SELECT * INTO v_state FROM ca_operational_state s WHERE s.ca_id = p_ca;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown activated CA' USING ERRCODE = 'P0002';
    END IF;
    IF v_state.state <> 'ACTIVE' THEN
        RAISE EXCEPTION 'only an ACTIVE CA can be suspended' USING ERRCODE = 'TP409';
    END IF;

    INSERT INTO ca_lifecycle_event (operation_id, request_sha256, action, ca_id, actor_issuer, actor_subject)
    VALUES (p_operation, p_request_sha256, 'ca.suspension', p_ca, p_issuer, p_subject)
    RETURNING event_id INTO v_event;
    INSERT INTO ca_state_change (ca_id, action, from_state, to_state, event_id, reason)
    VALUES (p_ca, 'suspend', 'ACTIVE', 'SUSPENDED', v_event, p_reason);
    UPDATE ca_operational_state SET state = 'SUSPENDED', changed_event_id = v_event, changed_at = clock_timestamp()
    WHERE ca_id = p_ca;
    INSERT INTO audit_event (event_id, ca_id, actor_id, event_type, decision, policy_version)
    VALUES (v_event, p_ca, p_subject, 'ca.suspension', 'allow', (SELECT c.policy_version FROM ca c WHERE c.ca_id = p_ca));

    RETURN QUERY SELECT 'SUSPENDED'::text, false;
END
$fn$;
REVOKE ALL ON FUNCTION suspend_ca_lab(TEXT, TEXT, UUID, TEXT, UUID, BYTEA) FROM PUBLIC;

-- Records a request to reactivate a SUSPENDED CA or retire an ACTIVE or
-- SUSPENDED one. One open request per CA.
CREATE FUNCTION request_ca_change_lab(
    p_issuer TEXT, p_subject TEXT, p_ca UUID, p_action TEXT, p_reason TEXT, p_operation UUID, p_request_sha256 BYTEA
) RETURNS TABLE (request_id UUID, from_state TEXT, replayed BOOLEAN)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_prior ca_lifecycle_event%ROWTYPE;
    v_state ca_operational_state%ROWTYPE;
    v_event UUID;
    v_request UUID;
BEGIN
    IF p_issuer IS NULL OR p_subject IS NULL OR p_ca IS NULL OR p_reason IS NULL OR p_operation IS NULL
       OR p_action IS NULL OR p_action NOT IN ('reactivate', 'retire')
       OR p_request_sha256 IS NULL OR octet_length(p_request_sha256) <> 32
       OR length(p_subject) NOT BETWEEN 1 AND 256 OR length(p_issuer) NOT BETWEEN 1 AND 1024 THEN
        RAISE EXCEPTION 'invalid CA change request parameters' USING ERRCODE = '22023';
    END IF;
    IF NOT ca_platform_granted(p_issuer, p_subject, 'ca-administrator') THEN
        RAISE EXCEPTION 'no ca-administrator grant' USING ERRCODE = '42501';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('ca:' || p_ca::text, 0));

    SELECT * INTO v_prior FROM ca_lifecycle_event e WHERE e.operation_id = p_operation;
    IF FOUND THEN
        IF v_prior.action = 'ca.change_requested' AND v_prior.request_sha256 = p_request_sha256
           AND v_prior.ca_id = p_ca AND v_prior.actor_issuer = p_issuer AND v_prior.actor_subject = p_subject THEN
            RETURN QUERY SELECT r.request_id, r.from_state, true
                FROM ca_change_request r WHERE r.requested_event_id = v_prior.event_id;
            RETURN;
        END IF;
        RAISE EXCEPTION 'idempotency key already used for another request' USING ERRCODE = 'TP409';
    END IF;

    SELECT * INTO v_state FROM ca_operational_state s WHERE s.ca_id = p_ca;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown activated CA' USING ERRCODE = 'P0002';
    END IF;
    IF v_state.state = 'RETIRED' OR (p_action = 'reactivate' AND v_state.state <> 'SUSPENDED') THEN
        RAISE EXCEPTION 'this change does not apply to the CA''s state' USING ERRCODE = 'TP409';
    END IF;
    IF EXISTS (SELECT 1 FROM ca_change_request r
               WHERE r.ca_id = p_ca AND r.from_state = v_state.state
                 AND ca_change_request_status(r.request_id) IN ('OPEN', 'APPROVED')) THEN
        RAISE EXCEPTION 'the CA already has an open change request' USING ERRCODE = 'TP409';
    END IF;

    INSERT INTO ca_lifecycle_event (operation_id, request_sha256, action, ca_id, actor_issuer, actor_subject)
    VALUES (p_operation, p_request_sha256, 'ca.change_requested', p_ca, p_issuer, p_subject)
    RETURNING event_id INTO v_event;
    INSERT INTO ca_change_request (ca_id, action, from_state, reason, requested_event_id)
    VALUES (p_ca, p_action, v_state.state, p_reason, v_event)
    RETURNING ca_change_request.request_id INTO v_request;
    INSERT INTO audit_event (event_id, ca_id, actor_id, event_type, decision, policy_version)
    VALUES (v_event, p_ca, p_subject, 'ca.change_requested', 'allow',
            (SELECT c.policy_version FROM ca c WHERE c.ca_id = p_ca));

    RETURN QUERY SELECT v_request, v_state.state, false;
END
$fn$;
REVOKE ALL ON FUNCTION request_ca_change_lab(TEXT, TEXT, UUID, TEXT, TEXT, UUID, BYTEA) FROM PUBLIC;

-- The exact text a CA approver signs for a change request.
CREATE FUNCTION ca_change_decision_claim(
    p_decision TEXT, p_request UUID, p_ca UUID, p_action TEXT, p_from_state TEXT, p_reason_sha256 BYTEA,
    p_certificate_sha256 BYTEA, p_issuer TEXT, p_subject TEXT, p_key_id TEXT, p_issued_at TIMESTAMPTZ
) RETURNS TEXT LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $fn$
    SELECT concat_ws(';',
        'trust-platform/ca-change-decision/v1',
        'decision=' || p_decision,
        'action=' || p_action,
        'request_id=' || p_request::text,
        'ca_id=' || p_ca::text,
        'from_state=' || p_from_state,
        'reason_sha256=' || encode(p_reason_sha256, 'hex'),
        'certificate_sha256=' || encode(p_certificate_sha256, 'hex'),
        'approver_issuer=' || p_issuer,
        'approver_subject=' || p_subject,
        'key_id=' || p_key_id,
        'issued_at=' || to_char(p_issued_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))
$fn$;
REVOKE ALL ON FUNCTION ca_change_decision_claim(TEXT, UUID, UUID, TEXT, TEXT, BYTEA, BYTEA, TEXT, TEXT, TEXT, TIMESTAMPTZ)
    FROM PUBLIC;

-- Checks shared by preparing and recording a decision on a change request.
CREATE FUNCTION ca_change_decision_context(
    p_issuer TEXT, p_subject TEXT, p_ca UUID, p_request UUID, p_decision TEXT, p_issued_at TIMESTAMPTZ
) RETURNS TABLE (claim TEXT, key_id TEXT, public_key_sec1 BYTEA, action TEXT, policy_version TEXT)
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_request ca_change_request%ROWTYPE;
    v_key ca_approver_key%ROWTYPE;
    v_status TEXT;
BEGIN
    IF p_issuer IS NULL OR p_subject IS NULL OR p_ca IS NULL OR p_request IS NULL OR p_decision IS NULL
       OR p_decision NOT IN ('approve', 'reject') OR p_issued_at IS NULL
       OR length(p_subject) NOT BETWEEN 1 AND 256 OR length(p_issuer) NOT BETWEEN 1 AND 1024
       OR p_issuer ~ '[;[:cntrl:]]' OR p_subject ~ '[;[:cntrl:]]' THEN
        RAISE EXCEPTION 'invalid CA change decision parameters' USING ERRCODE = '22023';
    END IF;
    IF NOT ca_platform_granted(p_issuer, p_subject, 'ca-approver') THEN
        RAISE EXCEPTION 'no ca-approver grant' USING ERRCODE = '42501';
    END IF;
    SELECT * INTO v_request FROM ca_change_request r WHERE r.request_id = p_request AND r.ca_id = p_ca;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown CA change request' USING ERRCODE = 'P0002';
    END IF;
    v_status := ca_change_request_status(p_request);
    IF v_status <> 'OPEN' THEN
        RAISE EXCEPTION 'the change request is not awaiting decisions' USING ERRCODE = 'TP409';
    END IF;
    -- The request is decided in the state it was made in.
    IF (SELECT s.state FROM ca_operational_state s WHERE s.ca_id = p_ca) IS DISTINCT FROM v_request.from_state THEN
        RAISE EXCEPTION 'the CA changed state since the request' USING ERRCODE = 'TP409';
    END IF;
    IF EXISTS (SELECT 1 FROM ca_change_decision d
               WHERE d.request_id = p_request AND d.approver_issuer = p_issuer AND d.approver_subject = p_subject) THEN
        RAISE EXCEPTION 'this approver already decided on the request' USING ERRCODE = 'TP409';
    END IF;
    -- Separation of duties: the requester cannot decide.
    IF EXISTS (SELECT 1 FROM ca_lifecycle_event e
               WHERE e.event_id = v_request.requested_event_id
                 AND e.actor_issuer = p_issuer AND e.actor_subject = p_subject) THEN
        RAISE EXCEPTION 'the requester of a change cannot decide on it' USING ERRCODE = '42501';
    END IF;
    SELECT * INTO v_key FROM ca_approver_key k
    WHERE k.issuer = p_issuer AND k.subject = p_subject AND k.revoked_at IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no active CA approver key' USING ERRCODE = '42501';
    END IF;
    RETURN QUERY SELECT
        ca_change_decision_claim(p_decision, p_request, p_ca, v_request.action, v_request.from_state,
                                 v_request.reason_sha256, c.certificate_sha256, p_issuer, p_subject, v_key.key_id,
                                 p_issued_at),
        v_key.key_id, v_key.public_key_sec1, v_request.action,
        (SELECT x.policy_version FROM ca x WHERE x.ca_id = p_ca)
        FROM ca_issuer_certificate c WHERE c.ca_id = p_ca;
END
$fn$;
REVOKE ALL ON FUNCTION ca_change_decision_context(TEXT, TEXT, UUID, UUID, TEXT, TIMESTAMPTZ) FROM PUBLIC;

CREATE FUNCTION prepare_ca_change_decision_lab(
    p_issuer TEXT, p_subject TEXT, p_ca UUID, p_request UUID, p_decision TEXT
) RETURNS TABLE (claim TEXT, key_id TEXT, issued_at TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_now TIMESTAMPTZ := date_trunc('milliseconds', clock_timestamp());
BEGIN
    RETURN QUERY SELECT c.claim, c.key_id, to_char(v_now AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
        FROM ca_change_decision_context(p_issuer, p_subject, p_ca, p_request, p_decision, v_now) c;
END
$fn$;
REVOKE ALL ON FUNCTION prepare_ca_change_decision_lab(TEXT, TEXT, UUID, UUID, TEXT) FROM PUBLIC;

-- Records a decision whose claim was issued less than ten minutes ago; the
-- API verifies the signature before commit.
CREATE FUNCTION record_ca_change_decision_lab(
    p_issuer TEXT, p_subject TEXT, p_ca UUID, p_request UUID, p_decision TEXT, p_issued_at TIMESTAMPTZ,
    p_signature_der BYTEA, p_operation UUID, p_request_sha256 BYTEA
) RETURNS TABLE (claim TEXT, public_key_sec1 BYTEA, signature_der BYTEA, request_status TEXT,
                 approval_count INTEGER, replayed BOOLEAN)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_prior ca_lifecycle_event%ROWTYPE;
    v_context RECORD;
    v_event UUID;
    v_now TIMESTAMPTZ := clock_timestamp();
    v_action TEXT := CASE p_decision WHEN 'approve' THEN 'ca.change_approval' ELSE 'ca.change_rejection' END;
BEGIN
    IF p_ca IS NULL OR p_request IS NULL OR p_operation IS NULL OR p_request_sha256 IS NULL
       OR octet_length(p_request_sha256) <> 32
       OR p_signature_der IS NULL OR octet_length(p_signature_der) NOT BETWEEN 8 AND 80 THEN
        RAISE EXCEPTION 'invalid CA change decision parameters' USING ERRCODE = '22023';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('ca:' || p_ca::text, 0));

    SELECT * INTO v_prior FROM ca_lifecycle_event e WHERE e.operation_id = p_operation;
    IF FOUND THEN
        IF v_prior.action = v_action AND v_prior.request_sha256 = p_request_sha256 AND v_prior.ca_id = p_ca
           AND v_prior.actor_issuer = p_issuer AND v_prior.actor_subject = p_subject THEN
            RETURN QUERY SELECT d.claim, d.public_key_sec1, d.signature_der, ca_change_request_status(p_request),
                (SELECT count(*)::integer FROM ca_change_decision y
                 WHERE y.request_id = p_request AND y.decision = 'approve'), true
                FROM ca_change_decision d WHERE d.event_id = v_prior.event_id AND d.request_id = p_request;
            RETURN;
        END IF;
        RAISE EXCEPTION 'idempotency key already used for another request' USING ERRCODE = 'TP409';
    END IF;

    IF p_issued_at IS NULL OR p_issued_at > v_now + interval '5 seconds'
       OR p_issued_at < v_now - interval '10 minutes' THEN
        RAISE EXCEPTION 'decision claim expired or not yet valid' USING ERRCODE = 'TP409';
    END IF;
    SELECT * INTO v_context
    FROM ca_change_decision_context(p_issuer, p_subject, p_ca, p_request, p_decision, p_issued_at);

    INSERT INTO ca_lifecycle_event (operation_id, request_sha256, action, ca_id, actor_issuer, actor_subject)
    VALUES (p_operation, p_request_sha256, v_action, p_ca, p_issuer, p_subject)
    RETURNING event_id INTO v_event;
    INSERT INTO ca_change_decision (request_id, approver_issuer, approver_subject, decision, key_id, public_key_sec1,
                                    claim, signature_der, claim_issued_at, event_id)
    VALUES (p_request, p_issuer, p_subject, p_decision, v_context.key_id, v_context.public_key_sec1, v_context.claim,
            p_signature_der, p_issued_at, v_event);
    INSERT INTO audit_event (event_id, ca_id, actor_id, event_type, decision, policy_version)
    VALUES (v_event, p_ca, p_subject, v_action, 'allow', v_context.policy_version);

    RETURN QUERY SELECT v_context.claim, v_context.public_key_sec1, p_signature_der,
        ca_change_request_status(p_request),
        (SELECT count(*)::integer FROM ca_change_decision y WHERE y.request_id = p_request AND y.decision = 'approve'),
        false;
END
$fn$;
REVOKE ALL ON FUNCTION record_ca_change_decision_lab(TEXT, TEXT, UUID, UUID, TEXT, TIMESTAMPTZ, BYTEA, UUID, BYTEA)
    FROM PUBLIC;

-- Applies an APPROVED request: reactivates the CA, or retires it and its
-- active profile revisions. Errors: 42501 forbidden (grant, or an approver
-- of the request), P0002 unknown, TP409 not approved, already applied or
-- the CA changed state, TP422 reactivation of an expired certificate.
CREATE FUNCTION apply_ca_change_lab(
    p_issuer TEXT, p_subject TEXT, p_ca UUID, p_request UUID, p_operation UUID, p_request_sha256 BYTEA
) RETURNS TABLE (operational_state TEXT, retired_revisions INTEGER, replayed BOOLEAN)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_prior ca_lifecycle_event%ROWTYPE;
    v_request ca_change_request%ROWTYPE;
    v_to TEXT;
    v_event UUID;
    v_change UUID;
    v_retired INTEGER := 0;
    v_revision RECORD;
    v_policy TEXT;
    v_event_action TEXT;
BEGIN
    IF p_issuer IS NULL OR p_subject IS NULL OR p_ca IS NULL OR p_request IS NULL OR p_operation IS NULL
       OR p_request_sha256 IS NULL OR octet_length(p_request_sha256) <> 32
       OR length(p_subject) NOT BETWEEN 1 AND 256 OR length(p_issuer) NOT BETWEEN 1 AND 1024 THEN
        RAISE EXCEPTION 'invalid CA change application parameters' USING ERRCODE = '22023';
    END IF;
    IF NOT ca_platform_granted(p_issuer, p_subject, 'ca-administrator') THEN
        RAISE EXCEPTION 'no ca-administrator grant' USING ERRCODE = '42501';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('ca:' || p_ca::text, 0));

    SELECT * INTO v_prior FROM ca_lifecycle_event e WHERE e.operation_id = p_operation;
    IF FOUND THEN
        IF v_prior.action IN ('ca.reactivation', 'ca.retirement') AND v_prior.request_sha256 = p_request_sha256
           AND v_prior.ca_id = p_ca AND v_prior.actor_issuer = p_issuer AND v_prior.actor_subject = p_subject
           AND EXISTS (SELECT 1 FROM ca_change_application a JOIN ca_state_change c USING (change_id)
                       WHERE a.request_id = p_request AND c.event_id = v_prior.event_id) THEN
            RETURN QUERY SELECT c.to_state, a.retired_revisions, true
                FROM ca_state_change c JOIN ca_change_application a USING (change_id)
                WHERE c.event_id = v_prior.event_id;
            RETURN;
        END IF;
        RAISE EXCEPTION 'idempotency key already used for another request' USING ERRCODE = 'TP409';
    END IF;

    SELECT * INTO v_request FROM ca_change_request r WHERE r.request_id = p_request AND r.ca_id = p_ca;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown CA change request' USING ERRCODE = 'P0002';
    END IF;
    -- Separation of duties: no one applies a change they decided on.
    IF EXISTS (SELECT 1 FROM ca_change_decision d
               WHERE d.request_id = p_request AND d.approver_issuer = p_issuer AND d.approver_subject = p_subject) THEN
        RAISE EXCEPTION 'an approver of a change cannot apply it' USING ERRCODE = '42501';
    END IF;
    IF ca_change_request_status(p_request) <> 'APPROVED' THEN
        RAISE EXCEPTION 'only an approved, unapplied change request can be applied' USING ERRCODE = 'TP409';
    END IF;
    IF (SELECT s.state FROM ca_operational_state s WHERE s.ca_id = p_ca) IS DISTINCT FROM v_request.from_state THEN
        RAISE EXCEPTION 'the CA changed state since the request' USING ERRCODE = 'TP409';
    END IF;
    IF v_request.action = 'reactivate'
       AND (SELECT c.not_after FROM ca_issuer_certificate c WHERE c.ca_id = p_ca) <= clock_timestamp() THEN
        RAISE EXCEPTION 'the issuer certificate has expired' USING ERRCODE = 'TP422';
    END IF;
    v_to := CASE v_request.action WHEN 'reactivate' THEN 'ACTIVE' ELSE 'RETIRED' END;
    v_event_action := CASE v_request.action WHEN 'reactivate' THEN 'ca.reactivation' ELSE 'ca.retirement' END;
    SELECT c.policy_version INTO v_policy FROM ca c WHERE c.ca_id = p_ca;

    INSERT INTO ca_lifecycle_event (operation_id, request_sha256, action, ca_id, actor_issuer, actor_subject)
    VALUES (p_operation, p_request_sha256, v_event_action, p_ca, p_issuer, p_subject)
    RETURNING event_id INTO v_event;
    INSERT INTO ca_state_change (ca_id, action, from_state, to_state, event_id, reason)
    VALUES (p_ca, v_request.action, v_request.from_state, v_to, v_event, v_request.reason)
    RETURNING change_id INTO v_change;
    UPDATE ca_operational_state SET state = v_to, changed_event_id = v_event, changed_at = clock_timestamp()
    WHERE ca_id = p_ca;
    INSERT INTO audit_event (event_id, ca_id, actor_id, event_type, decision, policy_version)
    VALUES (v_event, p_ca, p_subject, v_event_action, 'allow', v_policy);

    -- Retiring a CA retires its active profile revisions, with their own
    -- lifecycle and audit events, as 0024's retirement does.
    IF v_request.action = 'retire' THEN
        FOR v_revision IN
            SELECT a.profile_id, a.revision, s.snapshot_sha256, d.policy_version
            FROM certificate_profile_active a
            JOIN certificate_profile_submission s USING (ca_id, profile_id, revision)
            JOIN certificate_profile_draft d USING (ca_id, profile_id, revision)
            WHERE a.ca_id = p_ca
            ORDER BY a.profile_id
        LOOP
            INSERT INTO profile_lifecycle_event
                (operation_id, request_sha256, action, ca_id, profile_id, revision, snapshot_sha256, policy_version,
                 actor_issuer, actor_subject)
            VALUES (gen_random_uuid(), p_request_sha256, 'revision.retirement', p_ca, v_revision.profile_id,
                    v_revision.revision, v_revision.snapshot_sha256, v_revision.policy_version, p_issuer, p_subject)
            RETURNING event_id INTO v_event;
            INSERT INTO certificate_profile_activation (event_id, ca_id, profile_id, revision, action)
            VALUES (v_event, p_ca, v_revision.profile_id, v_revision.revision, 'retire');
            DELETE FROM certificate_profile_active a WHERE a.ca_id = p_ca AND a.profile_id = v_revision.profile_id;
            INSERT INTO audit_event (event_id, ca_id, actor_id, event_type, decision, policy_version)
            VALUES (v_event, p_ca, p_subject, 'profile.revision.retirement', 'allow', v_revision.policy_version);
            v_retired := v_retired + 1;
        END LOOP;
    END IF;

    INSERT INTO ca_change_application (request_id, change_id, retired_revisions)
    VALUES (p_request, v_change, v_retired);

    RETURN QUERY SELECT v_to, v_retired, false;
END
$fn$;
REVOKE ALL ON FUNCTION apply_ca_change_lab(TEXT, TEXT, UUID, UUID, UUID, BYTEA) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION suspend_ca_lab(TEXT, TEXT, UUID, TEXT, UUID, BYTEA) TO trust_profile_writer;
GRANT EXECUTE ON FUNCTION request_ca_change_lab(TEXT, TEXT, UUID, TEXT, TEXT, UUID, BYTEA) TO trust_profile_writer;
GRANT EXECUTE ON FUNCTION prepare_ca_change_decision_lab(TEXT, TEXT, UUID, UUID, TEXT) TO trust_profile_writer;
GRANT EXECUTE ON FUNCTION record_ca_change_decision_lab(TEXT, TEXT, UUID, UUID, TEXT, TIMESTAMPTZ, BYTEA, UUID, BYTEA)
    TO trust_profile_writer;
GRANT EXECUTE ON FUNCTION apply_ca_change_lab(TEXT, TEXT, UUID, UUID, UUID, BYTEA) TO trust_profile_writer;

-- Readers of a CA see its operational state (NULL for a CA the owner
-- created directly). A column is appended; the filter is unchanged.
CREATE OR REPLACE VIEW management_ca WITH (security_barrier = true) AS
SELECT ca.ca_id::text AS ca_id, ca.parent_ca_id::text AS parent_ca_id,
       ca.display_name, ca.policy_version,
       to_char(ca.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
       s.state AS operational_state
FROM ca
LEFT JOIN ca_operational_state s ON s.ca_id = ca.ca_id
WHERE EXISTS (
    SELECT 1 FROM management_reader_grant g
    WHERE g.issuer = current_setting('trust.reader_issuer', true)
      AND g.subject = current_setting('trust.reader_subject', true)
      AND g.ca_id = ca.ca_id
);

-- Administrators and approvers: the lifecycle status now follows the
-- operational state, and the open or approved change request is shown.
CREATE OR REPLACE VIEW management_ca_proposal WITH (security_barrier = true) AS
SELECT p.ca_id::text AS ca_id, p.display_name, p.policy_version, p.suite_id,
       CASE WHEN o.ca_id IS NOT NULL THEN o.state
            WHEN a.ca_id IS NOT NULL THEN 'ACTIVE'
            WHEN x.rejections > 0 THEN 'REJECTED'
            WHEN x.approvals >= 2 THEN 'APPROVED'
            WHEN c.ca_id IS NOT NULL THEN 'KEY_ATTESTED'
            ELSE 'PROPOSED' END AS lifecycle_status,
       to_char(p.proposed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS proposed_at,
       encode(c.certificate_sha256, 'hex') AS certificate_sha256,
       encode(c.spki_sha256, 'hex') AS spki_sha256,
       to_char(c.not_before AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS not_before,
       to_char(c.not_after AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS not_after,
       c.custody,
       to_char(c.registered_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS registered_at,
       x.approvals AS approval_count,
       CASE WHEN x.rejections > 0 OR x.approvals >= 2
            THEN to_char(x.last_decided_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END AS decided_at,
       to_char(a.activated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS activated_at,
       to_char(o.changed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS state_changed_at,
       q.request_id::text AS change_request_id,
       q.action AS change_action,
       q.status AS change_status,
       q.approvals AS change_approval_count,
       q.reason AS change_reason
FROM ca_proposal p
LEFT JOIN ca_issuer_certificate c ON c.ca_id = p.ca_id
LEFT JOIN ca_activation a ON a.ca_id = p.ca_id
LEFT JOIN ca_operational_state o ON o.ca_id = p.ca_id
CROSS JOIN LATERAL (
    SELECT count(*) FILTER (WHERE d.decision = 'approve')::integer AS approvals,
           count(*) FILTER (WHERE d.decision = 'reject')::integer AS rejections,
           max(d.decided_at) AS last_decided_at
    FROM ca_decision d WHERE d.ca_id = p.ca_id
) x
LEFT JOIN LATERAL (
    SELECT r.request_id, r.action, r.reason, k.approvals,
           CASE WHEN k.approvals >= 2 THEN 'APPROVED' ELSE 'OPEN' END AS status
    FROM ca_change_request r
    CROSS JOIN LATERAL (
        SELECT count(*) FILTER (WHERE d.decision = 'approve')::integer AS approvals,
               count(*) FILTER (WHERE d.decision = 'reject')::integer AS rejections
        FROM ca_change_decision d WHERE d.request_id = r.request_id
    ) k
    WHERE r.ca_id = p.ca_id AND r.from_state = o.state AND k.rejections = 0
      AND NOT EXISTS (SELECT 1 FROM ca_change_application t WHERE t.request_id = r.request_id)
    ORDER BY r.requested_at DESC
    LIMIT 1
) q ON true
WHERE EXISTS (
    SELECT 1 FROM management_platform_grant g
    WHERE g.issuer = current_setting('trust.reader_issuer', true)
      AND g.subject = current_setting('trust.reader_subject', true)
      AND g.platform_role IN ('ca-administrator', 'ca-approver')
);

CREATE FUNCTION management_ca_operation_version() RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $fn$ SELECT 1 $fn$;
REVOKE ALL ON FUNCTION management_ca_operation_version() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION management_ca_operation_version() TO trust_api_reader, trust_profile_writer;

COMMIT;
