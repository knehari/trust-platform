-- Migration 0030: revoking certificates issued for applications, and
-- publishing CRLs signed by the separate laboratory signer (MVP criterion 8,
-- first slice; ADR-0018, Proposed). Laboratory only.
--
-- Revocation is requested by the application's own requester (while still
-- granted) or by a registration officer, and approved or rejected by a
-- registration officer who did not request it. Approval writes the core
-- `revocation` row (migration 0001) with a reason code from a closed list.
--
-- A CRL is published on demand by a registration officer. The database
-- allocates a strictly increasing CRL number per CA and fixes the instant
-- whose revocations the CRL lists; the API journals the TBS digest BEFORE the
-- signer is called; the signer re-reads the entries itself, checks the TBS,
-- claims the intent once and signs; the API verifies the CRL before storing
-- it. An ambiguous outcome is never signed again: the next CRL takes a new
-- number. Only the CA's latest intent can be signed, so a signed CRL never
-- carries a lower number than an earlier one.
BEGIN;

ALTER TABLE certificate_application_event DROP CONSTRAINT certificate_application_event_action_check;
ALTER TABLE certificate_application_event ADD CONSTRAINT certificate_application_event_action_check
    CHECK (action IN ('application.submitted', 'application.approved', 'application.rejected',
                      'application.issuance_started', 'revocation.requested', 'revocation.approved',
                      'revocation.rejected'));

-- Core revocations are final: no update or delete, whoever writes them.
CREATE TRIGGER immutable_revocation
    BEFORE UPDATE OR DELETE ON revocation
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

-- RFC 5280 reason codes this laboratory accepts for end-entity certificates:
-- unspecified, keyCompromise, affiliationChanged, superseded,
-- cessationOfOperation, privilegeWithdrawn. Not caCompromise or aACompromise
-- (not end-entity reasons), certificateHold (revocation is final here) or
-- removeFromCRL (delta CRLs only).
CREATE FUNCTION certificate_revocation_reason_allowed(p_reason SMALLINT) RETURNS BOOLEAN
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $fn$
    SELECT p_reason IN (0, 1, 3, 4, 5, 9)
$fn$;
REVOKE ALL ON FUNCTION certificate_revocation_reason_allowed(SMALLINT) FROM PUBLIC;

CREATE TABLE certificate_revocation_request (
    revocation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL REFERENCES certificate_application_issuance (application_id),
    ca_id UUID NOT NULL,
    serial_der_content BYTEA NOT NULL,
    reason_code SMALLINT NOT NULL CHECK (certificate_revocation_reason_allowed(reason_code)),
    reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 500 AND reason !~ '[[:cntrl:]]'),
    requested_event_id UUID NOT NULL UNIQUE REFERENCES certificate_application_event (event_id),
    requested_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (ca_id, serial_der_content) REFERENCES certificate (ca_id, serial_der_content)
);
REVOKE ALL ON certificate_revocation_request FROM PUBLIC;
CREATE TRIGGER immutable_certificate_revocation_request
    BEFORE UPDATE OR DELETE ON certificate_revocation_request
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

CREATE TABLE certificate_revocation_decision (
    revocation_id UUID PRIMARY KEY REFERENCES certificate_revocation_request (revocation_id),
    decision TEXT NOT NULL CHECK (decision IN ('approve', 'reject')),
    reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 500 AND reason !~ '[[:cntrl:]]'),
    decided_event_id UUID NOT NULL UNIQUE REFERENCES certificate_application_event (event_id),
    decided_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON certificate_revocation_decision FROM PUBLIC;
CREATE TRIGGER immutable_certificate_revocation_decision
    BEFORE UPDATE OR DELETE ON certificate_revocation_decision
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

-- Revocation and CRLs stay possible while the CA is SUSPENDED: suspension
-- stops issuance, not the publication of what was revoked.
CREATE FUNCTION certificate_ca_publishes(p_ca UUID) RETURNS BOOLEAN
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $fn$
    SELECT EXISTS (SELECT 1 FROM ca_operational_state s
                   WHERE s.ca_id = p_ca AND s.state IN ('ACTIVE', 'SUSPENDED'))
$fn$;
REVOKE ALL ON FUNCTION certificate_ca_publishes(UUID) FROM PUBLIC;

-- Every revocation of a CA, and every CRL intent, takes this lock last.
CREATE FUNCTION crl_lock(p_ca UUID) RETURNS VOID
LANGUAGE sql SET search_path = pg_catalog AS $fn$
    SELECT pg_advisory_xact_lock(hashtextextended('crl:' || p_ca::text, 0))
$fn$;
REVOKE ALL ON FUNCTION crl_lock(UUID) FROM PUBLIC;

-- Requests revocation of an issued certificate. Errors: 42501 forbidden,
-- P0002 unknown or not issued, TP409 replayed key reuse, already revoked,
-- a request already open, or the CA retired; 22023 invalid parameters
-- (including a reason code outside the closed list).
CREATE FUNCTION request_certificate_revocation_lab(
    p_issuer TEXT, p_subject TEXT, p_ca UUID, p_application UUID, p_reason_code SMALLINT, p_reason TEXT,
    p_operation UUID, p_request_sha256 BYTEA
) RETURNS TABLE (revocation_id UUID, replayed BOOLEAN)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_prior certificate_application_event%ROWTYPE;
    v_issuance certificate_application_issuance%ROWTYPE;
    v_serial BYTEA;
    v_event UUID;
    v_revocation UUID;
BEGIN
    IF p_issuer IS NULL OR p_subject IS NULL OR p_ca IS NULL OR p_application IS NULL OR p_reason IS NULL
       OR p_reason_code IS NULL OR NOT certificate_revocation_reason_allowed(p_reason_code)
       OR length(p_reason) NOT BETWEEN 1 AND 500 OR p_reason ~ '[[:cntrl:]]'
       OR p_operation IS NULL OR p_request_sha256 IS NULL OR octet_length(p_request_sha256) <> 32
       OR length(p_subject) NOT BETWEEN 1 AND 256 OR length(p_issuer) NOT BETWEEN 1 AND 1024 THEN
        RAISE EXCEPTION 'invalid revocation request parameters' USING ERRCODE = '22023';
    END IF;
    IF NOT certificate_issuance_permitted(p_issuer, p_subject, p_ca, p_application) THEN
        RAISE EXCEPTION 'no registration-officer grant, and not the requester' USING ERRCODE = '42501';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('application:' || p_application::text, 0));

    SELECT * INTO v_prior FROM certificate_application_event e WHERE e.operation_id = p_operation;
    IF FOUND THEN
        IF v_prior.action = 'revocation.requested' AND v_prior.request_sha256 = p_request_sha256
           AND v_prior.ca_id = p_ca AND v_prior.application_id = p_application
           AND v_prior.actor_issuer = p_issuer AND v_prior.actor_subject = p_subject THEN
            RETURN QUERY SELECT q.revocation_id, true FROM certificate_revocation_request q
                WHERE q.requested_event_id = v_prior.event_id;
            RETURN;
        END IF;
        RAISE EXCEPTION 'idempotency key already used for another request' USING ERRCODE = 'TP409';
    END IF;

    SELECT * INTO v_issuance FROM certificate_application_issuance i
    WHERE i.application_id = p_application AND i.ca_id = p_ca;
    SELECT c.serial_der_content INTO v_serial FROM certificate c
    WHERE c.ca_id = p_ca AND c.request_id = v_issuance.request_id;
    IF v_serial IS NULL THEN
        RAISE EXCEPTION 'no certificate was issued for this application' USING ERRCODE = 'P0002';
    END IF;
    IF NOT certificate_ca_publishes(p_ca) THEN
        RAISE EXCEPTION 'the CA is retired' USING ERRCODE = 'TP409';
    END IF;
    IF EXISTS (SELECT 1 FROM revocation r WHERE r.ca_id = p_ca AND r.serial_der_content = v_serial) THEN
        RAISE EXCEPTION 'the certificate is already revoked' USING ERRCODE = 'TP409';
    END IF;
    IF EXISTS (SELECT 1 FROM certificate_revocation_request q
               WHERE q.application_id = p_application
                 AND NOT EXISTS (SELECT 1 FROM certificate_revocation_decision d
                                 WHERE d.revocation_id = q.revocation_id)) THEN
        RAISE EXCEPTION 'a revocation request is already open' USING ERRCODE = 'TP409';
    END IF;

    INSERT INTO certificate_application_event (operation_id, request_sha256, action, ca_id, application_id,
                                               actor_issuer, actor_subject)
    VALUES (p_operation, p_request_sha256, 'revocation.requested', p_ca, p_application, p_issuer, p_subject)
    RETURNING event_id INTO v_event;
    INSERT INTO certificate_revocation_request (application_id, ca_id, serial_der_content, reason_code, reason,
                                                requested_event_id)
    VALUES (p_application, p_ca, v_serial, p_reason_code, p_reason, v_event)
    RETURNING certificate_revocation_request.revocation_id INTO v_revocation;
    INSERT INTO audit_event (event_id, ca_id, request_id, actor_id, event_type, decision)
    VALUES (v_event, p_ca, v_issuance.request_id, p_subject, 'certificate.revocation.requested', 'allow');
    RETURN QUERY SELECT v_revocation, false;
END
$fn$;
REVOKE ALL ON FUNCTION request_certificate_revocation_lab(TEXT, TEXT, UUID, UUID, SMALLINT, TEXT, UUID, BYTEA)
    FROM PUBLIC;

-- Approves or rejects an open revocation request, once, by a registration
-- officer who did not request it. Approval writes the core revocation row
-- under the CA's CRL lock, so a CRL intent never misses it. Errors: 42501,
-- P0002 unknown request, TP409 already decided, key reuse or CA retired.
CREATE FUNCTION decide_certificate_revocation_lab(
    p_issuer TEXT, p_subject TEXT, p_ca UUID, p_application UUID, p_revocation UUID, p_decision TEXT,
    p_reason TEXT, p_operation UUID, p_request_sha256 BYTEA
) RETURNS TABLE (status TEXT, revoked_at TEXT, replayed BOOLEAN)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_prior certificate_application_event%ROWTYPE;
    v_request certificate_revocation_request%ROWTYPE;
    v_issuance certificate_application_issuance%ROWTYPE;
    v_event UUID;
    v_action TEXT := CASE p_decision WHEN 'approve' THEN 'revocation.approved' ELSE 'revocation.rejected' END;
BEGIN
    IF p_issuer IS NULL OR p_subject IS NULL OR p_ca IS NULL OR p_application IS NULL OR p_revocation IS NULL
       OR p_decision IS NULL OR p_decision NOT IN ('approve', 'reject') OR p_reason IS NULL
       OR length(p_reason) NOT BETWEEN 1 AND 500 OR p_reason ~ '[[:cntrl:]]'
       OR p_operation IS NULL OR p_request_sha256 IS NULL OR octet_length(p_request_sha256) <> 32
       OR length(p_subject) NOT BETWEEN 1 AND 256 OR length(p_issuer) NOT BETWEEN 1 AND 1024 THEN
        RAISE EXCEPTION 'invalid revocation decision parameters' USING ERRCODE = '22023';
    END IF;
    IF NOT certificate_role_granted(p_issuer, p_subject, p_ca, 'registration-officer') THEN
        RAISE EXCEPTION 'no registration-officer grant for this CA' USING ERRCODE = '42501';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('application:' || p_application::text, 0));

    SELECT * INTO v_prior FROM certificate_application_event e WHERE e.operation_id = p_operation;
    IF FOUND THEN
        IF v_prior.action = v_action AND v_prior.request_sha256 = p_request_sha256 AND v_prior.ca_id = p_ca
           AND v_prior.application_id = p_application
           AND v_prior.actor_issuer = p_issuer AND v_prior.actor_subject = p_subject THEN
            RETURN QUERY
            SELECT CASE d.decision WHEN 'approve' THEN 'REVOKED' ELSE 'REJECTED' END,
                   to_char(r.revoked_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), true
            FROM certificate_revocation_decision d
            JOIN certificate_revocation_request q ON q.revocation_id = d.revocation_id
            LEFT JOIN revocation r ON r.ca_id = q.ca_id AND r.serial_der_content = q.serial_der_content
                                  AND d.decision = 'approve'
            WHERE d.decided_event_id = v_prior.event_id;
            RETURN;
        END IF;
        RAISE EXCEPTION 'idempotency key already used for another request' USING ERRCODE = 'TP409';
    END IF;

    SELECT * INTO v_request FROM certificate_revocation_request q
    WHERE q.revocation_id = p_revocation AND q.application_id = p_application AND q.ca_id = p_ca;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown revocation request' USING ERRCODE = 'P0002';
    END IF;
    -- Separation of duties: whoever requested cannot decide.
    IF EXISTS (SELECT 1 FROM certificate_application_event e
               WHERE e.event_id = v_request.requested_event_id
                 AND e.actor_issuer = p_issuer AND e.actor_subject = p_subject) THEN
        RAISE EXCEPTION 'the revocation requester cannot decide on it' USING ERRCODE = '42501';
    END IF;
    IF EXISTS (SELECT 1 FROM certificate_revocation_decision d WHERE d.revocation_id = p_revocation) THEN
        RAISE EXCEPTION 'the revocation request was already decided' USING ERRCODE = 'TP409';
    END IF;
    IF p_decision = 'approve' AND NOT certificate_ca_publishes(p_ca) THEN
        RAISE EXCEPTION 'the CA is retired' USING ERRCODE = 'TP409';
    END IF;

    INSERT INTO certificate_application_event (operation_id, request_sha256, action, ca_id, application_id,
                                               actor_issuer, actor_subject)
    VALUES (p_operation, p_request_sha256, v_action, p_ca, p_application, p_issuer, p_subject)
    RETURNING event_id INTO v_event;
    INSERT INTO certificate_revocation_decision (revocation_id, decision, reason, decided_event_id)
    VALUES (p_revocation, p_decision, p_reason, v_event);
    SELECT * INTO v_issuance FROM certificate_application_issuance i WHERE i.application_id = p_application;
    IF p_decision = 'approve' THEN
        PERFORM crl_lock(p_ca);
        -- The instant is taken under the CRL lock: a CRL intent fixed earlier
        -- never includes it, and one fixed later always does.
        INSERT INTO revocation (ca_id, serial_der_content, reason_code, revoked_at, actor_id)
        VALUES (p_ca, v_request.serial_der_content, v_request.reason_code, clock_timestamp(), p_subject);
    END IF;
    INSERT INTO audit_event (event_id, ca_id, request_id, actor_id, event_type, decision)
    VALUES (v_event, p_ca, v_issuance.request_id, p_subject,
            CASE p_decision WHEN 'approve' THEN 'certificate.revoked' ELSE 'certificate.revocation.rejected' END,
            CASE p_decision WHEN 'approve' THEN 'allow' ELSE 'deny' END);

    RETURN QUERY
    SELECT CASE p_decision WHEN 'approve' THEN 'REVOKED' ELSE 'REJECTED' END,
           (SELECT to_char(r.revoked_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') FROM revocation r
            WHERE p_decision = 'approve' AND r.ca_id = p_ca AND r.serial_der_content = v_request.serial_der_content),
           false;
END
$fn$;
REVOKE ALL ON FUNCTION decide_certificate_revocation_lab(TEXT, TEXT, UUID, UUID, UUID, TEXT, TEXT, UUID, BYTEA)
    FROM PUBLIC;

-- CRL signing intents. PREPARED (number and instant fixed) -> UNCONFIRMED
-- (TBS digest journaled, the signer may be asked) -> PUBLISHED, or
-- RECONCILIATION_REQUIRED. `entries_until` is the instant whose revocations
-- the CRL lists; this_update is that instant truncated to the second.
CREATE TABLE crl_signing_intent (
    intent_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ca_id UUID NOT NULL REFERENCES ca (ca_id),
    crl_number BIGINT NOT NULL CHECK (crl_number >= 1),
    entries_until TIMESTAMPTZ NOT NULL,
    this_update TIMESTAMPTZ NOT NULL,
    next_update TIMESTAMPTZ NOT NULL,
    tbs_sha256 BYTEA CHECK (tbs_sha256 IS NULL OR octet_length(tbs_sha256) = 32),
    outcome TEXT NOT NULL DEFAULT 'PREPARED'
        CHECK (outcome IN ('PREPARED', 'UNCONFIRMED', 'RECONCILIATION_REQUIRED', 'PUBLISHED')),
    operation_id UUID NOT NULL UNIQUE,
    request_sha256 BYTEA NOT NULL CHECK (octet_length(request_sha256) = 32),
    actor_issuer TEXT NOT NULL CHECK (length(actor_issuer) BETWEEN 1 AND 1024),
    actor_subject TEXT NOT NULL CHECK (length(actor_subject) BETWEEN 1 AND 256),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (ca_id, crl_number),
    CHECK (this_update <= entries_until AND this_update < next_update),
    CHECK ((outcome = 'PREPARED') = (tbs_sha256 IS NULL))
);
REVOKE ALL ON crl_signing_intent FROM PUBLIC;

-- Only the forward transitions above, and nothing else, may change.
CREATE FUNCTION guard_crl_signing_intent() RETURNS TRIGGER
LANGUAGE plpgsql SET search_path = pg_catalog AS $fn$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'CRL signing intents may not be deleted';
    END IF;
    IF (NEW.intent_id, NEW.ca_id, NEW.crl_number, NEW.entries_until, NEW.this_update, NEW.next_update,
        NEW.operation_id, NEW.request_sha256, NEW.actor_issuer, NEW.actor_subject, NEW.created_at)
       IS DISTINCT FROM
       (OLD.intent_id, OLD.ca_id, OLD.crl_number, OLD.entries_until, OLD.this_update, OLD.next_update,
        OLD.operation_id, OLD.request_sha256, OLD.actor_issuer, OLD.actor_subject, OLD.created_at)
       OR NOT ((OLD.outcome = 'PREPARED' AND OLD.tbs_sha256 IS NULL AND NEW.outcome = 'UNCONFIRMED')
            OR (OLD.outcome = 'UNCONFIRMED' AND NEW.outcome IN ('PUBLISHED', 'RECONCILIATION_REQUIRED')
                AND NEW.tbs_sha256 = OLD.tbs_sha256)) THEN
        RAISE EXCEPTION 'invalid CRL signing intent transition';
    END IF;
    RETURN NEW;
END
$fn$;
CREATE TRIGGER guard_crl_signing_intent
    BEFORE UPDATE OR DELETE ON crl_signing_intent
    FOR EACH ROW EXECUTE FUNCTION guard_crl_signing_intent();

-- The signer's one claim per CRL intent.
CREATE TABLE lab_signer_crl_claim (
    intent_id UUID PRIMARY KEY REFERENCES crl_signing_intent (intent_id),
    claimed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON lab_signer_crl_claim FROM PUBLIC;
CREATE TRIGGER immutable_lab_signer_crl_claim
    BEFORE UPDATE OR DELETE ON lab_signer_crl_claim
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

-- The verified, published CRL. Its core record is crl_publication (0001).
CREATE TABLE crl_document (
    ca_id UUID NOT NULL,
    crl_number BIGINT NOT NULL,
    intent_id UUID NOT NULL UNIQUE REFERENCES crl_signing_intent (intent_id),
    crl_der BYTEA NOT NULL CHECK (octet_length(crl_der) BETWEEN 64 AND 1048576),
    crl_sha256 BYTEA GENERATED ALWAYS AS (digest(crl_der, 'sha256')) STORED,
    published_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (ca_id, crl_number),
    FOREIGN KEY (ca_id, crl_number) REFERENCES crl_signing_intent (ca_id, crl_number)
);
REVOKE ALL ON crl_document FROM PUBLIC;
CREATE TRIGGER immutable_crl_document
    BEFORE UPDATE OR DELETE ON crl_document
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

-- The revocations a CRL intent lists: the CA's revocations up to its instant.
CREATE FUNCTION crl_intent_entries(p_intent UUID)
RETURNS TABLE (serial BYTEA, revoked_at TIMESTAMPTZ, reason_code SMALLINT)
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $fn$
    SELECT r.serial_der_content, r.revoked_at, r.reason_code
    FROM crl_signing_intent i
    JOIN revocation r ON r.ca_id = i.ca_id AND r.revoked_at <= i.entries_until
    WHERE i.intent_id = p_intent
    ORDER BY r.serial_der_content
$fn$;
REVOKE ALL ON FUNCTION crl_intent_entries(UUID) FROM PUBLIC;

-- Starts (or, for the same key, returns) a CRL for the CA: the next number
-- and the instant whose revocations it lists. Errors: 42501 forbidden, TP409
-- key reuse or a CA that neither issues nor publishes, P0002 no issuer
-- certificate.
CREATE FUNCTION begin_crl_publication_lab(
    p_issuer TEXT, p_subject TEXT, p_ca UUID, p_operation UUID, p_request_sha256 BYTEA
) RETURNS TABLE (intent_id UUID, crl_number BIGINT, this_update TEXT, next_update TEXT, outcome TEXT,
                 issuer_certificate_der BYTEA, replayed BOOLEAN)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_prior crl_signing_intent%ROWTYPE;
    v_number BIGINT;
    v_instant TIMESTAMPTZ;
    v_intent UUID;
    v_replayed BOOLEAN := false;
BEGIN
    IF p_issuer IS NULL OR p_subject IS NULL OR p_ca IS NULL OR p_operation IS NULL
       OR p_request_sha256 IS NULL OR octet_length(p_request_sha256) <> 32
       OR length(p_subject) NOT BETWEEN 1 AND 256 OR length(p_issuer) NOT BETWEEN 1 AND 1024 THEN
        RAISE EXCEPTION 'invalid CRL parameters' USING ERRCODE = '22023';
    END IF;
    IF NOT certificate_role_granted(p_issuer, p_subject, p_ca, 'registration-officer') THEN
        RAISE EXCEPTION 'no registration-officer grant for this CA' USING ERRCODE = '42501';
    END IF;
    PERFORM crl_lock(p_ca);
    SELECT * INTO v_prior FROM crl_signing_intent i WHERE i.operation_id = p_operation;
    IF FOUND THEN
        IF v_prior.ca_id <> p_ca OR v_prior.request_sha256 <> p_request_sha256
           OR v_prior.actor_issuer <> p_issuer OR v_prior.actor_subject <> p_subject THEN
            RAISE EXCEPTION 'idempotency key already used for another request' USING ERRCODE = 'TP409';
        END IF;
        v_intent := v_prior.intent_id;
        v_replayed := true;
    ELSE
        IF NOT certificate_ca_publishes(p_ca) THEN
            RAISE EXCEPTION 'the CA neither issues nor publishes' USING ERRCODE = 'TP409';
        END IF;
        IF NOT EXISTS (SELECT 1 FROM ca_issuer_certificate c WHERE c.ca_id = p_ca) THEN
            RAISE EXCEPTION 'the CA has no registered issuer certificate' USING ERRCODE = 'P0002';
        END IF;
        SELECT COALESCE(max(i.crl_number), 0) + 1 INTO v_number FROM crl_signing_intent i WHERE i.ca_id = p_ca;
        v_instant := clock_timestamp();
        INSERT INTO crl_signing_intent (ca_id, crl_number, entries_until, this_update, next_update,
                                        operation_id, request_sha256, actor_issuer, actor_subject)
        VALUES (p_ca, v_number, v_instant, date_trunc('second', v_instant),
                date_trunc('second', v_instant) + interval '7 days',
                p_operation, p_request_sha256, p_issuer, p_subject)
        RETURNING crl_signing_intent.intent_id INTO v_intent;
        INSERT INTO audit_event (event_id, ca_id, actor_id, event_type, decision)
        VALUES (gen_random_uuid(), p_ca, p_subject, 'crl.prepared', 'allow');
    END IF;
    RETURN QUERY
    SELECT i.intent_id, i.crl_number,
           to_char(i.this_update AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
           to_char(i.next_update AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
           i.outcome, c.certificate_der, v_replayed
    FROM crl_signing_intent i JOIN ca_issuer_certificate c ON c.ca_id = i.ca_id
    WHERE i.intent_id = v_intent;
END
$fn$;
REVOKE ALL ON FUNCTION begin_crl_publication_lab(TEXT, TEXT, UUID, UUID, BYTEA) FROM PUBLIC;

-- The entries of a CRL intent, for the API to build its TBS.
CREATE FUNCTION crl_publication_entries_lab(p_issuer TEXT, p_subject TEXT, p_ca UUID, p_intent UUID)
RETURNS TABLE (serial BYTEA, revoked_at TEXT, reason_code SMALLINT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
BEGIN
    IF NOT certificate_role_granted(p_issuer, p_subject, p_ca, 'registration-officer') THEN
        RAISE EXCEPTION 'no registration-officer grant for this CA' USING ERRCODE = '42501';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM crl_signing_intent i WHERE i.intent_id = p_intent AND i.ca_id = p_ca) THEN
        RAISE EXCEPTION 'unknown CRL intent' USING ERRCODE = 'P0002';
    END IF;
    RETURN QUERY
    SELECT e.serial, to_char(e.revoked_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), e.reason_code
    FROM crl_intent_entries(p_intent) e;
END
$fn$;
REVOKE ALL ON FUNCTION crl_publication_entries_lab(TEXT, TEXT, UUID, UUID) FROM PUBLIC;

-- Journals the TBS digest BEFORE the signer is called. Returns replayed =
-- true when a digest was journaled before: the API must then not sign.
-- Errors: TP409 when the intent is no longer the CA's latest or the CA no
-- longer publishes.
CREATE FUNCTION record_crl_signing_intent_lab(
    p_issuer TEXT, p_subject TEXT, p_ca UUID, p_intent UUID, p_tbs_sha256 BYTEA
) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_intent crl_signing_intent%ROWTYPE;
BEGIN
    IF p_tbs_sha256 IS NULL OR octet_length(p_tbs_sha256) <> 32 THEN
        RAISE EXCEPTION 'invalid TBS digest' USING ERRCODE = '22023';
    END IF;
    IF NOT certificate_role_granted(p_issuer, p_subject, p_ca, 'registration-officer') THEN
        RAISE EXCEPTION 'no registration-officer grant for this CA' USING ERRCODE = '42501';
    END IF;
    PERFORM crl_lock(p_ca);
    SELECT * INTO v_intent FROM crl_signing_intent i WHERE i.intent_id = p_intent AND i.ca_id = p_ca;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown CRL intent' USING ERRCODE = 'P0002';
    END IF;
    IF v_intent.outcome <> 'PREPARED' THEN
        RETURN true;
    END IF;
    IF NOT certificate_ca_publishes(p_ca)
       OR EXISTS (SELECT 1 FROM crl_signing_intent i WHERE i.ca_id = p_ca AND i.crl_number > v_intent.crl_number) THEN
        RAISE EXCEPTION 'this CRL intent can no longer be signed' USING ERRCODE = 'TP409';
    END IF;
    UPDATE crl_signing_intent SET tbs_sha256 = p_tbs_sha256, outcome = 'UNCONFIRMED' WHERE intent_id = p_intent;
    RETURN false;
END
$fn$;
REVOKE ALL ON FUNCTION record_crl_signing_intent_lab(TEXT, TEXT, UUID, UUID, BYTEA) FROM PUBLIC;

-- Stores the CRL the API verified. The signer must have claimed the intent.
CREATE FUNCTION store_crl_lab(p_issuer TEXT, p_subject TEXT, p_ca UUID, p_intent UUID, p_crl_der BYTEA)
RETURNS TEXT
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_intent crl_signing_intent%ROWTYPE;
BEGIN
    IF NOT certificate_role_granted(p_issuer, p_subject, p_ca, 'registration-officer') THEN
        RAISE EXCEPTION 'no registration-officer grant for this CA' USING ERRCODE = '42501';
    END IF;
    PERFORM crl_lock(p_ca);
    SELECT * INTO v_intent FROM crl_signing_intent i WHERE i.intent_id = p_intent AND i.ca_id = p_ca;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown CRL intent' USING ERRCODE = 'P0002';
    END IF;
    IF v_intent.outcome <> 'UNCONFIRMED'
       OR NOT EXISTS (SELECT 1 FROM lab_signer_crl_claim k WHERE k.intent_id = p_intent) THEN
        RAISE EXCEPTION 'this CRL intent cannot be stored' USING ERRCODE = 'TP409';
    END IF;
    INSERT INTO crl_publication (ca_id, crl_number, this_update, next_update, crl_sha256, published_at)
    VALUES (p_ca, v_intent.crl_number, v_intent.this_update, v_intent.next_update, digest(p_crl_der, 'sha256'),
            clock_timestamp());
    INSERT INTO crl_document (ca_id, crl_number, intent_id, crl_der)
    VALUES (p_ca, v_intent.crl_number, p_intent, p_crl_der);
    UPDATE crl_signing_intent SET outcome = 'PUBLISHED' WHERE intent_id = p_intent;
    INSERT INTO audit_event (event_id, ca_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), p_ca, p_subject, 'crl.published', 'allow');
    RETURN 'PUBLISHED';
END
$fn$;
REVOKE ALL ON FUNCTION store_crl_lab(TEXT, TEXT, UUID, UUID, BYTEA) FROM PUBLIC;

-- After a signer failure or timeout, or a CRL that does not verify.
CREATE FUNCTION mark_crl_signing_uncertain_lab(p_issuer TEXT, p_subject TEXT, p_ca UUID, p_intent UUID)
RETURNS TEXT
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
BEGIN
    IF NOT certificate_role_granted(p_issuer, p_subject, p_ca, 'registration-officer') THEN
        RAISE EXCEPTION 'no registration-officer grant for this CA' USING ERRCODE = '42501';
    END IF;
    PERFORM crl_lock(p_ca);
    UPDATE crl_signing_intent SET outcome = 'RECONCILIATION_REQUIRED'
    WHERE intent_id = p_intent AND ca_id = p_ca AND outcome = 'UNCONFIRMED';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no unconfirmed CRL intent' USING ERRCODE = 'TP409';
    END IF;
    INSERT INTO audit_event (event_id, ca_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), p_ca, p_subject, 'crl.reconciliation_required', 'deny');
    RETURN 'RECONCILIATION_REQUIRED';
END
$fn$;
REVOKE ALL ON FUNCTION mark_crl_signing_uncertain_lab(TEXT, TEXT, UUID, UUID) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION request_certificate_revocation_lab(TEXT, TEXT, UUID, UUID, SMALLINT, TEXT, UUID, BYTEA)
    TO trust_profile_writer;
GRANT EXECUTE ON FUNCTION decide_certificate_revocation_lab(TEXT, TEXT, UUID, UUID, UUID, TEXT, TEXT, UUID, BYTEA)
    TO trust_profile_writer;
GRANT EXECUTE ON FUNCTION begin_crl_publication_lab(TEXT, TEXT, UUID, UUID, BYTEA) TO trust_profile_writer;
GRANT EXECUTE ON FUNCTION crl_publication_entries_lab(TEXT, TEXT, UUID, UUID) TO trust_profile_writer;
GRANT EXECUTE ON FUNCTION record_crl_signing_intent_lab(TEXT, TEXT, UUID, UUID, BYTEA) TO trust_profile_writer;
GRANT EXECUTE ON FUNCTION store_crl_lab(TEXT, TEXT, UUID, UUID, BYTEA) TO trust_profile_writer;
GRANT EXECUTE ON FUNCTION mark_crl_signing_uncertain_lab(TEXT, TEXT, UUID, UUID) TO trust_profile_writer;

-- What the signer may know about a CRL intent: its number, instants, digest,
-- the CA's registered certificate, and whether it may still be signed (the
-- CA's latest intent, journaled, of a CA that publishes). Inlined: a view's
-- functions run with the reader's privileges.
CREATE VIEW lab_signer_crl_intent WITH (security_barrier = true) AS
SELECT i.intent_id::text AS intent_id, i.ca_id::text AS ca_id, i.crl_number, i.tbs_sha256,
       to_char(i.this_update AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS this_update,
       to_char(i.next_update AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS next_update,
       c.certificate_der AS issuer_certificate_der, c.spki_sha256 AS issuer_spki_sha256,
       i.outcome = 'UNCONFIRMED'
           AND NOT EXISTS (SELECT 1 FROM crl_signing_intent l WHERE l.ca_id = i.ca_id AND l.crl_number > i.crl_number)
           AND EXISTS (SELECT 1 FROM ca_operational_state o
                       WHERE o.ca_id = i.ca_id AND o.state IN ('ACTIVE', 'SUSPENDED'))
           AS signable,
       EXISTS (SELECT 1 FROM lab_signer_crl_claim k WHERE k.intent_id = i.intent_id) AS claimed
FROM crl_signing_intent i
JOIN ca_issuer_certificate c ON c.ca_id = i.ca_id;
GRANT SELECT ON lab_signer_crl_intent TO trust_lab_signer;

-- The entries of each CRL intent, read by the signer on its own.
CREATE VIEW lab_signer_crl_entry WITH (security_barrier = true) AS
SELECT i.intent_id::text AS intent_id, r.serial_der_content AS serial,
       to_char(r.revoked_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS revoked_at, r.reason_code
FROM crl_signing_intent i
JOIN revocation r ON r.ca_id = i.ca_id AND r.revoked_at <= i.entries_until;
GRANT SELECT ON lab_signer_crl_entry TO trust_lab_signer;

-- The signer's single write for CRLs: claim the intent before signing, once.
CREATE FUNCTION claim_lab_crl_intent(p_intent UUID, p_tbs_sha256 BYTEA) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_intent crl_signing_intent%ROWTYPE;
BEGIN
    SELECT * INTO v_intent FROM crl_signing_intent i WHERE i.intent_id = p_intent;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown CRL intent' USING ERRCODE = 'P0002';
    END IF;
    PERFORM crl_lock(v_intent.ca_id);
    SELECT * INTO v_intent FROM crl_signing_intent i WHERE i.intent_id = p_intent;
    IF v_intent.outcome <> 'UNCONFIRMED' OR v_intent.tbs_sha256 IS DISTINCT FROM p_tbs_sha256
       OR NOT certificate_ca_publishes(v_intent.ca_id)
       OR EXISTS (SELECT 1 FROM crl_signing_intent l
                  WHERE l.ca_id = v_intent.ca_id AND l.crl_number > v_intent.crl_number) THEN
        RAISE EXCEPTION 'this CRL intent cannot be signed' USING ERRCODE = 'TP409';
    END IF;
    INSERT INTO lab_signer_crl_claim (intent_id) VALUES (p_intent);
    RETURN true;
EXCEPTION WHEN unique_violation THEN
    RAISE EXCEPTION 'this CRL intent was already claimed by the signer' USING ERRCODE = 'TP409';
END
$fn$;
REVOKE ALL ON FUNCTION claim_lab_crl_intent(UUID, BYTEA) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION claim_lab_crl_intent(UUID, BYTEA) TO trust_lab_signer;

-- Readers of the CA see revocation state on applications...
CREATE OR REPLACE VIEW management_certificate_application WITH (security_barrier = true) AS
SELECT a.application_id::text AS application_id, a.ca_id::text AS ca_id, a.profile_id, a.revision,
       encode(a.csr_sha256, 'hex') AS csr_sha256, a.subject_cn, a.dns_names, a.validity_days,
       CASE WHEN rv.serial_der_content IS NOT NULL THEN 'REVOKED'
            WHEN oq.revocation_id IS NOT NULL THEN 'REVOCATION_REQUESTED'
            WHEN i.application_id IS NOT NULL THEN
                CASE r.state WHEN 'SIGNED' THEN 'ISSUED'
                             WHEN 'RECONCILIATION_REQUIRED' THEN 'RECONCILIATION_REQUIRED'
                             ELSE 'ISSUING' END
            WHEN d.decision = 'approve' THEN 'APPROVED' WHEN d.decision = 'reject' THEN 'REJECTED'
            ELSE 'SUBMITTED' END AS status,
       d.reason AS decision_reason,
       to_char(a.submitted_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS submitted_at,
       to_char(d.decided_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS decided_at,
       encode(cert.serial_der_content, 'hex') AS certificate_serial_hex,
       encode(cert.fingerprint_sha256, 'hex') AS certificate_sha256,
       cert.request_id::text AS certificate_request_id,
       oq.revocation_id::text AS open_revocation_id,
       oq.reason_code AS open_revocation_reason_code,
       rv.reason_code AS revocation_reason_code,
       to_char(rv.revoked_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS revoked_at
FROM certificate_application a
LEFT JOIN certificate_application_decision d ON d.application_id = a.application_id
LEFT JOIN certificate_application_issuance i ON i.application_id = a.application_id
LEFT JOIN certificate_request r ON r.ca_id = i.ca_id AND r.request_id = i.request_id
LEFT JOIN certificate cert ON cert.ca_id = i.ca_id AND cert.request_id = i.request_id
LEFT JOIN revocation rv ON rv.ca_id = cert.ca_id AND rv.serial_der_content = cert.serial_der_content
LEFT JOIN certificate_revocation_request oq ON oq.application_id = a.application_id
    AND NOT EXISTS (SELECT 1 FROM certificate_revocation_decision od WHERE od.revocation_id = oq.revocation_id)
WHERE EXISTS (
    SELECT 1 FROM management_reader_grant g
    WHERE g.issuer = current_setting('trust.reader_issuer', true)
      AND g.subject = current_setting('trust.reader_subject', true)
      AND g.ca_id = a.ca_id
);

-- ...and the CA's published CRLs.
CREATE VIEW management_certificate_crl WITH (security_barrier = true) AS
SELECT d.ca_id::text AS ca_id, d.crl_number,
       to_char(i.this_update AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS this_update,
       to_char(i.next_update AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS next_update,
       encode(d.crl_sha256, 'hex') AS crl_sha256,
       to_char(d.published_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS published_at,
       -- Inlined: a view's functions run with the reader's privileges.
       (SELECT count(*) FROM revocation r WHERE r.ca_id = i.ca_id AND r.revoked_at <= i.entries_until) AS entry_count,
       d.crl_der
FROM crl_document d
JOIN crl_signing_intent i ON i.intent_id = d.intent_id
WHERE EXISTS (
    SELECT 1 FROM management_reader_grant g
    WHERE g.issuer = current_setting('trust.reader_issuer', true)
      AND g.subject = current_setting('trust.reader_subject', true)
      AND g.ca_id = d.ca_id
);
GRANT SELECT ON management_certificate_crl TO trust_api_reader;

CREATE FUNCTION management_revocation_crl_version() RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $fn$ SELECT 1 $fn$;
REVOKE ALL ON FUNCTION management_revocation_crl_version() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION management_revocation_crl_version()
    TO trust_api_reader, trust_profile_writer, trust_lab_signer;

COMMIT;
