-- Migration 0034: reconcile an ambiguous application issuance by voiding its
-- serial under dual control (ADR-0020, Proposed). Laboratory only.
--
-- An issuance marked RECONCILIATION_REQUIRED (migration 0030) stays blocked:
-- the core never re-signs it and its request state has no way out. Two
-- registration officers, neither the application's requester, now close it:
--   propose  -> records the reserved serial, whether the signer had claimed
--               the intent, the reason and the proposer;
--   confirm  -> a different officer, under the CA's CRL lock, at
--               clock_timestamp(): the application becomes VOIDED (final).
-- A voided serial is listed, without reason code, on every CRL whose intent
-- is fixed after the confirmation, whether or not a certificate was signed.
-- The serial stays reserved and is never reused; the core request keeps its
-- RECONCILIATION_REQUIRED state. A new certificate needs a new application.
BEGIN;

ALTER TABLE certificate_application_event DROP CONSTRAINT certificate_application_event_action_check;
ALTER TABLE certificate_application_event ADD CONSTRAINT certificate_application_event_action_check
    CHECK (action IN ('application.submitted', 'application.approved', 'application.rejected',
                      'application.issuance_started', 'revocation.requested', 'revocation.approved',
                      'revocation.rejected', 'issuance.void_proposed', 'issuance.voided'));

CREATE TABLE certificate_application_void (
    application_id UUID PRIMARY KEY REFERENCES certificate_application_issuance (application_id),
    ca_id UUID NOT NULL,
    request_id UUID NOT NULL UNIQUE,
    serial_der_content BYTEA NOT NULL,
    signer_claimed BOOLEAN NOT NULL,
    proposal_reason TEXT NOT NULL CHECK (length(proposal_reason) BETWEEN 1 AND 500),
    proposed_by_issuer TEXT NOT NULL,
    proposed_by_subject TEXT NOT NULL,
    proposed_event_id UUID NOT NULL UNIQUE REFERENCES certificate_application_event (event_id),
    proposed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    confirmation_reason TEXT CHECK (length(confirmation_reason) BETWEEN 1 AND 500),
    confirmed_by_issuer TEXT,
    confirmed_by_subject TEXT,
    confirmed_event_id UUID UNIQUE REFERENCES certificate_application_event (event_id),
    voided_at TIMESTAMPTZ,
    UNIQUE (ca_id, serial_der_content),
    FOREIGN KEY (ca_id, request_id) REFERENCES certificate_request (ca_id, request_id),
    FOREIGN KEY (ca_id, serial_der_content) REFERENCES serial_reservation (ca_id, serial_der_content),
    CHECK ((voided_at IS NULL AND confirmation_reason IS NULL AND confirmed_by_issuer IS NULL
            AND confirmed_by_subject IS NULL AND confirmed_event_id IS NULL)
        OR (voided_at IS NOT NULL AND confirmation_reason IS NOT NULL AND confirmed_by_issuer IS NOT NULL
            AND confirmed_by_subject IS NOT NULL AND confirmed_event_id IS NOT NULL
            AND (confirmed_by_issuer, confirmed_by_subject) <> (proposed_by_issuer, proposed_by_subject)))
);
REVOKE ALL ON certificate_application_void FROM PUBLIC;
CREATE INDEX certificate_application_void_ca_voided ON certificate_application_void (ca_id, voided_at)
    WHERE voided_at IS NOT NULL;

-- A proposal is confirmed once; nothing else ever changes, nothing is deleted.
CREATE FUNCTION guard_certificate_application_void() RETURNS TRIGGER
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $fn$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'voids are append-only' USING ERRCODE = 'P0001';
    END IF;
    IF OLD.voided_at IS NOT NULL
       OR (NEW.application_id, NEW.ca_id, NEW.request_id, NEW.serial_der_content, NEW.signer_claimed,
           NEW.proposal_reason, NEW.proposed_by_issuer, NEW.proposed_by_subject, NEW.proposed_event_id,
           NEW.proposed_at)
          IS DISTINCT FROM
          (OLD.application_id, OLD.ca_id, OLD.request_id, OLD.serial_der_content, OLD.signer_claimed,
           OLD.proposal_reason, OLD.proposed_by_issuer, OLD.proposed_by_subject, OLD.proposed_event_id,
           OLD.proposed_at) THEN
        RAISE EXCEPTION 'a void proposal is only ever confirmed, once' USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END
$fn$;
CREATE TRIGGER guard_certificate_application_void
    BEFORE UPDATE OR DELETE ON certificate_application_void
    FOR EACH ROW EXECUTE FUNCTION guard_certificate_application_void();

-- VOIDED once confirmed; otherwise as before.
CREATE OR REPLACE FUNCTION certificate_application_issuance_status(p_application UUID) RETURNS TEXT
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $fn$
    SELECT CASE
        WHEN i.application_id IS NULL THEN certificate_application_status(p_application)
        WHEN v.voided_at IS NOT NULL THEN 'VOIDED'
        WHEN r.state = 'SIGNED' THEN 'ISSUED'
        WHEN r.state = 'RECONCILIATION_REQUIRED' THEN 'RECONCILIATION_REQUIRED'
        ELSE 'ISSUING'
    END
    FROM (SELECT p_application AS application_id) a
    LEFT JOIN certificate_application_issuance i USING (application_id)
    LEFT JOIN certificate_request r ON r.ca_id = i.ca_id AND r.request_id = i.request_id
    LEFT JOIN certificate_application_void v ON v.application_id = i.application_id
$fn$;

-- Common checks of both steps: an officer of the CA who is not the
-- application's requester, an issuance of this CA that is still ambiguous.
CREATE FUNCTION application_void_actor_check(p_issuer TEXT, p_subject TEXT, p_ca UUID, p_application UUID,
                                              p_reason TEXT, p_operation UUID, p_request_sha256 BYTEA)
RETURNS certificate_application_issuance
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_issuance certificate_application_issuance%ROWTYPE;
BEGIN
    IF p_issuer IS NULL OR p_subject IS NULL OR p_ca IS NULL OR p_application IS NULL OR p_reason IS NULL
       OR length(p_reason) NOT BETWEEN 1 AND 500 OR p_operation IS NULL
       OR p_request_sha256 IS NULL OR octet_length(p_request_sha256) <> 32
       OR length(p_subject) NOT BETWEEN 1 AND 256 OR length(p_issuer) NOT BETWEEN 1 AND 1024 THEN
        RAISE EXCEPTION 'invalid void parameters' USING ERRCODE = '22023';
    END IF;
    IF NOT certificate_role_granted(p_issuer, p_subject, p_ca, 'registration-officer') THEN
        RAISE EXCEPTION 'no registration-officer grant for this CA' USING ERRCODE = '42501';
    END IF;
    SELECT * INTO v_issuance FROM certificate_application_issuance i
    WHERE i.application_id = p_application AND i.ca_id = p_ca;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no issuance for this application' USING ERRCODE = 'P0002';
    END IF;
    IF EXISTS (SELECT 1 FROM certificate_application a
               JOIN certificate_application_event e ON e.event_id = a.submitted_event_id
               WHERE a.application_id = p_application
                 AND e.actor_issuer = p_issuer AND e.actor_subject = p_subject) THEN
        RAISE EXCEPTION 'the requester cannot void their own issuance' USING ERRCODE = '42501';
    END IF;
    RETURN v_issuance;
END
$fn$;
REVOKE ALL ON FUNCTION application_void_actor_check(TEXT, TEXT, UUID, UUID, TEXT, UUID, BYTEA) FROM PUBLIC;

-- An idempotent replay of the same request returns true; a key reused for
-- another request raises TP409.
CREATE FUNCTION application_void_replayed(p_issuer TEXT, p_subject TEXT, p_ca UUID, p_application UUID,
                                          p_action TEXT, p_operation UUID, p_request_sha256 BYTEA)
RETURNS BOOLEAN
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_prior certificate_application_event%ROWTYPE;
BEGIN
    SELECT * INTO v_prior FROM certificate_application_event e WHERE e.operation_id = p_operation;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    IF v_prior.action = p_action AND v_prior.request_sha256 = p_request_sha256 AND v_prior.ca_id = p_ca
       AND v_prior.application_id = p_application
       AND v_prior.actor_issuer = p_issuer AND v_prior.actor_subject = p_subject THEN
        RETURN true;
    END IF;
    RAISE EXCEPTION 'idempotency key already used for another request' USING ERRCODE = 'TP409';
END
$fn$;
REVOKE ALL ON FUNCTION application_void_replayed(TEXT, TEXT, UUID, UUID, TEXT, UUID, BYTEA) FROM PUBLIC;

-- Proposes to void an ambiguous issuance. Errors: 22023 invalid input,
-- 42501 not an officer or the requester, P0002 nothing issued, TP409 not
-- RECONCILIATION_REQUIRED, already proposed, or a reused key.
CREATE FUNCTION propose_application_void_lab(
    p_issuer TEXT, p_subject TEXT, p_ca UUID, p_application UUID, p_reason TEXT,
    p_operation UUID, p_request_sha256 BYTEA
) RETURNS TABLE (status TEXT, signer_claimed BOOLEAN, replayed BOOLEAN)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_issuance certificate_application_issuance%ROWTYPE;
    v_serial BYTEA;
    v_claimed BOOLEAN;
    v_event UUID;
BEGIN
    v_issuance := application_void_actor_check(p_issuer, p_subject, p_ca, p_application, p_reason,
                                               p_operation, p_request_sha256);
    PERFORM pg_advisory_xact_lock(hashtextextended('application:' || p_application::text, 0));
    IF application_void_replayed(p_issuer, p_subject, p_ca, p_application, 'issuance.void_proposed',
                                 p_operation, p_request_sha256) THEN
        RETURN QUERY SELECT certificate_application_issuance_status(p_application), v.signer_claimed, true
            FROM certificate_application_void v WHERE v.application_id = p_application;
        RETURN;
    END IF;
    IF EXISTS (SELECT 1 FROM certificate_application_void v WHERE v.application_id = p_application) THEN
        RAISE EXCEPTION 'a void was already proposed for this issuance' USING ERRCODE = 'TP409';
    END IF;
    IF certificate_application_issuance_status(p_application) <> 'RECONCILIATION_REQUIRED' THEN
        RAISE EXCEPTION 'only an issuance that needs reconciliation can be voided' USING ERRCODE = 'TP409';
    END IF;
    SELECT s.serial_der_content INTO v_serial FROM serial_reservation s
    WHERE s.ca_id = p_ca AND s.request_id = v_issuance.request_id;
    SELECT EXISTS (SELECT 1 FROM signing_intent si JOIN lab_signer_claim k ON k.intent_id = si.intent_id
                   WHERE si.ca_id = p_ca AND si.request_id = v_issuance.request_id)
      INTO v_claimed;

    INSERT INTO certificate_application_event (operation_id, request_sha256, action, ca_id, application_id,
                                               actor_issuer, actor_subject)
    VALUES (p_operation, p_request_sha256, 'issuance.void_proposed', p_ca, p_application, p_issuer, p_subject)
    RETURNING event_id INTO v_event;
    INSERT INTO certificate_application_void (application_id, ca_id, request_id, serial_der_content,
                                              signer_claimed, proposal_reason, proposed_by_issuer,
                                              proposed_by_subject, proposed_event_id)
    VALUES (p_application, p_ca, v_issuance.request_id, v_serial, v_claimed, p_reason, p_issuer, p_subject,
            v_event);
    INSERT INTO audit_event (event_id, ca_id, request_id, actor_id, event_type, decision, policy_version)
    SELECT v_event, p_ca, v_issuance.request_id, p_subject, 'certificate.application.void_proposed',
           CASE WHEN v_claimed THEN 'signer_claimed' ELSE 'signer_unclaimed' END, r.policy_version
    FROM certificate_request r WHERE r.ca_id = p_ca AND r.request_id = v_issuance.request_id;

    RETURN QUERY SELECT 'RECONCILIATION_REQUIRED'::text, v_claimed, false;
END
$fn$;
REVOKE ALL ON FUNCTION propose_application_void_lab(TEXT, TEXT, UUID, UUID, TEXT, UUID, BYTEA) FROM PUBLIC;

-- Confirms a proposal, by an officer other than the proposer, under the CA's
-- CRL lock. Errors as for the proposal; 42501 also for the proposer; P0002
-- when nothing was proposed; TP409 when already voided.
CREATE FUNCTION confirm_application_void_lab(
    p_issuer TEXT, p_subject TEXT, p_ca UUID, p_application UUID, p_reason TEXT,
    p_operation UUID, p_request_sha256 BYTEA
) RETURNS TABLE (status TEXT, serial BYTEA, voided_at TEXT, replayed BOOLEAN)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_issuance certificate_application_issuance%ROWTYPE;
    v_void certificate_application_void%ROWTYPE;
    v_event UUID;
BEGIN
    v_issuance := application_void_actor_check(p_issuer, p_subject, p_ca, p_application, p_reason,
                                               p_operation, p_request_sha256);
    -- The application lock, then the CRL lock, in the order an approved
    -- revocation takes them (migration 0031): a CRL intent either lists this
    -- serial or was fixed before it.
    PERFORM pg_advisory_xact_lock(hashtextextended('application:' || p_application::text, 0));
    PERFORM crl_lock(p_ca);
    IF application_void_replayed(p_issuer, p_subject, p_ca, p_application, 'issuance.voided',
                                 p_operation, p_request_sha256) THEN
        RETURN QUERY SELECT 'VOIDED'::text, v.serial_der_content,
                            to_char(v.voided_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), true
            FROM certificate_application_void v WHERE v.application_id = p_application;
        RETURN;
    END IF;
    SELECT * INTO v_void FROM certificate_application_void v WHERE v.application_id = p_application FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no void was proposed for this issuance' USING ERRCODE = 'P0002';
    END IF;
    IF v_void.voided_at IS NOT NULL THEN
        RAISE EXCEPTION 'this issuance was already voided' USING ERRCODE = 'TP409';
    END IF;
    IF v_void.proposed_by_issuer = p_issuer AND v_void.proposed_by_subject = p_subject THEN
        RAISE EXCEPTION 'the proposer cannot confirm their own void' USING ERRCODE = '42501';
    END IF;

    INSERT INTO certificate_application_event (operation_id, request_sha256, action, ca_id, application_id,
                                               actor_issuer, actor_subject)
    VALUES (p_operation, p_request_sha256, 'issuance.voided', p_ca, p_application, p_issuer, p_subject)
    RETURNING event_id INTO v_event;
    UPDATE certificate_application_void v
       SET confirmation_reason = p_reason, confirmed_by_issuer = p_issuer, confirmed_by_subject = p_subject,
           confirmed_event_id = v_event, voided_at = clock_timestamp()
     WHERE v.application_id = p_application
    RETURNING * INTO v_void;
    INSERT INTO audit_event (event_id, ca_id, request_id, actor_id, event_type, decision, policy_version)
    SELECT v_event, p_ca, v_issuance.request_id, p_subject, 'certificate.application.voided', 'allow',
           r.policy_version
    FROM certificate_request r WHERE r.ca_id = p_ca AND r.request_id = v_issuance.request_id;

    RETURN QUERY SELECT 'VOIDED'::text, v_void.serial_der_content,
                        to_char(v_void.voided_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), false;
END
$fn$;
REVOKE ALL ON FUNCTION confirm_application_void_lab(TEXT, TEXT, UUID, UUID, TEXT, UUID, BYTEA) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION propose_application_void_lab(TEXT, TEXT, UUID, UUID, TEXT, UUID, BYTEA)
    TO trust_profile_writer;
GRANT EXECUTE ON FUNCTION confirm_application_void_lab(TEXT, TEXT, UUID, UUID, TEXT, UUID, BYTEA)
    TO trust_profile_writer;

-- CRL entries: the CA's revocations and voided serials up to the intent's
-- instant. The API, the signer and the audit tool all read this list.
CREATE OR REPLACE FUNCTION crl_intent_entries(p_intent UUID)
RETURNS TABLE (serial BYTEA, revoked_at TIMESTAMPTZ, reason_code SMALLINT)
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $fn$
    SELECT e.serial, e.revoked_at, e.reason_code FROM (
        SELECT r.serial_der_content AS serial, r.revoked_at, r.reason_code
        FROM crl_signing_intent i
        JOIN revocation r ON r.ca_id = i.ca_id AND r.revoked_at <= i.entries_until
        WHERE i.intent_id = p_intent
        UNION ALL
        SELECT v.serial_der_content, v.voided_at, 0::smallint
        FROM crl_signing_intent i
        JOIN certificate_application_void v ON v.ca_id = i.ca_id AND v.voided_at <= i.entries_until
        WHERE i.intent_id = p_intent
    ) e
    ORDER BY e.serial
$fn$;

CREATE OR REPLACE VIEW lab_signer_crl_entry WITH (security_barrier = true) AS
SELECT i.intent_id::text AS intent_id, r.serial_der_content AS serial,
       to_char(r.revoked_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS revoked_at, r.reason_code
FROM crl_signing_intent i
JOIN revocation r ON r.ca_id = i.ca_id AND r.revoked_at <= i.entries_until
UNION ALL
SELECT i.intent_id::text, v.serial_der_content,
       to_char(v.voided_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), 0::smallint
FROM crl_signing_intent i
JOIN certificate_application_void v ON v.ca_id = i.ca_id AND v.voided_at <= i.entries_until;

-- Readers count voided serials among a CRL's entries.
CREATE OR REPLACE VIEW management_certificate_crl WITH (security_barrier = true) AS
SELECT d.ca_id::text AS ca_id, d.crl_number,
       to_char(i.this_update AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS this_update,
       to_char(i.next_update AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS next_update,
       encode(d.crl_sha256, 'hex') AS crl_sha256,
       to_char(d.published_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS published_at,
       -- Inlined: a view's functions run with the reader's privileges.
       (SELECT count(*) FROM revocation r WHERE r.ca_id = i.ca_id AND r.revoked_at <= i.entries_until)
       + (SELECT count(*) FROM certificate_application_void v
          WHERE v.ca_id = i.ca_id AND v.voided_at <= i.entries_until) AS entry_count,
       d.crl_der
FROM crl_document d
JOIN crl_signing_intent i ON i.intent_id = d.intent_id
WHERE EXISTS (
    SELECT 1 FROM management_reader_grant g
    WHERE g.issuer = current_setting('trust.reader_issuer', true)
      AND g.subject = current_setting('trust.reader_subject', true)
      AND g.ca_id = d.ca_id
);

-- Readers see the void state of applications; the other officer is never named.
CREATE OR REPLACE VIEW management_certificate_application WITH (security_barrier = true) AS
SELECT a.application_id::text AS application_id, a.ca_id::text AS ca_id, a.profile_id, a.revision,
       encode(a.csr_sha256, 'hex') AS csr_sha256, a.subject_cn, a.dns_names, a.validity_days,
       CASE WHEN rv.serial_der_content IS NOT NULL THEN 'REVOKED'
            WHEN oq.revocation_id IS NOT NULL THEN 'REVOCATION_REQUESTED'
            WHEN vd.voided_at IS NOT NULL THEN 'VOIDED'
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
       to_char(rv.revoked_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS revoked_at,
       CASE WHEN vd.voided_at IS NOT NULL THEN 'VOIDED' WHEN vd.application_id IS NOT NULL THEN 'PROPOSED' END
           AS void_status,
       vd.signer_claimed AS void_signer_claimed,
       (vd.proposed_by_issuer = current_setting('trust.reader_issuer', true)
        AND vd.proposed_by_subject = current_setting('trust.reader_subject', true)) AS void_proposed_by_reader,
       encode(vd.serial_der_content, 'hex') AS void_serial_hex,
       to_char(vd.voided_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS voided_at
FROM certificate_application a
LEFT JOIN certificate_application_decision d ON d.application_id = a.application_id
LEFT JOIN certificate_application_issuance i ON i.application_id = a.application_id
LEFT JOIN certificate_request r ON r.ca_id = i.ca_id AND r.request_id = i.request_id
LEFT JOIN certificate cert ON cert.ca_id = i.ca_id AND cert.request_id = i.request_id
LEFT JOIN revocation rv ON rv.ca_id = cert.ca_id AND rv.serial_der_content = cert.serial_der_content
LEFT JOIN certificate_revocation_request oq ON oq.application_id = a.application_id
    AND NOT EXISTS (SELECT 1 FROM certificate_revocation_decision od WHERE od.revocation_id = oq.revocation_id)
LEFT JOIN certificate_application_void vd ON vd.application_id = a.application_id
WHERE EXISTS (
    SELECT 1 FROM management_reader_grant g
    WHERE g.issuer = current_setting('trust.reader_issuer', true)
      AND g.subject = current_setting('trust.reader_subject', true)
      AND g.ca_id = a.ca_id
);

CREATE FUNCTION management_application_void_version() RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $fn$ SELECT 1 $fn$;
REVOKE ALL ON FUNCTION management_application_void_version() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION management_application_void_version()
    TO trust_api_reader, trust_profile_writer, trust_lab_signer;

COMMIT;
