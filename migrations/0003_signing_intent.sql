-- Issuance signing-intent state, PostgreSQL 16.
-- A durable intent is recorded BEFORE any non-transactional HSM operation.
-- It is not safe to retry external signing merely because a DB transaction failed.
BEGIN;

CREATE TABLE signing_intent (
    ca_id UUID NOT NULL,
    request_id UUID NOT NULL,
    intent_id UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    signer_key_ref TEXT NOT NULL CHECK (length(signer_key_ref) BETWEEN 1 AND 256),
    tbs_sha256 BYTEA NOT NULL CHECK (octet_length(tbs_sha256) = 32),
    policy_revision TEXT NOT NULL CHECK (length(policy_revision) BETWEEN 1 AND 128),
    operation_ref TEXT NOT NULL CHECK (length(operation_ref) BETWEEN 1 AND 128),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    outcome TEXT NOT NULL DEFAULT 'UNCONFIRMED' CHECK (outcome IN (
        'UNCONFIRMED','RECONCILIATION_REQUIRED','CERTIFICATE_STORED'
    )),
    PRIMARY KEY (ca_id, request_id),
    FOREIGN KEY (ca_id, request_id) REFERENCES certificate_request (ca_id, request_id),
    UNIQUE (ca_id, operation_ref)
);

-- Serialize request before recording an immutable signing attempt.
-- Returning an existing operation reference is for INVESTIGATION only;
-- it NEVER means it is safe to invoke signer.sign again.
CREATE FUNCTION create_signing_intent(
    p_ca_id UUID, p_request_id UUID, p_actor_id TEXT,
    p_signer_key_ref TEXT, p_tbs_sha256 BYTEA,
    p_policy_revision TEXT, p_operation_ref TEXT
)
RETURNS TABLE(intent_id UUID, operation_ref TEXT, outcome TEXT, replay BOOLEAN)
LANGUAGE plpgsql AS $fn$
DECLARE
    v_state TEXT;
    v_policy TEXT;
    v_intent signing_intent%ROWTYPE;
BEGIN
    IF p_actor_id IS NULL OR length(p_actor_id) NOT BETWEEN 1 AND 256
       OR p_signer_key_ref IS NULL OR length(p_signer_key_ref) NOT BETWEEN 1 AND 256
       OR p_tbs_sha256 IS NULL OR octet_length(p_tbs_sha256) <> 32
       OR p_policy_revision IS NULL OR length(p_policy_revision) NOT BETWEEN 1 AND 128
       OR p_operation_ref IS NULL OR length(p_operation_ref) NOT BETWEEN 1 AND 128
    THEN
        RAISE EXCEPTION 'invalid signing-intent input' USING ERRCODE='22023';
    END IF;

    SELECT cr.state, cr.policy_version INTO STRICT v_state,v_policy
    FROM certificate_request cr
    WHERE cr.ca_id=p_ca_id AND cr.request_id=p_request_id FOR UPDATE;

    SELECT * INTO v_intent FROM signing_intent si
    WHERE si.ca_id=p_ca_id AND si.request_id=p_request_id;

    IF FOUND THEN
        IF v_intent.signer_key_ref <> p_signer_key_ref
            OR v_intent.tbs_sha256 <> p_tbs_sha256
            OR v_intent.policy_revision <> p_policy_revision
            OR v_intent.operation_ref <> p_operation_ref
        THEN
            RAISE EXCEPTION 'conflicting signing intent' USING ERRCODE='23505';
        END IF;
        RETURN QUERY SELECT v_intent.intent_id, v_intent.operation_ref, v_intent.outcome, true;
        RETURN;
    END IF;

    IF v_state <> 'SERIAL_RESERVED' OR v_policy <> p_policy_revision
       OR NOT EXISTS (
            SELECT 1 FROM serial_reservation sr
            WHERE sr.ca_id=p_ca_id AND sr.request_id=p_request_id
       )
    THEN
        RAISE EXCEPTION 'signing intent requires reserved serial and active policy version'
            USING ERRCODE='23514';
    END IF;

    INSERT INTO signing_intent (
        ca_id, request_id, signer_key_ref, tbs_sha256, policy_revision, operation_ref
    ) VALUES (
        p_ca_id, p_request_id, p_signer_key_ref, p_tbs_sha256, p_policy_revision, p_operation_ref
    ) RETURNING * INTO v_intent;

    PERFORM transition_issuance_request(p_ca_id,p_request_id,'SERIAL_RESERVED','SIGNING',p_actor_id);

    INSERT INTO audit_event (
        event_id,ca_id,request_id,actor_id,event_type,decision,policy_version
    ) VALUES (
        gen_random_uuid(),p_ca_id,p_request_id,p_actor_id,
        'signing.intent','created:' || v_intent.intent_id::text,p_policy_revision
    );

    RETURN QUERY SELECT v_intent.intent_id, v_intent.operation_ref, v_intent.outcome, false;
END
$fn$;

-- A crash, timeout or unknown HSM result must become explicitly ambiguous.
-- No transition returns the request to SIGNING. Recovery requires separate,
-- independently verified HSM/certificate reconciliation, not a re-sign call.
CREATE FUNCTION mark_signing_uncertain(
    p_ca_id UUID, p_request_id UUID, p_actor_id TEXT
)
RETURNS TEXT
LANGUAGE plpgsql AS $fn$
DECLARE
    v_state TEXT;
BEGIN
    SELECT cr.state INTO STRICT v_state
    FROM certificate_request cr WHERE cr.ca_id=p_ca_id AND cr.request_id=p_request_id
    FOR UPDATE;

    IF v_state='RECONCILIATION_REQUIRED' THEN
        RETURN v_state;
    END IF;
    IF v_state <> 'SIGNING'
       OR NOT EXISTS (
         SELECT 1 FROM signing_intent si WHERE si.ca_id=p_ca_id AND si.request_id=p_request_id
       )
    THEN
        RAISE EXCEPTION 'no active signing intent to mark uncertain' USING ERRCODE='23514';
    END IF;

    UPDATE signing_intent SET outcome='RECONCILIATION_REQUIRED'
    WHERE ca_id=p_ca_id AND request_id=p_request_id;
    PERFORM transition_issuance_request(
        p_ca_id,p_request_id,'SIGNING','RECONCILIATION_REQUIRED',p_actor_id
    );
    RETURN 'RECONCILIATION_REQUIRED';
END
$fn$;

-- IMPORTANT: Caller MUST independently validate certificate DER/signature,
-- issuer, serial, SPKI, SAN/validity, TBS hash and approved policy.
-- PostgreSQL cannot cryptographically validate arbitrary X.509 with these functions.
-- This function persists a result only; no sign or automatic re-sign is performed.
CREATE FUNCTION store_signed_certificate(
    p_ca_id UUID, p_request_id UUID, p_actor_id TEXT,
    p_serial BYTEA, p_tbs_sha256 BYTEA, p_cert_sha256 BYTEA, p_cert_der BYTEA
)
RETURNS TEXT
LANGUAGE plpgsql AS $fn$
DECLARE
    v_state TEXT;
    v_serial BYTEA;
    v_tbs BYTEA;
BEGIN
    IF p_actor_id IS NULL OR length(p_actor_id) NOT BETWEEN 1 AND 256
       OR p_tbs_sha256 IS NULL OR octet_length(p_tbs_sha256) <> 32
       OR p_cert_sha256 IS NULL OR octet_length(p_cert_sha256) <> 32
       OR p_cert_der IS NULL OR octet_length(p_cert_der) NOT BETWEEN 1 AND 65536
       OR digest(p_cert_der,'sha256') <> p_cert_sha256
    THEN RAISE EXCEPTION 'invalid signed certificate input' USING ERRCODE='22023'; END IF;

    SELECT cr.state INTO STRICT v_state FROM certificate_request cr
    WHERE cr.ca_id=p_ca_id AND cr.request_id=p_request_id FOR UPDATE;
    SELECT sr.serial_der_content INTO STRICT v_serial FROM serial_reservation sr
    WHERE sr.ca_id=p_ca_id AND sr.request_id=p_request_id;
    SELECT si.tbs_sha256 INTO STRICT v_tbs FROM signing_intent si
    WHERE si.ca_id=p_ca_id AND si.request_id=p_request_id;

    IF v_state <> 'SIGNING' OR v_serial <> p_serial OR v_tbs <> p_tbs_sha256 THEN
        RAISE EXCEPTION 'signing state, serial or TBS digest mismatch' USING ERRCODE='23514';
    END IF;

    INSERT INTO certificate (
        ca_id,serial_der_content,request_id,fingerprint_sha256,certificate_der,signed_at
    ) VALUES (
        p_ca_id,p_serial,p_request_id,p_cert_sha256,p_cert_der,now()
    );

    UPDATE signing_intent SET outcome='CERTIFICATE_STORED'
    WHERE ca_id=p_ca_id AND request_id=p_request_id;
    PERFORM transition_issuance_request(p_ca_id,p_request_id,'SIGNING','SIGNED',p_actor_id);

    INSERT INTO audit_event(event_id,ca_id,request_id,actor_id,event_type,decision)
    VALUES (gen_random_uuid(),p_ca_id,p_request_id,p_actor_id,'signing.result','persisted');

    RETURN 'SIGNED';
END
$fn$;

-- Both intent and completed operation are append-only in application semantics.
-- Editing an intent's security-critical fields is forbidden even to table owners
-- unless they alter/drop triggers; use separate privileges and anchoring later.
CREATE FUNCTION guard_signing_intent_update() RETURNS TRIGGER LANGUAGE plpgsql AS $fn$
BEGIN
    IF (NEW.ca_id,NEW.request_id,NEW.intent_id,NEW.signer_key_ref,
        NEW.tbs_sha256,NEW.policy_revision,NEW.operation_ref,NEW.created_at)
       IS DISTINCT FROM
       (OLD.ca_id,OLD.request_id,OLD.intent_id,OLD.signer_key_ref,
        OLD.tbs_sha256,OLD.policy_revision,OLD.operation_ref,OLD.created_at)
    THEN RAISE EXCEPTION 'immutable signing-intent fields changed'; END IF;
    IF OLD.outcome='CERTIFICATE_STORED' OR
       (OLD.outcome='RECONCILIATION_REQUIRED' AND NEW.outcome<>'RECONCILIATION_REQUIRED')
    THEN RAISE EXCEPTION 'invalid signing-intent outcome mutation'; END IF;
    RETURN NEW;
END $fn$;
CREATE TRIGGER signing_intent_update_guard BEFORE UPDATE ON signing_intent
FOR EACH ROW EXECUTE FUNCTION guard_signing_intent_update();

REVOKE ALL ON FUNCTION create_signing_intent(UUID,UUID,TEXT,TEXT,BYTEA,TEXT,TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION mark_signing_uncertain(UUID,UUID,TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION store_signed_certificate(UUID,UUID,TEXT,BYTEA,BYTEA,BYTEA,BYTEA) FROM PUBLIC;

COMMIT;
