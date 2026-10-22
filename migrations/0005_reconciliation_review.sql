-- v0.9: maker/checker review of evidence for an ambiguous signing attempt.
-- This is a DRAFT REVIEW ONLY. No function resumes signing, stores recovered DER,
-- transitions to SIGNED or asserts HSM/eIDAS compliance.
BEGIN;

CREATE TABLE signing_reconciliation_review (
    ca_id UUID NOT NULL,
    request_id UUID NOT NULL,
    observation_id UUID NOT NULL UNIQUE
        REFERENCES signing_reconciliation_observation(observation_id),
    intent_id UUID NOT NULL REFERENCES signing_intent(intent_id),
    operation_ref TEXT NOT NULL,
    evidence_sha256 BYTEA NOT NULL CHECK (
        octet_length(evidence_sha256)=32
        AND evidence_sha256<>decode(repeat('00',32),'hex')
    ),
    proposed_certificate_sha256 BYTEA NOT NULL CHECK (
        octet_length(proposed_certificate_sha256)=32
        AND proposed_certificate_sha256<>decode(repeat('00',32),'hex')
    ),
    maker_actor TEXT NOT NULL CHECK (length(maker_actor) BETWEEN 1 AND 256),
    checker_actor TEXT,
    status TEXT NOT NULL DEFAULT 'PROPOSED'
        CHECK (status IN ('PROPOSED','REVIEWED_FOR_MANUAL_DISPOSITION')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    reviewed_at TIMESTAMPTZ,
    PRIMARY KEY(ca_id,request_id),
    FOREIGN KEY(ca_id,request_id) REFERENCES signing_intent(ca_id,request_id),
    CHECK (
        (status='PROPOSED' AND checker_actor IS NULL AND reviewed_at IS NULL)
        OR
        (status='REVIEWED_FOR_MANUAL_DISPOSITION'
         AND checker_actor IS NOT NULL AND checker_actor<>maker_actor
         AND reviewed_at IS NOT NULL)
    )
);

-- Treat input metadata as caller ASSERTIONS. This database function cannot
-- cryptographically validate the X.509 output, provider evidence or actors.
-- Such checks must occur in a future independently authenticated service.
CREATE FUNCTION propose_reconciliation_review(
    p_ca_id UUID,p_request_id UUID,p_observation_id UUID,
    p_maker_actor TEXT,p_operation_ref TEXT,p_tbs_sha256 BYTEA,
    p_cert_sha256 BYTEA
)
RETURNS TEXT
LANGUAGE plpgsql AS $fn$
DECLARE
    v_state TEXT;
    v_intent signing_intent%ROWTYPE;
    v_observation signing_reconciliation_observation%ROWTYPE;
BEGIN
    IF p_ca_id IS NULL OR p_request_id IS NULL OR p_observation_id IS NULL
        OR p_maker_actor IS NULL OR length(p_maker_actor) NOT BETWEEN 1 AND 256
        OR p_operation_ref IS NULL OR length(p_operation_ref) NOT BETWEEN 1 AND 128
        OR p_tbs_sha256 IS NULL OR octet_length(p_tbs_sha256)<>32
        OR p_cert_sha256 IS NULL OR octet_length(p_cert_sha256)<>32
        OR p_cert_sha256=decode(repeat('00',32),'hex')
    THEN
        RAISE EXCEPTION 'invalid review proposal input' USING ERRCODE='22023';
    END IF;
    SELECT cr.state INTO STRICT v_state
    FROM certificate_request cr
    WHERE cr.ca_id=p_ca_id AND cr.request_id=p_request_id FOR UPDATE;
    SELECT * INTO STRICT v_intent FROM signing_intent si
    WHERE si.ca_id=p_ca_id AND si.request_id=p_request_id;
    SELECT * INTO STRICT v_observation
    FROM signing_reconciliation_observation so
    WHERE so.observation_id=p_observation_id
      AND so.ca_id=p_ca_id AND so.request_id=p_request_id;

    IF v_state<>'RECONCILIATION_REQUIRED'
        OR v_intent.outcome<>'RECONCILIATION_REQUIRED'
        OR v_intent.operation_ref<>p_operation_ref
        OR v_intent.tbs_sha256<>p_tbs_sha256
        OR v_observation.observation_type<>'PROVIDER_RESULT_OBSERVED'
        OR EXISTS(SELECT 1 FROM certificate c
                  WHERE c.ca_id=p_ca_id AND c.request_id=p_request_id)
    THEN
        RAISE EXCEPTION 'unverified or incorrect reconciliation correlation'
          USING ERRCODE='23514';
    END IF;

    INSERT INTO signing_reconciliation_review (
        ca_id,request_id,observation_id,intent_id,operation_ref,
        evidence_sha256,proposed_certificate_sha256,maker_actor
    ) VALUES (
        p_ca_id,p_request_id,p_observation_id,v_intent.intent_id,p_operation_ref,
        v_observation.evidence_sha256,p_cert_sha256,p_maker_actor
    );

    INSERT INTO audit_event(
        event_id,ca_id,request_id,actor_id,event_type,decision,
        policy_version
    ) VALUES (
        gen_random_uuid(),p_ca_id,p_request_id,p_maker_actor,
        'signing.reconciliation.proposed','review_pending',
        v_intent.policy_revision
    );
    RETURN 'PROPOSED';
END $fn$;

CREATE FUNCTION review_reconciliation_proposal(
    p_ca_id UUID,p_request_id UUID,p_checker_actor TEXT,
    p_expected_cert_sha256 BYTEA,p_expected_evidence_sha256 BYTEA
)
RETURNS TEXT
LANGUAGE plpgsql AS $fn$
DECLARE
    v_case signing_reconciliation_review%ROWTYPE;
    v_state TEXT;
BEGIN
    IF p_checker_actor IS NULL OR length(p_checker_actor) NOT BETWEEN 1 AND 256
      OR p_expected_cert_sha256 IS NULL OR octet_length(p_expected_cert_sha256)<>32
      OR p_expected_evidence_sha256 IS NULL
      OR octet_length(p_expected_evidence_sha256)<>32
    THEN RAISE EXCEPTION 'invalid checker input' USING ERRCODE='22023'; END IF;

    -- Serialize the same issuer/request and preserve quarantined state.
    SELECT cr.state INTO STRICT v_state
    FROM certificate_request cr
    WHERE cr.ca_id=p_ca_id AND cr.request_id=p_request_id FOR UPDATE;
    SELECT * INTO STRICT v_case FROM signing_reconciliation_review sr
    WHERE sr.ca_id=p_ca_id AND sr.request_id=p_request_id FOR UPDATE;

    IF v_state<>'RECONCILIATION_REQUIRED'
      OR v_case.status<>'PROPOSED'
      OR v_case.maker_actor=p_checker_actor
      OR v_case.proposed_certificate_sha256<>p_expected_cert_sha256
      OR v_case.evidence_sha256<>p_expected_evidence_sha256
    THEN
      RAISE EXCEPTION 'checker separation or evidence mismatch'
        USING ERRCODE='23514';
    END IF;

    UPDATE signing_reconciliation_review
    SET checker_actor=p_checker_actor,
        status='REVIEWED_FOR_MANUAL_DISPOSITION',
        reviewed_at=clock_timestamp()
    WHERE ca_id=p_ca_id AND request_id=p_request_id;

    INSERT INTO audit_event(
       event_id,ca_id,request_id,actor_id,event_type,decision
    ) VALUES (
       gen_random_uuid(),p_ca_id,p_request_id,p_checker_actor,
       'signing.reconciliation.reviewed','manual_disposition_only'
    );
    RETURN 'REVIEWED_FOR_MANUAL_DISPOSITION';
END $fn$;

CREATE FUNCTION guard_reconciliation_review() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'review records cannot be deleted';
    END IF;
    IF (NEW.ca_id,NEW.request_id,NEW.observation_id,NEW.intent_id,
        NEW.operation_ref,NEW.evidence_sha256,NEW.proposed_certificate_sha256,
        NEW.maker_actor,NEW.created_at)
       IS DISTINCT FROM
       (OLD.ca_id,OLD.request_id,OLD.observation_id,OLD.intent_id,
        OLD.operation_ref,OLD.evidence_sha256,OLD.proposed_certificate_sha256,
        OLD.maker_actor,OLD.created_at)
    THEN
        RAISE EXCEPTION 'immutable review proposal modified';
    END IF;
    IF OLD.status<>'PROPOSED'
       OR NEW.status<>'REVIEWED_FOR_MANUAL_DISPOSITION'
       OR OLD.checker_actor IS NOT NULL
       OR NEW.checker_actor IS NULL
       OR NEW.checker_actor=NEW.maker_actor
       OR OLD.reviewed_at IS NOT NULL
       OR NEW.reviewed_at IS NULL
    THEN
        RAISE EXCEPTION 'invalid reconciliation review mutation';
    END IF;
    RETURN NEW;
END $fn$;

CREATE TRIGGER protect_reconciliation_review
    BEFORE UPDATE OR DELETE ON signing_reconciliation_review
    FOR EACH ROW EXECUTE FUNCTION guard_reconciliation_review();

REVOKE ALL ON FUNCTION propose_reconciliation_review(
    UUID,UUID,UUID,TEXT,TEXT,BYTEA,BYTEA
) FROM PUBLIC;
REVOKE ALL ON FUNCTION review_reconciliation_proposal(
    UUID,UUID,TEXT,BYTEA,BYTEA
) FROM PUBLIC;

-- Production must separate schema owners, runtime grant roles and authenticated
-- operator identities. A DB administrator can bypass this defense in depth.
COMMIT;
