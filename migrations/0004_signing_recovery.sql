-- v0.8: durable crash quarantine and manual reconciliation evidence.
-- A SIGNING intent with no durable completed result remains ambiguous after a crash.
-- The scanner DOES NOT issue, retry, invoke an HSM, or approve a certificate.
BEGIN;

CREATE TABLE signing_reconciliation_observation (
    observation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ca_id UUID NOT NULL,
    request_id UUID NOT NULL,
    actor_id TEXT NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 256),
    observation_type TEXT NOT NULL CHECK (
        observation_type IN ('NO_PROVIDER_EVIDENCE', 'SIGNATURE_POSSIBLE', 'PROVIDER_RESULT_OBSERVED')
    ),
    evidence_sha256 BYTEA NOT NULL CHECK (
        octet_length(evidence_sha256) = 32
        AND evidence_sha256 <> decode(repeat('00',32),'hex')
    ),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (ca_id,request_id) REFERENCES signing_intent(ca_id,request_id)
);

-- Evidence is append-only at the application-role level. A DB owner/superuser
-- can bypass this defense. External independently administered WORM anchoring
-- remains a non-negotiable requirement for strong audit assurance.
CREATE TRIGGER prohibit_reconciliation_observation_changes
    BEFORE UPDATE OR DELETE ON signing_reconciliation_observation
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

-- Quarantine only aged, unfinished intents in a precisely selected issuer.
-- Locks request rows in stable order. SKIP LOCKED permits simultaneous
-- recovery workers without double processing or blocking on in-flight writes.
-- The cutoff must be <= server time; caller is responsible for a safe grace window.
CREATE FUNCTION quarantine_stale_signing_intents(
    p_ca_id UUID, p_before TIMESTAMPTZ, p_limit INTEGER, p_actor_id TEXT
)
RETURNS TABLE (
    request_id UUID, intent_id UUID, operation_ref TEXT,
    signer_key_ref TEXT, tbs_sha256 BYTEA
)
LANGUAGE plpgsql AS $fn$
DECLARE
    v_candidate RECORD;
BEGIN
    IF p_ca_id IS NULL OR p_before IS NULL OR p_before > clock_timestamp()
       OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100
       OR p_actor_id IS NULL OR length(p_actor_id) NOT BETWEEN 1 AND 256
    THEN
        RAISE EXCEPTION 'invalid recovery scan parameters' USING ERRCODE='22023';
    END IF;

    FOR v_candidate IN
        SELECT cr.request_id AS candidate_request_id,
               si.intent_id AS candidate_intent_id,
               si.operation_ref AS candidate_operation_ref,
               si.signer_key_ref AS candidate_signer_key_ref,
               si.tbs_sha256 AS candidate_tbs_sha256
        FROM certificate_request cr
        JOIN signing_intent si ON si.ca_id=cr.ca_id AND si.request_id=cr.request_id
        WHERE cr.ca_id=p_ca_id
          AND cr.state='SIGNING'
          AND si.outcome='UNCONFIRMED'
          AND si.created_at <= p_before
          AND NOT EXISTS (
              SELECT 1 FROM certificate cert
              WHERE cert.ca_id=cr.ca_id AND cert.request_id=cr.request_id
          )
        ORDER BY si.created_at, cr.request_id
        LIMIT p_limit
        FOR UPDATE OF cr SKIP LOCKED
    LOOP
        -- mark_signing_uncertain reuses the same row lock, atomically updates
        -- the intent/state and inserts the transition's audit event.
        PERFORM mark_signing_uncertain(
            p_ca_id,v_candidate.candidate_request_id,p_actor_id
        );
        request_id := v_candidate.candidate_request_id;
        intent_id := v_candidate.candidate_intent_id;
        operation_ref := v_candidate.candidate_operation_ref;
        signer_key_ref := v_candidate.candidate_signer_key_ref;
        tbs_sha256 := v_candidate.candidate_tbs_sha256;
        RETURN NEXT;
    END LOOP;
END
$fn$;

-- Attach an evidence *reference* (hash), never a claimed resolution.
-- Operators must separately obtain independent provider/certificate evidence;
-- this function does not claim the digest corresponds to a real signed result.
CREATE FUNCTION record_signing_reconciliation_observation(
    p_ca_id UUID,p_request_id UUID,p_actor_id TEXT,
    p_observation_type TEXT,p_evidence_sha256 BYTEA
)
RETURNS UUID
LANGUAGE plpgsql AS $fn$
DECLARE
    v_state TEXT;
    v_observation UUID;
BEGIN
    IF p_actor_id IS NULL OR length(p_actor_id) NOT BETWEEN 1 AND 256
       OR p_observation_type IS NULL
       OR p_observation_type NOT IN (
          'NO_PROVIDER_EVIDENCE','SIGNATURE_POSSIBLE','PROVIDER_RESULT_OBSERVED'
       )
       OR p_evidence_sha256 IS NULL
       OR octet_length(p_evidence_sha256) <> 32
       OR p_evidence_sha256=decode(repeat('00',32),'hex')
    THEN
        RAISE EXCEPTION 'invalid reconciliation observation'
            USING ERRCODE='22023';
    END IF;

    SELECT cr.state INTO STRICT v_state
    FROM certificate_request cr
    WHERE cr.ca_id=p_ca_id AND cr.request_id=p_request_id FOR UPDATE;

    IF v_state <> 'RECONCILIATION_REQUIRED' THEN
        RAISE EXCEPTION 'reconciliation observation requires quarantined request'
            USING ERRCODE='23514';
    END IF;

    INSERT INTO signing_reconciliation_observation (
        ca_id,request_id,actor_id,observation_type,evidence_sha256
    ) VALUES (
        p_ca_id,p_request_id,p_actor_id,p_observation_type,p_evidence_sha256
    ) RETURNING observation_id INTO v_observation;

    INSERT INTO audit_event (
        event_id,ca_id,request_id,actor_id,event_type,decision
    ) VALUES (
        gen_random_uuid(),p_ca_id,p_request_id,p_actor_id,
        'signing.reconciliation.observation',p_observation_type
    );
    RETURN v_observation;
END
$fn$;

REVOKE ALL ON FUNCTION quarantine_stale_signing_intents(UUID,TIMESTAMPTZ,INTEGER,TEXT)
    FROM PUBLIC;
REVOKE ALL ON FUNCTION record_signing_reconciliation_observation(
    UUID,UUID,TEXT,TEXT,BYTEA
) FROM PUBLIC;

-- Future runtime deployment requires independent authenticated recovery role,
-- issuer-scoped permissions, externally anchored audit and recovery evidence.
COMMIT;
