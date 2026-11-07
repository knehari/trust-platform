-- v1.1: immutable laboratory evidence receipts and replay detection.
-- These SQL functions DO NOT cryptographically verify a signed statement;
-- only the separately reviewed Rust layer may produce verified claims.
-- A database owner/superuser can still circumvent triggers and functions.
BEGIN;

CREATE TABLE signing_collector_evidence (
    evidence_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ca_id UUID NOT NULL,
    request_id UUID NOT NULL,
    collector_key_id TEXT NOT NULL CHECK(length(collector_key_id) BETWEEN 1 AND 128),
    audit_event_id TEXT NOT NULL CHECK(length(audit_event_id) BETWEEN 1 AND 128),
    operation_ref TEXT NOT NULL CHECK(length(operation_ref) BETWEEN 1 AND 128),
    signer_key_ref TEXT NOT NULL CHECK(length(signer_key_ref) BETWEEN 1 AND 256),
    policy_revision TEXT NOT NULL CHECK(length(policy_revision) BETWEEN 1 AND 128),
    observed_at_unix_seconds BIGINT NOT NULL CHECK(observed_at_unix_seconds > 0),
    evidence_kind TEXT NOT NULL CHECK(evidence_kind IN (
        'SIGNING_EVENT', 'RETRIEVED_CERTIFICATE', 'NO_MATCHING_EVENT'
    )),
    tbs_sha256 BYTEA NOT NULL CHECK(octet_length(tbs_sha256)=32),
    raw_provider_log_sha256 BYTEA NOT NULL CHECK(
        octet_length(raw_provider_log_sha256)=32
        AND raw_provider_log_sha256 <> decode(repeat('00',32),'hex')
    ),
    certificate_sha256 BYTEA,
    canonical_claim BYTEA NOT NULL CHECK(octet_length(canonical_claim) BETWEEN 80 AND 2048),
    claim_sha256 BYTEA GENERATED ALWAYS AS (digest(canonical_claim,'sha256')) STORED,
    collector_signature_der BYTEA NOT NULL CHECK(
        octet_length(collector_signature_der) BETWEEN 64 AND 80
    ),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (ca_id,request_id) REFERENCES signing_intent(ca_id,request_id),
    UNIQUE (collector_key_id,audit_event_id),
    UNIQUE (ca_id,request_id,claim_sha256),
    CHECK (
        (evidence_kind='RETRIEVED_CERTIFICATE'
         AND certificate_sha256 IS NOT NULL AND octet_length(certificate_sha256)=32
         AND certificate_sha256 <> decode(repeat('00',32),'hex'))
        OR
        (evidence_kind<>'RETRIEVED_CERTIFICATE' AND certificate_sha256 IS NULL)
    )
);

CREATE TRIGGER protect_signing_collector_evidence
    BEFORE UPDATE OR DELETE ON signing_collector_evidence
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

-- This function checks issuer, intent, key, policy, TBS and quarantine state
-- under the same row lock. Claim *signature authenticity* and the canonical
-- bytes' internal semantic fields are NOT checked here. A future authenticated
-- service must only pass a Rust-verified, trusted-source claim.
CREATE FUNCTION persist_signing_collector_evidence(
    p_ca_id UUID, p_request_id UUID,
    p_collector_key_id TEXT, p_audit_event_id TEXT,
    p_operation_ref TEXT, p_signer_key_ref TEXT, p_policy_revision TEXT,
    p_observed_unix_seconds BIGINT, p_evidence_kind TEXT,
    p_tbs_sha256 BYTEA, p_raw_log_sha256 BYTEA, p_certificate_sha256 BYTEA,
    p_canonical_claim BYTEA, p_collector_signature_der BYTEA
) RETURNS UUID
LANGUAGE plpgsql AS $fn$
DECLARE
    v_state TEXT;
    v_intent signing_intent%ROWTYPE;
    v_evidence_id UUID;
BEGIN
    IF p_ca_id IS NULL OR p_request_id IS NULL
        OR p_collector_key_id IS NULL OR length(p_collector_key_id) NOT BETWEEN 1 AND 128
        OR p_audit_event_id IS NULL OR length(p_audit_event_id) NOT BETWEEN 1 AND 128
        OR p_operation_ref IS NULL OR length(p_operation_ref) NOT BETWEEN 1 AND 128
        OR p_signer_key_ref IS NULL OR length(p_signer_key_ref) NOT BETWEEN 1 AND 256
        OR p_policy_revision IS NULL OR length(p_policy_revision) NOT BETWEEN 1 AND 128
        OR p_observed_unix_seconds IS NULL OR p_observed_unix_seconds <= 0
        OR p_evidence_kind IS NULL
        OR p_evidence_kind NOT IN (
            'SIGNING_EVENT','RETRIEVED_CERTIFICATE','NO_MATCHING_EVENT'
        )
        OR p_tbs_sha256 IS NULL OR octet_length(p_tbs_sha256)<>32
        OR p_raw_log_sha256 IS NULL OR octet_length(p_raw_log_sha256)<>32
        OR p_raw_log_sha256=decode(repeat('00',32),'hex')
        OR p_canonical_claim IS NULL
        OR octet_length(p_canonical_claim) NOT BETWEEN 80 AND 2048
        OR p_collector_signature_der IS NULL
        OR octet_length(p_collector_signature_der) NOT BETWEEN 64 AND 80
        OR (p_evidence_kind='RETRIEVED_CERTIFICATE' AND
            (p_certificate_sha256 IS NULL OR octet_length(p_certificate_sha256)<>32
             OR p_certificate_sha256=decode(repeat('00',32),'hex')))
        OR (p_evidence_kind<>'RETRIEVED_CERTIFICATE' AND
            p_certificate_sha256 IS NOT NULL)
    THEN
        RAISE EXCEPTION 'invalid collector evidence metadata'
            USING ERRCODE='22023';
    END IF;

    SELECT cr.state INTO STRICT v_state
      FROM certificate_request cr
      WHERE cr.ca_id=p_ca_id AND cr.request_id=p_request_id
      FOR UPDATE;
    SELECT * INTO STRICT v_intent FROM signing_intent si
      WHERE si.ca_id=p_ca_id AND si.request_id=p_request_id;

    IF v_state<>'RECONCILIATION_REQUIRED'
        OR v_intent.outcome<>'RECONCILIATION_REQUIRED'
        OR v_intent.operation_ref<>p_operation_ref
        OR v_intent.signer_key_ref<>p_signer_key_ref
        OR v_intent.policy_revision<>p_policy_revision
        OR v_intent.tbs_sha256<>p_tbs_sha256
        OR EXISTS (
            SELECT 1 FROM certificate c
              WHERE c.ca_id=p_ca_id AND c.request_id=p_request_id
        )
    THEN
        RAISE EXCEPTION 'collector claim is not correlated to quarantined intent'
            USING ERRCODE='23514';
    END IF;

    INSERT INTO signing_collector_evidence(
        ca_id,request_id,collector_key_id,audit_event_id,
        operation_ref,signer_key_ref,policy_revision,
        observed_at_unix_seconds,evidence_kind,tbs_sha256,
        raw_provider_log_sha256,certificate_sha256,
        canonical_claim,collector_signature_der
    ) VALUES (
        p_ca_id,p_request_id,p_collector_key_id,p_audit_event_id,
        p_operation_ref,p_signer_key_ref,p_policy_revision,
        p_observed_unix_seconds,p_evidence_kind,p_tbs_sha256,
        p_raw_log_sha256,p_certificate_sha256,
        p_canonical_claim,p_collector_signature_der
    ) RETURNING evidence_id INTO v_evidence_id;

    INSERT INTO audit_event(
        event_id,ca_id,request_id,actor_id,event_type,decision,policy_version
    ) VALUES (
        gen_random_uuid(),p_ca_id,p_request_id,p_collector_key_id,
        'signing.collector.evidence',p_evidence_kind,p_policy_revision
    );
    RETURN v_evidence_id;
END
$fn$;

REVOKE ALL ON FUNCTION persist_signing_collector_evidence(
    UUID,UUID,TEXT,TEXT,TEXT,TEXT,TEXT,BIGINT,TEXT,
    BYTEA,BYTEA,BYTEA,BYTEA,BYTEA
) FROM PUBLIC;

COMMIT;
