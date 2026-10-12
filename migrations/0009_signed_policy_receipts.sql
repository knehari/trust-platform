-- v1.5 laboratory signed decision RECEIPTS. This is not a PKI authority
-- signature or verified human identity. PostgreSQL DOES NOT verify ECDSA.
-- Only the typed Rust verification path is intended to submit these bytes.
BEGIN;
CREATE TABLE policy_dual_signature_receipt (
    receipt_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ca_id UUID NOT NULL,
    approval_id UUID NOT NULL,
    policy_draft_id UUID NOT NULL,
    proposer_key_id TEXT NOT NULL CHECK(length(proposer_key_id) BETWEEN 1 AND 128),
    approver_key_id TEXT NOT NULL CHECK(length(approver_key_id) BETWEEN 1 AND 128),
    canonical_claim BYTEA NOT NULL CHECK(octet_length(canonical_claim) BETWEEN 100 AND 2048),
    signed_claim_sha256 BYTEA GENERATED ALWAYS AS (digest(canonical_claim,'sha256')) STORED,
    proposer_signature_der BYTEA NOT NULL CHECK(octet_length(proposer_signature_der) BETWEEN 64 AND 80),
    approver_signature_der BYTEA NOT NULL CHECK(octet_length(approver_signature_der) BETWEEN 64 AND 80),
    evidence_sha256 BYTEA NOT NULL CHECK(octet_length(evidence_sha256)=32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK(proposer_key_id<>approver_key_id),
    FOREIGN KEY(ca_id,approval_id) REFERENCES approved_policy_edition(ca_id,approval_id),
    FOREIGN KEY(ca_id,policy_draft_id) REFERENCES cp_cps_draft_snapshot(ca_id,draft_id),
    UNIQUE(ca_id,approval_id),
    UNIQUE(ca_id,policy_draft_id,signed_claim_sha256),
    UNIQUE(ca_id,policy_draft_id,evidence_sha256)
);
CREATE TRIGGER immutable_dual_policy_receipt
    BEFORE UPDATE OR DELETE ON policy_dual_signature_receipt FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_modification();

-- Explicit second-level opt-in (for an issuer already using v1.4 gate).
-- Only signed decision receipts linked to its approved edition count.
CREATE TABLE ca_dual_signature_enforcement (
    ca_id UUID PRIMARY KEY REFERENCES ca_policy_enforcement(ca_id),
    enabled_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TRIGGER immutable_dual_policy_gate
    BEFORE UPDATE OR DELETE ON ca_dual_signature_enforcement FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_modification();

CREATE FUNCTION persist_verified_dual_policy_receipt_lab(
    p_ca UUID,p_approval UUID,p_draft UUID,
    p_proposer_key TEXT,p_approver_key TEXT,
    p_canonical BYTEA,p_proposer_sig BYTEA,p_approver_sig BYTEA,
    p_evidence_sha256 BYTEA,p_claim_cp_hash BYTEA,p_claim_cps_hash BYTEA,
    p_policy_oid TEXT,p_policy_revision TEXT
) RETURNS UUID LANGUAGE plpgsql AS $fn$
DECLARE v_approved approved_policy_edition%ROWTYPE;
        v_id UUID;
BEGIN
    IF p_proposer_key IS NULL OR p_approver_key IS NULL
       OR p_proposer_key=p_approver_key
       OR length(p_proposer_key) NOT BETWEEN 1 AND 128
       OR length(p_approver_key) NOT BETWEEN 1 AND 128
       OR p_canonical IS NULL OR octet_length(p_canonical) NOT BETWEEN 100 AND 2048
       OR p_proposer_sig IS NULL OR octet_length(p_proposer_sig) NOT BETWEEN 64 AND 80
       OR p_approver_sig IS NULL OR octet_length(p_approver_sig) NOT BETWEEN 64 AND 80
       OR p_evidence_sha256 IS NULL OR octet_length(p_evidence_sha256)<>32
       OR p_claim_cp_hash IS NULL OR octet_length(p_claim_cp_hash)<>32
       OR p_claim_cps_hash IS NULL OR octet_length(p_claim_cps_hash)<>32
       OR p_policy_oid IS NULL OR p_policy_revision IS NULL
    THEN RAISE EXCEPTION 'invalid policy attestation metadata' USING ERRCODE='22023'; END IF;
    SELECT * INTO STRICT v_approved FROM approved_policy_edition
      WHERE ca_id=p_ca AND approval_id=p_approval FOR SHARE;
    IF v_approved.draft_id<>p_draft
       OR v_approved.cp_sha256<>p_claim_cp_hash
       OR v_approved.cps_sha256<>p_claim_cps_hash
       OR v_approved.policy_oid<>p_policy_oid
       OR v_approved.policy_revision<>p_policy_revision
    THEN RAISE EXCEPTION 'signed decision metadata mismatches approved draft'
         USING ERRCODE='23514'; END IF;
    INSERT INTO policy_dual_signature_receipt(
        ca_id,approval_id,policy_draft_id,proposer_key_id,approver_key_id,
        canonical_claim,proposer_signature_der,approver_signature_der,evidence_sha256
    ) VALUES(
        p_ca,p_approval,p_draft,p_proposer_key,p_approver_key,
        p_canonical,p_proposer_sig,p_approver_sig,p_evidence_sha256
    ) RETURNING receipt_id INTO v_id;
    INSERT INTO audit_event(event_id,ca_id,actor_id,event_type,decision,policy_version)
    VALUES(gen_random_uuid(),p_ca,p_approver_key,'policy.edition.lab_dual_signature',
           'COLLECTOR_VERIFIED_BY_CALLER_NOT_DATABASE',v_approved.policy_revision);
    RETURN v_id;
END $fn$;

-- Important: enable BEFORE signing, never retrofit on active signing issuer.
CREATE FUNCTION require_dual_signature_policy_lab(p_ca UUID,p_actor TEXT)
RETURNS TEXT LANGUAGE plpgsql AS $fn$
BEGIN
    IF p_actor IS NULL OR length(p_actor) NOT BETWEEN 1 AND 256
    THEN RAISE EXCEPTION 'missing actor' USING ERRCODE='22023'; END IF;
    PERFORM 1 FROM ca WHERE ca_id=p_ca FOR UPDATE;
    IF NOT FOUND OR NOT EXISTS(
        SELECT 1 FROM ca_policy_enforcement e WHERE e.ca_id=p_ca)
    THEN RAISE EXCEPTION 'issuer policy gate not activated'
        USING ERRCODE='23514'; END IF;
    IF EXISTS(SELECT 1 FROM signing_intent si WHERE si.ca_id=p_ca)
    THEN RAISE EXCEPTION 'cannot retrofit dual signature gate after signing'
        USING ERRCODE='23514'; END IF;
    INSERT INTO ca_dual_signature_enforcement(ca_id) VALUES(p_ca);
    INSERT INTO audit_event(event_id,ca_id,actor_id,event_type,decision)
    VALUES(gen_random_uuid(),p_ca,p_actor,'policy.dual_signature_gate.activated',
           'SIGNED_RECEIPT_REQUIRED');
    RETURN 'SIGNED_RECEIPT_REQUIRED';
END $fn$;

-- The v1.4 signing_intent trigger still checks issuer/TBS/time/OID, while this
-- additional trigger prevents an issuer's unsigned approvals from being used.
CREATE FUNCTION check_dual_signature_edition_before_signing()
RETURNS TRIGGER LANGUAGE plpgsql AS $fn$
BEGIN
    IF NOT EXISTS(SELECT 1 FROM ca_dual_signature_enforcement WHERE ca_id=NEW.ca_id)
    THEN RETURN NEW; END IF;
    IF NOT EXISTS(
        SELECT 1 FROM issuance_policy_grant g
        JOIN policy_dual_signature_receipt r
          ON r.ca_id=g.ca_id AND r.approval_id=g.approval_id
        WHERE g.ca_id=NEW.ca_id AND g.request_id=NEW.request_id
          AND g.tbs_sha256=NEW.tbs_sha256
    ) THEN RAISE EXCEPTION 'signing requires dual signature policy receipt'
        USING ERRCODE='23514'; END IF;
    RETURN NEW;
END $fn$;
CREATE TRIGGER signed_policy_decision_gate BEFORE INSERT ON signing_intent
    FOR EACH ROW EXECUTE FUNCTION check_dual_signature_edition_before_signing();

REVOKE ALL ON FUNCTION persist_verified_dual_policy_receipt_lab(
    UUID,UUID,UUID,TEXT,TEXT,BYTEA,BYTEA,BYTEA,BYTEA,BYTEA,BYTEA,TEXT,TEXT
) FROM PUBLIC;
REVOKE ALL ON FUNCTION require_dual_signature_policy_lab(UUID,TEXT) FROM PUBLIC;
COMMIT;
