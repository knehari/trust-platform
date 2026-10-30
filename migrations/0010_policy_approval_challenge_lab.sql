-- v1.6 laboratory challenge lifecycle. Not an authentication or signing verifier.
-- Only the verified application adapter should invoke consumption. Privileged SQL
-- callers can bypass application verification; do not deploy as production control.
BEGIN;
CREATE TABLE policy_approval_challenge_lab (
    challenge_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ca_id UUID NOT NULL REFERENCES ca(ca_id),
    draft_id UUID NOT NULL,
    nonce_sha256 BYTEA NOT NULL CHECK (octet_length(nonce_sha256)=32),
    proposer_subject TEXT NOT NULL CHECK (length(proposer_subject) BETWEEN 1 AND 256),
    approver_subject TEXT NOT NULL CHECK (length(approver_subject) BETWEEN 1 AND 256),
    issued_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    receipt_id UUID REFERENCES policy_dual_signature_receipt(receipt_id),
    CHECK(proposer_subject <> approver_subject),
    CHECK(expires_at > issued_at),
    CHECK ((consumed_at IS NULL AND receipt_id IS NULL)
        OR (consumed_at IS NOT NULL AND receipt_id IS NOT NULL)),
    FOREIGN KEY(ca_id,draft_id) REFERENCES cp_cps_draft_snapshot(ca_id,draft_id),
    UNIQUE(nonce_sha256),
    UNIQUE(receipt_id)
);
CREATE INDEX policy_approval_challenge_pending_lab
    ON policy_approval_challenge_lab(ca_id,draft_id,expires_at)
    WHERE consumed_at IS NULL;

-- Atomic state transition. The caller MUST first verify the complete signed
-- claim and reviewer entitlements; the DB does not verify cryptographic signatures.
CREATE FUNCTION consume_policy_approval_challenge_lab(
    p_challenge UUID, p_ca UUID, p_draft UUID, p_nonce_sha256 BYTEA,
    p_proposer TEXT, p_approver TEXT, p_receipt UUID
) RETURNS BOOLEAN LANGUAGE plpgsql AS $fn$
DECLARE v_updated INTEGER;
BEGIN
    IF p_nonce_sha256 IS NULL OR octet_length(p_nonce_sha256)<>32
       OR p_proposer IS NULL OR p_approver IS NULL OR p_proposer=p_approver
    THEN RAISE EXCEPTION 'invalid challenge consumption parameters'
         USING ERRCODE='22023'; END IF;
    UPDATE policy_approval_challenge_lab c
       SET consumed_at=clock_timestamp(), receipt_id=p_receipt
     WHERE c.challenge_id=p_challenge AND c.ca_id=p_ca AND c.draft_id=p_draft
       AND c.nonce_sha256=p_nonce_sha256
       AND c.proposer_subject=p_proposer AND c.approver_subject=p_approver
       AND c.consumed_at IS NULL AND c.expires_at>clock_timestamp()
       AND EXISTS (SELECT 1 FROM policy_dual_signature_receipt r
                   WHERE r.receipt_id=p_receipt AND r.ca_id=p_ca
                     AND r.policy_draft_id=p_draft);
    GET DIAGNOSTICS v_updated=ROW_COUNT;
    RETURN v_updated=1;
END $fn$;
REVOKE ALL ON FUNCTION consume_policy_approval_challenge_lab(
    UUID,UUID,UUID,BYTEA,TEXT,TEXT,UUID) FROM PUBLIC;
COMMIT;
