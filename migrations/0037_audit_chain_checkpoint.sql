-- Migration 0037: signed checkpoints of the audit chain in the laboratory
-- (ADR-0023, Proposed). The chain of migration 0036 (ADR-0022) is evidence
-- only against a head kept outside the database. Until now that head was an
-- unsigned manifest exported by hand.
--
-- The laboratory signer now signs checkpoints with a P-256 audit key, distinct
-- from every CA key. A checkpoint is the head of the chain at one sequence.
-- The signed bytes are trust_pki_core::audit_chain::audit_checkpoint_message:
-- sequence, chain hash, signing instant and key identifier (SHA-256 of the
-- key's SubjectPublicKeyInfo DER).
--
-- Before it signs, the signer recomputes every link after the last checkpoint
-- it signed, from the raw events, in Rust. It keeps that last checkpoint in
-- its own state file, outside the database, so it refuses a chain that was
-- rewritten or rolled back behind it. The database stores checkpoints only
-- through lab_signer_record_audit_checkpoint, granted to the signer role.
-- No database function verifies the signature: lab_verify_audit_chain does,
-- with the public key supplied out of band.
BEGIN;

CREATE TABLE audit_chain_checkpoint (
    seq BIGINT PRIMARY KEY REFERENCES audit_chain_link (seq),
    chain_hash BYTEA NOT NULL CHECK (octet_length(chain_hash) = 32),
    key_id BYTEA NOT NULL CHECK (octet_length(key_id) = 32),
    signed_at TIMESTAMPTZ NOT NULL,
    -- An ECDSA P-256 signature in DER is at most 72 bytes.
    signature BYTEA NOT NULL CHECK (octet_length(signature) BETWEEN 8 AND 72),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON audit_chain_checkpoint FROM PUBLIC;

CREATE TRIGGER prevent_audit_checkpoint_update
    BEFORE UPDATE OR DELETE ON audit_chain_checkpoint
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_chain_modification();
CREATE TRIGGER prevent_audit_checkpoint_truncate
    BEFORE TRUNCATE ON audit_chain_checkpoint
    FOR EACH STATEMENT EXECUTE FUNCTION prevent_audit_chain_modification();

-- The latest checkpoint, for the signer to compare with its own state.
CREATE FUNCTION lab_signer_audit_checkpoint_latest()
RETURNS TABLE (seq BIGINT, chain_hash BYTEA, key_id BYTEA, signed_at_unix BIGINT, signature BYTEA)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
    SELECT c.seq, c.chain_hash, c.key_id, extract(epoch FROM c.signed_at)::bigint, c.signature
    FROM audit_chain_checkpoint c ORDER BY c.seq DESC LIMIT 1
$fn$;
REVOKE ALL ON FUNCTION lab_signer_audit_checkpoint_latest() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION lab_signer_audit_checkpoint_latest() TO trust_lab_signer;

-- Links after p_after, with the raw columns of their events (absent when an
-- event no longer exists), for the signer to recompute.
CREATE FUNCTION lab_signer_audit_links(p_after BIGINT, p_max INTEGER)
RETURNS TABLE (seq BIGINT, event_sha256 BYTEA, previous_hash BYTEA, chain_hash BYTEA,
               event_id BYTEA, ca_id BYTEA, request_id BYTEA, actor_id TEXT, event_type TEXT,
               decision TEXT, policy_version TEXT, recorded_at_micros BIGINT)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
BEGIN
    IF p_after IS NULL OR p_after < 0 OR p_max IS NULL OR p_max < 1 OR p_max > 10000 THEN
        RAISE EXCEPTION 'invalid audit link range' USING ERRCODE = '22023';
    END IF;
    RETURN QUERY
    SELECT l.seq, l.event_sha256, l.previous_hash, l.chain_hash,
           uuid_send(a.event_id), uuid_send(a.ca_id), uuid_send(a.request_id), a.actor_id,
           a.event_type, a.decision, a.policy_version,
           (extract(epoch FROM a.recorded_at) * 1000000)::bigint
    FROM audit_chain_link l LEFT JOIN audit_event a ON a.event_id = l.event_id
    WHERE l.seq > p_after
    ORDER BY l.seq
    LIMIT p_max;
END;
$fn$;
REVOKE ALL ON FUNCTION lab_signer_audit_links(BIGINT, INTEGER) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION lab_signer_audit_links(BIGINT, INTEGER) TO trust_lab_signer;

-- Records a checkpoint the signer signed. Structural checks only: the link
-- exists with that hash, and checkpoints only move forward. The append-only
-- checkpoint table is the record; no audit event is written, since it would
-- itself be sealed and call for the next checkpoint, forever.
CREATE FUNCTION lab_signer_record_audit_checkpoint(
    p_seq BIGINT, p_chain_hash BYTEA, p_key_id BYTEA, p_signed_at_unix BIGINT, p_signature BYTEA
) RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_latest BIGINT;
BEGIN
    LOCK TABLE audit_chain_checkpoint IN EXCLUSIVE MODE;
    IF NOT EXISTS (SELECT 1 FROM audit_chain_link l WHERE l.seq = p_seq AND l.chain_hash = p_chain_hash) THEN
        RAISE EXCEPTION 'no audit link with this sequence and hash' USING ERRCODE = 'TP409';
    END IF;
    SELECT max(c.seq) INTO v_latest FROM audit_chain_checkpoint c;
    IF v_latest IS NOT NULL AND p_seq <= v_latest THEN
        RAISE EXCEPTION 'audit checkpoints only move forward' USING ERRCODE = 'TP409';
    END IF;
    INSERT INTO audit_chain_checkpoint (seq, chain_hash, key_id, signed_at, signature)
    VALUES (p_seq, p_chain_hash, p_key_id, to_timestamp(p_signed_at_unix), p_signature);
END;
$fn$;
REVOKE ALL ON FUNCTION lab_signer_record_audit_checkpoint(BIGINT, BYTEA, BYTEA, BIGINT, BYTEA) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION lab_signer_record_audit_checkpoint(BIGINT, BYTEA, BYTEA, BIGINT, BYTEA) TO trust_lab_signer;

CREATE FUNCTION management_audit_checkpoint_version() RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $fn$ SELECT 1 $fn$;
REVOKE ALL ON FUNCTION management_audit_checkpoint_version() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION management_audit_checkpoint_version() TO trust_api_reader, trust_profile_writer, trust_lab_signer;

COMMIT;
