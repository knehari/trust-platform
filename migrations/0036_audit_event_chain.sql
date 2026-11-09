-- Migration 0036: tamper-evident audit chain in the laboratory (ADR-0022,
-- Proposed). Until now audit_event was protected only by a trigger that the
-- database owner can disable (migration 0001): an owner, a superuser or a
-- restored backup could alter, remove or insert an event without trace.
--
-- Each committed audit event is sealed, once, into a SHA-256 hash chain:
--
--   event_sha256 = SHA-256(audit_event_canonical(event))
--   chain_hash   = SHA-256("trust-platform:audit-chain:v1" || 0x00
--                          || previous chain_hash || int8 BE seq || event_sha256)
--
-- with an all-zero previous hash before sequence 1. This is the construction
-- of trust_pki_core::audit_chain::next_audit_hash. The independent tool
-- lab_verify_audit_chain recomputes every digest and link from the raw
-- columns, in Rust, without trusting these functions.
--
-- The chain detects a change only against a head recorded outside the
-- database: someone who can rewrite audit_event can also rewrite the chain.
-- The tool prints a manifest (sequence and hash of the head) for export and
-- checks that a previously exported head is still part of the chain.
--
-- Sealing runs after commit, in a separate pass (seal_audit_events_lab),
-- never inside the transactions that write events: those transactions hold
-- CA, CRL and application locks, and a global head lock there could
-- deadlock with them. Events not yet sealed are not protected; the API runs
-- the pass periodically and readers see whether an event is sealed
-- (management_audit_seal).
BEGIN;

-- Canonical, unambiguous encoding of one audit event (version 1). Every
-- column of audit_event, in table order; texts are length-prefixed UTF-8,
-- optional values carry a presence byte, the instant is microseconds since
-- the Unix epoch as a big-endian int8.
CREATE FUNCTION audit_event_canonical(
    p_event_id UUID, p_ca_id UUID, p_request_id UUID, p_actor_id TEXT, p_event_type TEXT,
    p_decision TEXT, p_policy_version TEXT, p_recorded_at TIMESTAMPTZ
) RETURNS BYTEA
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $fn$
    SELECT convert_to('trust-platform:audit-event:v1', 'UTF8') || '\x00'::bytea
        || uuid_send(p_event_id)
        || CASE WHEN p_ca_id IS NULL THEN '\x00'::bytea ELSE '\x01'::bytea || uuid_send(p_ca_id) END
        || CASE WHEN p_request_id IS NULL THEN '\x00'::bytea ELSE '\x01'::bytea || uuid_send(p_request_id) END
        || int4send(octet_length(convert_to(p_actor_id, 'UTF8'))) || convert_to(p_actor_id, 'UTF8')
        || int4send(octet_length(convert_to(p_event_type, 'UTF8'))) || convert_to(p_event_type, 'UTF8')
        || int4send(octet_length(convert_to(p_decision, 'UTF8'))) || convert_to(p_decision, 'UTF8')
        || CASE WHEN p_policy_version IS NULL THEN '\x00'::bytea
                ELSE '\x01'::bytea || int4send(octet_length(convert_to(p_policy_version, 'UTF8')))
                     || convert_to(p_policy_version, 'UTF8') END
        || int8send((extract(epoch FROM p_recorded_at) * 1000000)::bigint)
$fn$;
REVOKE ALL ON FUNCTION audit_event_canonical(UUID, UUID, UUID, TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ) FROM PUBLIC;

-- One link per sealed event; the sequence has no gap and starts at 1.
CREATE TABLE audit_chain_link (
    seq BIGINT PRIMARY KEY CHECK (seq > 0),
    event_id UUID NOT NULL UNIQUE REFERENCES audit_event (event_id),
    event_sha256 BYTEA NOT NULL CHECK (octet_length(event_sha256) = 32),
    previous_hash BYTEA NOT NULL CHECK (octet_length(previous_hash) = 32),
    chain_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(chain_hash) = 32),
    sealed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON audit_chain_link FROM PUBLIC;

-- Defense in depth, as for audit_event: the owner can still bypass it, which
-- is what an externally recorded head detects.
CREATE FUNCTION prevent_audit_chain_modification() RETURNS TRIGGER
LANGUAGE plpgsql SET search_path = pg_catalog AS $fn$
BEGIN
    RAISE EXCEPTION 'audit records may not be updated, deleted or truncated';
END;
$fn$;
CREATE TRIGGER prevent_audit_chain_update
    BEFORE UPDATE OR DELETE ON audit_chain_link
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_chain_modification();
CREATE TRIGGER prevent_audit_chain_truncate
    BEFORE TRUNCATE ON audit_chain_link
    FOR EACH STATEMENT EXECUTE FUNCTION prevent_audit_chain_modification();
-- migration 0001 covered UPDATE and DELETE of events, not TRUNCATE.
CREATE TRIGGER prevent_audit_truncate
    BEFORE TRUNCATE ON audit_event
    FOR EACH STATEMENT EXECUTE FUNCTION prevent_audit_chain_modification();

-- Seal up to p_max committed events not yet sealed, oldest first
-- (recorded_at, then event_id). One pass at a time: the table lock blocks
-- other sealers, not readers. Returns how many were sealed and the head.
CREATE FUNCTION seal_audit_events_lab(p_max INTEGER)
RETURNS TABLE (sealed INTEGER, head_seq BIGINT, head_hash TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_seq BIGINT := 0;
    v_head BYTEA := decode(repeat('00', 32), 'hex');
    v_count INTEGER := 0;
    v_event BYTEA;
    v_next BYTEA;
    r RECORD;
BEGIN
    IF p_max IS NULL OR p_max < 1 OR p_max > 10000 THEN
        RAISE EXCEPTION 'p_max must be between 1 and 10000' USING ERRCODE = '22023';
    END IF;
    LOCK TABLE audit_chain_link IN EXCLUSIVE MODE;
    SELECT l.seq, l.chain_hash INTO v_seq, v_head
    FROM audit_chain_link l ORDER BY l.seq DESC LIMIT 1;
    IF NOT FOUND THEN
        v_seq := 0;
        v_head := decode(repeat('00', 32), 'hex');
    END IF;
    FOR r IN
        SELECT a.event_id, a.ca_id, a.request_id, a.actor_id, a.event_type, a.decision,
               a.policy_version, a.recorded_at
        FROM audit_event a
        WHERE NOT EXISTS (SELECT 1 FROM audit_chain_link l WHERE l.event_id = a.event_id)
        ORDER BY a.recorded_at, a.event_id
        LIMIT p_max
    LOOP
        v_seq := v_seq + 1;
        v_event := sha256(audit_event_canonical(r.event_id, r.ca_id, r.request_id, r.actor_id,
                                                r.event_type, r.decision, r.policy_version,
                                                r.recorded_at));
        v_next := sha256(convert_to('trust-platform:audit-chain:v1', 'UTF8') || '\x00'::bytea
                         || v_head || int8send(v_seq) || v_event);
        INSERT INTO audit_chain_link (seq, event_id, event_sha256, previous_hash, chain_hash)
        VALUES (v_seq, r.event_id, v_event, v_head, v_next);
        v_head := v_next;
        v_count := v_count + 1;
    END LOOP;
    RETURN QUERY SELECT v_count, v_seq, encode(v_head, 'hex');
END;
$fn$;
REVOKE ALL ON FUNCTION seal_audit_events_lab(INTEGER) FROM PUBLIC;
-- Sealing only records digests of events that already exist; the API's
-- writer login runs it.
GRANT EXECUTE ON FUNCTION seal_audit_events_lab(INTEGER) TO trust_profile_writer;

-- Readers see which events of their authorities are sealed, never the
-- global sequence or hashes, which would reveal other authorities' volume.
-- A separate view, not a column of management_audit: the API looks up only
-- the events of the page it returns, by UUID, through the link index, so the
-- history queries of migrations 0017-0020 keep their plans.
CREATE VIEW management_audit_seal WITH (security_barrier = true) AS
SELECT l.event_id AS event_uuid, a.ca_id::text AS ca_id
FROM audit_chain_link l
JOIN audit_event a ON a.event_id = l.event_id
WHERE EXISTS (
    SELECT 1 FROM management_reader_grant g
    WHERE g.issuer = current_setting('trust.reader_issuer', true)
      AND g.subject = current_setting('trust.reader_subject', true)
      AND g.ca_id = a.ca_id
);
GRANT SELECT ON management_audit_seal TO trust_api_reader;

CREATE FUNCTION management_audit_chain_version() RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $fn$ SELECT 1 $fn$;
REVOKE ALL ON FUNCTION management_audit_chain_version() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION management_audit_chain_version() TO trust_api_reader, trust_profile_writer;

COMMIT;
