-- v0.27 (lab): hash-chained audit, verifiable outside the database
-- (ADR-0006 acceptance condition 5, open item D-04; status Proposed,
-- implemented in lab at the owner's request). LAB ONLY.
-- * seal_audit_chain() appends every not yet sealed audit_event and
--   schema_change_audit row to audit_chain_entry, in one chain:
--     event_sha256 = SHA-256 of the record's canonical encoding (below)
--     entry_hash   = SHA-256("trust-platform:audit-chain:v1\0" || previous
--                    || seq as 8-byte big-endian || event_sha256)
--   the format of trust_pki_core::audit_chain::next_audit_hash; the first
--   entry's previous is 32 zero bytes. Sealing is a scheduled job, not a
--   trigger, so business transactions never wait on the chain head.
-- * Canonical record encoding: "trust-platform:audit-record:v1\0", then the
--   source name and each column in order, each as 0x00 (NULL) or 0x01, a
--   4-byte big-endian length and the bytes: UUIDs as 16 bytes, text as
--   UTF-8, timestamps as 8-byte big-endian microseconds since the Unix
--   epoch, integers as 8-byte big-endian. The Rust verifier
--   (audit_chain::AuditRecord) re-encodes the raw columns independently.
-- * audit_chain_entries() returns entries with their raw source columns
--   (NULL when the source row is gone) for the external verifier, which
--   recomputes the chain and compares it with checkpoints it keeps outside
--   the database (audit_chain_anchor example). A superuser can rewrite the
--   database, but not the exported checkpoints: rewriting or deleting a
--   sealed record, truncating the chain or recomputing it is detected at the
--   next verification against them. Records not yet sealed, and entries
--   sealed after the last exported checkpoint, are not protected.
-- * Owner trust_audit_owner (NOLOGIN); trust_audit_sealer may seal,
--   trust_audit_verifier may read entries and count unsealed records. The
--   chain table is append-only (ENABLE ALWAYS guards).
-- Apply after 0026 as a superuser.
BEGIN;

DO $roles$
DECLARE
    r TEXT;
BEGIN
    FOREACH r IN ARRAY ARRAY['trust_audit_owner', 'trust_audit_sealer', 'trust_audit_verifier'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
            EXECUTE format('CREATE ROLE %I NOLOGIN', r);
        END IF;
    END LOOP;
END $roles$;

CREATE TABLE audit_chain_entry (
    seq BIGINT PRIMARY KEY CHECK (seq >= 1),
    source TEXT NOT NULL CHECK (source IN ('audit_event', 'schema_change_audit')),
    source_key TEXT NOT NULL,
    event_sha256 BYTEA NOT NULL CHECK (length(event_sha256) = 32),
    previous BYTEA NOT NULL CHECK (length(previous) = 32),
    entry_hash BYTEA NOT NULL CHECK (length(entry_hash) = 32),
    sealed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (source, source_key)
);
ALTER TABLE audit_chain_entry OWNER TO trust_audit_owner;

CREATE FUNCTION guard_audit_chain()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp AS $fn$
BEGIN
    RAISE EXCEPTION 'audit_chain_entry is append-only'
        USING ERRCODE = 'restrict_violation';
END $fn$;
ALTER FUNCTION guard_audit_chain() OWNER TO trust_audit_owner;
REVOKE ALL ON FUNCTION guard_audit_chain() FROM PUBLIC;
CREATE TRIGGER audit_chain_entry_append_only
    BEFORE UPDATE OR DELETE ON audit_chain_entry
    FOR EACH ROW EXECUTE FUNCTION guard_audit_chain();
CREATE TRIGGER audit_chain_entry_no_truncate
    BEFORE TRUNCATE ON audit_chain_entry
    FOR EACH STATEMENT EXECUTE FUNCTION guard_audit_chain();
ALTER TABLE audit_chain_entry ENABLE ALWAYS TRIGGER audit_chain_entry_append_only;
ALTER TABLE audit_chain_entry ENABLE ALWAYS TRIGGER audit_chain_entry_no_truncate;

-- One length-prefixed field of the canonical encoding.
CREATE FUNCTION audit_field(p BYTEA)
RETURNS BYTEA
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog, public, pg_temp AS $fn$
    SELECT CASE WHEN p IS NULL THEN '\x00'::bytea
                ELSE '\x01'::bytea || int4send(length(p)) || p END
$fn$;

CREATE FUNCTION audit_ts(p TIMESTAMPTZ)
RETURNS BYTEA
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog, public, pg_temp AS $fn$
    SELECT int8send((extract(epoch FROM p) * 1000000)::bigint)
$fn$;

CREATE FUNCTION audit_event_digest(e audit_event)
RETURNS BYTEA
LANGUAGE sql STABLE
SET search_path = pg_catalog, public, pg_temp AS $fn$
    SELECT sha256(convert_to('trust-platform:audit-record:v1', 'UTF8') || '\x00'::bytea
        || audit_field(convert_to('audit_event', 'UTF8'))
        || audit_field(uuid_send(e.event_id))
        || audit_field(uuid_send(e.ca_id))
        || audit_field(uuid_send(e.request_id))
        || audit_field(convert_to(e.actor_id, 'UTF8'))
        || audit_field(convert_to(e.event_type, 'UTF8'))
        || audit_field(convert_to(e.decision, 'UTF8'))
        || audit_field(convert_to(e.policy_version, 'UTF8'))
        || audit_field(audit_ts(e.recorded_at)))
$fn$;

CREATE FUNCTION schema_change_digest(c schema_change_audit)
RETURNS BYTEA
LANGUAGE sql STABLE
SET search_path = pg_catalog, public, pg_temp AS $fn$
    SELECT sha256(convert_to('trust-platform:audit-record:v1', 'UTF8') || '\x00'::bytea
        || audit_field(convert_to('schema_change_audit', 'UTF8'))
        || audit_field(int8send(c.change_seq))
        || audit_field(audit_ts(c.recorded_at))
        || audit_field(convert_to(c.event, 'UTF8'))
        || audit_field(convert_to(c.command_tag, 'UTF8'))
        || audit_field(convert_to(c.object_type, 'UTF8'))
        || audit_field(convert_to(c.schema_name, 'UTF8'))
        || audit_field(convert_to(c.object_identity, 'UTF8'))
        || audit_field(convert_to(c.session_user_name, 'UTF8'))
        || audit_field(int8send(c.transaction_id::text::numeric::bigint)))
$fn$;

CREATE FUNCTION seal_audit_chain(p_limit INTEGER)
RETURNS INTEGER
LANGUAGE plpgsql AS $fn$
DECLARE
    v_seq BIGINT;
    v_prev BYTEA;
    v_hash BYTEA;
    v_count INTEGER := 0;
    r RECORD;
BEGIN
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 100000 THEN
        RAISE EXCEPTION 'seal limit must be between 1 and 100000'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- One sealer at a time; readers are not blocked.
    LOCK TABLE audit_chain_entry IN EXCLUSIVE MODE;
    SELECT seq, entry_hash INTO v_seq, v_prev
    FROM audit_chain_entry ORDER BY seq DESC LIMIT 1;
    v_seq := coalesce(v_seq, 0);
    v_prev := coalesce(v_prev, '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea);
    FOR r IN
        SELECT * FROM (
            SELECT 'audit_event'::text AS source, e.event_id::text AS source_key,
                   e.recorded_at, audit_event_digest(e) AS digest
            FROM audit_event e
            WHERE NOT EXISTS (SELECT 1 FROM audit_chain_entry x
                              WHERE x.source = 'audit_event' AND x.source_key = e.event_id::text)
            UNION ALL
            SELECT 'schema_change_audit', c.change_seq::text, c.recorded_at,
                   schema_change_digest(c)
            FROM schema_change_audit c
            WHERE NOT EXISTS (SELECT 1 FROM audit_chain_entry x
                              WHERE x.source = 'schema_change_audit'
                                AND x.source_key = c.change_seq::text)
        ) pending
        ORDER BY recorded_at, source, source_key
        LIMIT p_limit
    LOOP
        v_seq := v_seq + 1;
        v_hash := sha256(convert_to('trust-platform:audit-chain:v1', 'UTF8') || '\x00'::bytea
                         || v_prev || int8send(v_seq) || r.digest);
        INSERT INTO audit_chain_entry (seq, source, source_key, event_sha256, previous, entry_hash)
        VALUES (v_seq, r.source, r.source_key, r.digest, v_prev, v_hash);
        v_prev := v_hash;
        v_count := v_count + 1;
    END LOOP;
    RETURN v_count;
END $fn$;

-- Entries after p_after_seq with the raw source columns, for re-encoding
-- outside the database. UUIDs as text, timestamps as epoch microseconds.
CREATE FUNCTION audit_chain_entries(p_after_seq BIGINT, p_limit INTEGER)
RETURNS TABLE (
    seq BIGINT, source TEXT, source_key TEXT, event_sha256 BYTEA,
    previous BYTEA, entry_hash BYTEA, source_present BOOLEAN,
    event_id TEXT, ca_id TEXT, request_id TEXT, actor_id TEXT, event_type TEXT,
    decision TEXT, policy_version TEXT, recorded_at_us BIGINT,
    change_seq BIGINT, change_event TEXT, command_tag TEXT, object_type TEXT,
    schema_name TEXT, object_identity TEXT, session_user_name TEXT,
    transaction_id TEXT)
LANGUAGE sql STABLE AS $fn$
    SELECT x.seq, x.source, x.source_key, x.event_sha256, x.previous, x.entry_hash,
           (e.event_id IS NOT NULL OR c.change_seq IS NOT NULL),
           e.event_id::text, e.ca_id::text, e.request_id::text, e.actor_id, e.event_type,
           e.decision, e.policy_version,
           (extract(epoch FROM coalesce(e.recorded_at, c.recorded_at)) * 1000000)::bigint,
           c.change_seq, c.event, c.command_tag, c.object_type, c.schema_name,
           c.object_identity, c.session_user_name, c.transaction_id::text
    FROM audit_chain_entry x
    LEFT JOIN audit_event e
      ON x.source = 'audit_event' AND e.event_id::text = x.source_key
    LEFT JOIN schema_change_audit c
      ON x.source = 'schema_change_audit' AND c.change_seq::text = x.source_key
    WHERE x.seq > p_after_seq
    ORDER BY x.seq
    LIMIT least(greatest(p_limit, 1), 10000)
$fn$;

CREATE FUNCTION unsealed_audit_records(p_older_than INTERVAL)
RETURNS BIGINT
LANGUAGE sql STABLE AS $fn$
    SELECT (SELECT count(*) FROM audit_event e
            WHERE e.recorded_at < now() - p_older_than
              AND NOT EXISTS (SELECT 1 FROM audit_chain_entry x
                              WHERE x.source = 'audit_event' AND x.source_key = e.event_id::text))
         + (SELECT count(*) FROM schema_change_audit c
            WHERE c.recorded_at < now() - p_older_than
              AND NOT EXISTS (SELECT 1 FROM audit_chain_entry x
                              WHERE x.source = 'schema_change_audit'
                                AND x.source_key = c.change_seq::text))
$fn$;

GRANT SELECT ON audit_event TO trust_audit_owner;
GRANT SELECT ON schema_change_audit TO trust_audit_owner;

DO $fns$
DECLARE
    f TEXT;
BEGIN
    FOREACH f IN ARRAY ARRAY['seal_audit_chain(integer)',
                             'audit_chain_entries(bigint,integer)',
                             'unsealed_audit_records(interval)'] LOOP
        EXECUTE format('ALTER FUNCTION %s OWNER TO trust_audit_owner', f);
        EXECUTE format('ALTER FUNCTION %s SECURITY DEFINER', f);
        EXECUTE format('ALTER FUNCTION %s SET search_path = pg_catalog, public, pg_temp', f);
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
    END LOOP;
    FOREACH f IN ARRAY ARRAY['audit_field(bytea)', 'audit_ts(timestamp with time zone)',
                             'audit_event_digest(audit_event)',
                             'schema_change_digest(schema_change_audit)'] LOOP
        EXECUTE format('ALTER FUNCTION %s OWNER TO trust_audit_owner', f);
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
    END LOOP;
END $fns$;

GRANT EXECUTE ON FUNCTION seal_audit_chain(integer) TO trust_audit_sealer;
GRANT EXECUTE ON FUNCTION audit_chain_entries(bigint,integer),
                          unsealed_audit_records(interval) TO trust_audit_verifier;

SELECT acknowledge_schema_changes('0027_audit_chain');

COMMIT;
