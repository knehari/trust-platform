-- v0.22 (lab): bind each CA to its issuer certificate. LAB ONLY.
-- * ca_issuer_certificate holds the one issuer certificate (DER) a CA signs
--   CRLs with. It is registered once by register_ca_issuer, after the Rust
--   core has parsed and checked it (SQL cannot parse DER), and is immutable;
--   key rollover would need a new CA row (out of scope).
-- * record_crl_intent and store_reconciled_crl take the SHA-256 of the
--   issuer certificate the CRL is built and verified with, and refuse
--   (SQLSTATE 42704) unless it is the CA's registered certificate. A CRL of
--   another CA can therefore no longer be signed for, or stored under, this
--   ca_id. The parameter defaults to NULL, which is refused; the check runs
--   after all earlier checks so their error codes are unchanged.
-- Apply after 0021 as the migration owner.
BEGIN;

CREATE TABLE ca_issuer_certificate (
    ca_id UUID PRIMARY KEY REFERENCES ca(ca_id),
    certificate_der BYTEA NOT NULL
        CHECK (octet_length(certificate_der) BETWEEN 1 AND 65536),
    certificate_sha256 BYTEA GENERATED ALWAYS AS (sha256(certificate_der)) STORED,
    registered_by TEXT NOT NULL CHECK (length(registered_by) BETWEEN 1 AND 1024),
    registered_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON ca_issuer_certificate FROM PUBLIC;

CREATE FUNCTION guard_ca_issuer_certificate() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    RAISE EXCEPTION 'ca_issuer_certificate is immutable' USING ERRCODE='23514';
END $fn$;
CREATE TRIGGER ca_issuer_certificate_guard
    BEFORE UPDATE OR DELETE ON ca_issuer_certificate
    FOR EACH ROW EXECUTE FUNCTION guard_ca_issuer_certificate();
CREATE TRIGGER ca_issuer_certificate_no_truncate
    BEFORE TRUNCATE ON ca_issuer_certificate
    FOR EACH STATEMENT EXECUTE FUNCTION guard_ca_issuer_certificate();

-- Idempotent for the same certificate; a different one is refused.
CREATE FUNCTION register_ca_issuer(p_ca UUID, p_certificate_der BYTEA, p_actor TEXT)
RETURNS BYTEA
LANGUAGE plpgsql AS $fn$
DECLARE
    v_existing BYTEA;
BEGIN
    IF p_ca IS NULL OR p_certificate_der IS NULL
       OR octet_length(p_certificate_der) NOT BETWEEN 1 AND 65536
       OR p_actor IS NULL OR length(p_actor) NOT BETWEEN 1 AND 1024
    THEN
        RAISE EXCEPTION 'invalid issuer registration input' USING ERRCODE='22023';
    END IF;
    PERFORM 1 FROM ca WHERE ca_id = p_ca FOR NO KEY UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown CA' USING ERRCODE='22023';
    END IF;
    SELECT certificate_der INTO v_existing FROM ca_issuer_certificate WHERE ca_id = p_ca;
    IF FOUND THEN
        IF v_existing <> p_certificate_der THEN
            RAISE EXCEPTION 'CA already has a different issuer certificate'
              USING ERRCODE='23514';
        END IF;
        RETURN sha256(v_existing);
    END IF;
    INSERT INTO ca_issuer_certificate(ca_id, certificate_der, registered_by)
    VALUES (p_ca, p_certificate_der, p_actor);
    INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), p_ca, NULL, p_actor, 'ca.issuer.registered',
            'REGISTERED:' || encode(sha256(p_certificate_der), 'hex'));
    RETURN sha256(p_certificate_der);
END $fn$;

DROP FUNCTION record_crl_intent(uuid,bigint,text,bytea,bytea,bigint,bigint,bigint);
CREATE FUNCTION record_crl_intent(
    p_ca UUID, p_crl_number BIGINT, p_operation_ref TEXT, p_tbs_sha256 BYTEA,
    p_entries_sha256 BYTEA, p_this_update_unix BIGINT, p_next_update_unix BIGINT,
    p_expired_certs_on_crl_since_unix BIGINT, p_issuer_sha256 BYTEA DEFAULT NULL
)
RETURNS TEXT
LANGUAGE plpgsql AS $fn$
DECLARE
    v_pub crl_publication%ROWTYPE;
    v_interval INTERVAL;
BEGIN
    IF p_ca IS NULL OR p_crl_number IS NULL
       OR p_operation_ref IS NULL OR length(p_operation_ref) NOT BETWEEN 1 AND 256
       OR p_tbs_sha256 IS NULL OR octet_length(p_tbs_sha256) <> 32
       OR p_entries_sha256 IS NULL OR octet_length(p_entries_sha256) <> 32
       OR p_this_update_unix IS NULL OR p_next_update_unix IS NULL
    THEN
        RAISE EXCEPTION 'invalid CRL intent input' USING ERRCODE='22023';
    END IF;
    -- Intents and reservations of one CA are serialised on the CA row (taken
    -- before the publication row, as reserve_crl does), so the higher-number
    -- check below cannot race a concurrent reservation.
    PERFORM 1 FROM ca WHERE ca_id = p_ca FOR NO KEY UPDATE;
    SELECT * INTO v_pub FROM crl_publication cp
    WHERE cp.ca_id = p_ca AND cp.crl_number = p_crl_number FOR UPDATE;
    -- An abandoned reservation was never signed: certain, reserve again.
    IF FOUND AND v_pub.status = 'ABANDONED' AND v_pub.operation_ref = p_operation_ref THEN
        RAISE EXCEPTION 'CRL intent refused: the reservation was abandoned'
          USING ERRCODE='55000';
    END IF;
    IF NOT FOUND OR v_pub.status <> 'RESERVED'
       OR v_pub.operation_ref <> p_operation_ref
    THEN
        RAISE EXCEPTION 'CRL intent refused: unknown number, wrong operation or not RESERVED'
          USING ERRCODE='23514';
    END IF;
    IF p_entries_sha256 <> v_pub.entries_sha256
       OR p_this_update_unix <> floor(extract(epoch FROM v_pub.this_update))::bigint
       OR p_next_update_unix <> floor(extract(epoch FROM v_pub.next_update))::bigint
       OR p_expired_certs_on_crl_since_unix IS DISTINCT FROM
          floor(extract(epoch FROM v_pub.expired_certs_on_crl_since))::bigint
    THEN
        RAISE EXCEPTION 'CRL intent refused: entries, number or times differ from the reservation'
          USING ERRCODE='23514';
    END IF;
    -- Only the CA's highest reserved number may be signed: once a newer
    -- reservation exists (in any status), this one is superseded and the
    -- worker must reserve again. Relying parties keep the highest number.
    IF EXISTS (SELECT 1 FROM crl_publication cp
               WHERE cp.ca_id = p_ca AND cp.crl_number > p_crl_number) THEN
        RAISE EXCEPTION 'CRL intent refused: a higher CRL number has been reserved'
          USING ERRCODE='55000';
    END IF;
    -- The reservation's own nextUpdate, independent of later policy changes.
    IF v_pub.next_update <= clock_timestamp() THEN
        RAISE EXCEPTION 'CRL intent refused: the reserved nextUpdate has passed'
          USING ERRCODE='55000';
    END IF;
    -- A reservation older than the issue interval is stale: a newer CRL is
    -- already due. The row stays RESERVED for abandon_stale_crl_reservations.
    SELECT p.crl_issue_interval INTO v_interval
    FROM ca_revocation_policy p WHERE p.ca_id = p_ca FOR SHARE;
    IF v_pub.this_update + COALESCE(v_interval, INTERVAL '24 hours') <= clock_timestamp() THEN
        RAISE EXCEPTION 'CRL intent refused: reservation older than the CRL issue interval'
          USING ERRCODE='55000';
    END IF;
    -- The CRL is built and signed with exactly the CA's registered issuer
    -- certificate (checked last so the earlier refusals keep their codes).
    IF p_issuer_sha256 IS NULL OR NOT EXISTS (
        SELECT 1 FROM ca_issuer_certificate i
        WHERE i.ca_id = p_ca AND i.certificate_sha256 = p_issuer_sha256)
    THEN
        RAISE EXCEPTION 'CRL intent refused: issuer is not the CA''s registered issuer certificate'
          USING ERRCODE='42704';
    END IF;
    UPDATE crl_publication
    SET status = 'INTENT_RECORDED', tbs_sha256 = p_tbs_sha256,
        intent_recorded_at = clock_timestamp()
    WHERE ca_id = p_ca AND crl_number = p_crl_number;
    INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), p_ca, NULL, v_pub.actor_id, 'crl.intent',
            'INTENT_RECORDED:' || p_crl_number);
    RETURN 'INTENT_RECORDED';
END $fn$;

DROP FUNCTION store_reconciled_crl(uuid,bigint,text,bytea,bytea,bytea,text);
CREATE FUNCTION store_reconciled_crl(
    p_ca UUID, p_crl_number BIGINT, p_operation_ref TEXT, p_tbs_sha256 BYTEA,
    p_crl_sha256 BYTEA, p_crl_der BYTEA, p_actor TEXT, p_issuer_sha256 BYTEA DEFAULT NULL
)
RETURNS TEXT
LANGUAGE plpgsql AS $fn$
DECLARE
    v_pub crl_publication%ROWTYPE;
    v_digest BYTEA;
BEGIN
    IF p_ca IS NULL OR p_crl_number IS NULL
       OR p_operation_ref IS NULL OR length(p_operation_ref) NOT BETWEEN 1 AND 256
       OR p_tbs_sha256 IS NULL OR octet_length(p_tbs_sha256) <> 32
       OR p_crl_der IS NULL OR octet_length(p_crl_der) = 0
       OR p_crl_sha256 IS NULL OR p_crl_sha256 <> sha256(p_crl_der)
       OR p_actor IS NULL OR length(p_actor) NOT BETWEEN 1 AND 1024
    THEN
        RAISE EXCEPTION 'invalid CRL reconciliation input' USING ERRCODE='22023';
    END IF;
    SELECT * INTO v_pub FROM crl_publication cp
    WHERE cp.ca_id = p_ca AND cp.crl_number = p_crl_number FOR UPDATE;
    -- Quarantined after a recorded intent, and the TBS hash equals the one
    -- journaled before signing: these are the bytes that were meant to be
    -- signed, so storing them once independently verified loses nothing.
    IF NOT FOUND OR v_pub.status <> 'RECONCILIATION_REQUIRED'
       OR v_pub.tbs_sha256 IS NULL
       OR v_pub.operation_ref <> p_operation_ref
       OR v_pub.tbs_sha256 <> p_tbs_sha256
    THEN
        RAISE EXCEPTION 'CRL reconciliation refused: unknown number, not quarantined after an intent, wrong operation or TBS hash'
          USING ERRCODE='23514';
    END IF;
    SELECT sha256(COALESCE(string_agg(
               crl_entry_encoding(s.serial_der_content, s.revoked_at,
                                  s.reason_code, s.invalidity_at),
               '\x'::bytea ORDER BY s.serial_der_content), '\x'::bytea))
    INTO v_digest
    FROM crl_entry_snapshot s
    WHERE s.ca_id = p_ca AND s.crl_number = p_crl_number;
    IF v_digest IS DISTINCT FROM v_pub.entries_sha256 THEN
        RAISE EXCEPTION 'CRL reconciliation refused: snapshot does not match the reserved digest'
          USING ERRCODE='23514';
    END IF;
    IF p_issuer_sha256 IS NULL OR NOT EXISTS (
        SELECT 1 FROM ca_issuer_certificate i
        WHERE i.ca_id = p_ca AND i.certificate_sha256 = p_issuer_sha256)
    THEN
        RAISE EXCEPTION 'CRL reconciliation refused: issuer is not the CA''s registered issuer certificate'
          USING ERRCODE='42704';
    END IF;
    UPDATE crl_publication
    SET status = 'STORED', crl_sha256 = p_crl_sha256, crl_der = p_crl_der
    WHERE ca_id = p_ca AND crl_number = p_crl_number;
    INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), p_ca, NULL, p_actor, 'crl.reconciled',
            'STORED:' || p_crl_number);
    RETURN 'STORED';
END $fn$;

REVOKE ALL ON FUNCTION guard_ca_issuer_certificate() FROM PUBLIC;
REVOKE ALL ON FUNCTION register_ca_issuer(uuid,bytea,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION record_crl_intent(uuid,bigint,text,bytea,bytea,bigint,bigint,bigint,bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION store_reconciled_crl(uuid,bigint,text,bytea,bytea,bytea,text,bytea) FROM PUBLIC;

COMMIT;
