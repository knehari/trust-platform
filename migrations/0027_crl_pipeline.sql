-- v0.15 (lab): durable CRL numbering, signing intents, immutable entry
-- snapshots and publication-deadline queries. LAB ONLY. No CRL is signed
-- here: the Rust CA core reserves a number, records the intent, signs with the
-- lab signer, verifies the DER independently and only then calls
-- store_verified_crl. Any failure after the intent leaves the row for
-- reconciliation; a number is never reused and a CRL is never re-signed
-- automatically.
-- Apply after 0014 as the migration owner.
BEGIN;

-- crl_publication (0001) is empty in every environment. Numbers are per CA,
-- strictly increasing and below 2^63 - 1 (BIGINT instead of NUMERIC(39,0)).
ALTER TABLE crl_publication DROP CONSTRAINT crl_publication_crl_number_check;
ALTER TABLE crl_publication ALTER COLUMN crl_number TYPE BIGINT;
ALTER TABLE crl_publication ALTER COLUMN crl_sha256 DROP NOT NULL;
ALTER TABLE crl_publication
    ADD COLUMN status TEXT NOT NULL DEFAULT 'RESERVED',
    ADD COLUMN operation_ref TEXT NOT NULL,
    ADD COLUMN actor_id TEXT NOT NULL,
    ADD COLUMN entries_sha256 BYTEA NOT NULL,
    ADD COLUMN tbs_sha256 BYTEA,
    ADD COLUMN crl_der BYTEA,
    ADD COLUMN expired_certs_on_crl_since TIMESTAMPTZ;

ALTER TABLE crl_publication
    ADD CONSTRAINT crl_publication_number_range
        CHECK (crl_number BETWEEN 1 AND 9223372036854775806),
    ADD CONSTRAINT crl_publication_status_valid CHECK (
        status IN ('RESERVED','INTENT_RECORDED','STORED','RECONCILIATION_REQUIRED')
    ),
    ADD CONSTRAINT crl_publication_operation_ref_len
        CHECK (length(operation_ref) BETWEEN 1 AND 256),
    ADD CONSTRAINT crl_publication_actor_len
        CHECK (length(actor_id) BETWEEN 1 AND 1024),
    ADD CONSTRAINT crl_publication_entries_sha256_len
        CHECK (octet_length(entries_sha256) = 32),
    ADD CONSTRAINT crl_publication_tbs_sha256_len
        CHECK (tbs_sha256 IS NULL OR octet_length(tbs_sha256) = 32),
    ADD CONSTRAINT crl_publication_stored_complete CHECK (
        status <> 'STORED'
        OR (crl_der IS NOT NULL AND crl_sha256 IS NOT NULL AND tbs_sha256 IS NOT NULL)
    ),
    ADD CONSTRAINT crl_publication_artifacts_only_stored CHECK (
        status = 'STORED' OR (crl_der IS NULL AND crl_sha256 IS NULL)
    ),
    ADD CONSTRAINT crl_publication_intent_has_tbs CHECK (
        status NOT IN ('INTENT_RECORDED','STORED') OR tbs_sha256 IS NOT NULL
    ),
    ADD CONSTRAINT crl_publication_operation_unique UNIQUE (ca_id, operation_ref);

CREATE TABLE crl_entry_snapshot (
    ca_id UUID NOT NULL,
    crl_number BIGINT NOT NULL,
    serial_der_content BYTEA NOT NULL,
    revoked_at TIMESTAMPTZ NOT NULL,
    reason_code SMALLINT NOT NULL CHECK (reason_code IN (0,1,2,3,4,5,6,9,10)),
    invalidity_at TIMESTAMPTZ,
    PRIMARY KEY (ca_id, crl_number, serial_der_content),
    FOREIGN KEY (ca_id, crl_number) REFERENCES crl_publication (ca_id, crl_number)
);

REVOKE ALL ON crl_entry_snapshot FROM PUBLIC;

-- Publication rows move only RESERVED -> INTENT_RECORDED -> STORED |
-- RECONCILIATION_REQUIRED (and RESERVED -> RECONCILIATION_REQUIRED); STORED
-- and RECONCILIATION_REQUIRED are final, nothing is ever deleted (a deleted
-- row would let a number be reused). Snapshots never change.
CREATE FUNCTION guard_crl_publication() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    IF TG_OP IN ('DELETE','TRUNCATE') THEN
        RAISE EXCEPTION 'crl_publication is append-only' USING ERRCODE='23514';
    END IF;
    IF (OLD.status, NEW.status) NOT IN (
            ('RESERVED','INTENT_RECORDED'),
            ('RESERVED','RECONCILIATION_REQUIRED'),
            ('INTENT_RECORDED','STORED'),
            ('INTENT_RECORDED','RECONCILIATION_REQUIRED'))
       OR (NEW.ca_id, NEW.crl_number, NEW.this_update, NEW.next_update,
           NEW.operation_ref, NEW.actor_id, NEW.entries_sha256,
           NEW.expired_certs_on_crl_since, NEW.published_at)
          IS DISTINCT FROM
          (OLD.ca_id, OLD.crl_number, OLD.this_update, OLD.next_update,
           OLD.operation_ref, OLD.actor_id, OLD.entries_sha256,
           OLD.expired_certs_on_crl_since, OLD.published_at)
       OR (OLD.status <> 'RESERVED'
           AND NEW.tbs_sha256 IS DISTINCT FROM OLD.tbs_sha256)
    THEN
        RAISE EXCEPTION 'illegal crl_publication change % -> %', OLD.status, NEW.status
          USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $fn$;

CREATE FUNCTION guard_crl_entry_snapshot() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    RAISE EXCEPTION 'crl_entry_snapshot is immutable' USING ERRCODE='23514';
END $fn$;

CREATE TRIGGER crl_publication_guard
    BEFORE UPDATE OR DELETE ON crl_publication
    FOR EACH ROW EXECUTE FUNCTION guard_crl_publication();
CREATE TRIGGER crl_publication_no_truncate
    BEFORE TRUNCATE ON crl_publication
    FOR EACH STATEMENT EXECUTE FUNCTION guard_crl_publication();
CREATE TRIGGER crl_entry_snapshot_guard
    BEFORE UPDATE OR DELETE ON crl_entry_snapshot
    FOR EACH ROW EXECUTE FUNCTION guard_crl_entry_snapshot();
CREATE TRIGGER crl_entry_snapshot_no_truncate
    BEFORE TRUNCATE ON crl_entry_snapshot
    FOR EACH STATEMENT EXECUTE FUNCTION guard_crl_entry_snapshot();

-- Canonical encoding of one snapshot entry for entries_sha256. Times are
-- whole epoch seconds (fractions truncated, as in the DER encoding); a missing
-- invalidity date is -1 (0014 keeps invalidity dates >= 1970-01-01, so a real
-- date is never -1). The Rust CA core hashes the entries it signs with exactly
-- this encoding in serial order (trust_pki_core::crl::entries_sha256) and
-- passes the digest to record_crl_intent, which refuses any mismatch.
CREATE FUNCTION crl_entry_encoding(
    p_serial BYTEA, p_revoked_at TIMESTAMPTZ, p_reason SMALLINT,
    p_invalidity_at TIMESTAMPTZ
)
RETURNS BYTEA
LANGUAGE sql IMMUTABLE AS $fn$
    SELECT int4send(octet_length(p_serial)) || p_serial
        || int8send(floor(extract(epoch FROM p_revoked_at))::bigint)
        || int2send(p_reason)
        || int8send(COALESCE(floor(extract(epoch FROM p_invalidity_at))::bigint, -1))
$fn$;

-- Reserve the next CRL number and freeze the revocation set. The CA row lock
-- serialises reservations with each other and with approve_certificate_status_change
-- (which takes the CA row FOR SHARE): the snapshot contains every approval
-- committed before it and none that commits after, and later approvals carry a
-- decided_at after this_update.
CREATE FUNCTION reserve_crl(p_ca UUID, p_actor TEXT, p_operation_ref TEXT)
RETURNS TABLE(crl_number BIGINT, this_update TIMESTAMPTZ, next_update TIMESTAMPTZ,
              expired_certs_on_crl_since TIMESTAMPTZ)
LANGUAGE plpgsql AS $fn$
#variable_conflict use_column
DECLARE
    v_created TIMESTAMPTZ;
    v_target TEXT := 'RFC5280';
    v_validity INTERVAL := INTERVAL '7 days';
    v_number BIGINT;
    v_this TIMESTAMPTZ;
    v_expired TIMESTAMPTZ;
BEGIN
    -- Fail closed: under REPEATABLE READ / SERIALIZABLE the transaction
    -- snapshot predates the CA row lock, so an approval that commits while
    -- this call waits would be missing from the snapshot although its
    -- decided_at precedes this_update.
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'reserve_crl requires transaction isolation read committed (got %)',
            current_setting('transaction_isolation') USING ERRCODE='23514';
    END IF;
    IF p_ca IS NULL
       OR p_actor IS NULL OR length(p_actor) NOT BETWEEN 1 AND 1024
       OR p_operation_ref IS NULL OR length(p_operation_ref) NOT BETWEEN 1 AND 256
    THEN
        RAISE EXCEPTION 'invalid CRL reservation input' USING ERRCODE='22023';
    END IF;
    SELECT c.created_at INTO v_created FROM ca c WHERE c.ca_id = p_ca FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown CA' USING ERRCODE='22023';
    END IF;
    SELECT p.conformance_target, p.crl_validity INTO v_target, v_validity
    FROM ca_revocation_policy p WHERE p.ca_id = p_ca FOR SHARE;
    IF NOT FOUND THEN
        v_target := 'RFC5280';
        v_validity := INTERVAL '7 days';
    END IF;

    SELECT COALESCE(max(cp.crl_number), 0) + 1 INTO v_number
    FROM crl_publication cp WHERE cp.ca_id = p_ca;
    IF v_number > 9223372036854775806 THEN
        RAISE EXCEPTION 'CRL number space exhausted' USING ERRCODE='23514';
    END IF;
    v_this := date_trunc('second', clock_timestamp());
    IF v_target = 'ETSI_EN_319_411_2' THEN v_expired := v_created; END IF;

    -- One statement, one snapshot: the digest and the stored entries come
    -- from the same set of revocation rows.
    WITH cur AS MATERIALIZED (
        SELECT r.serial_der_content, r.revoked_at, r.reason_code, r.invalidity_at
        FROM revocation r WHERE r.ca_id = p_ca
    ), pub AS (
        INSERT INTO crl_publication(
            ca_id, crl_number, this_update, next_update, status, operation_ref,
            actor_id, entries_sha256, expired_certs_on_crl_since)
        SELECT p_ca, v_number, v_this, v_this + v_validity, 'RESERVED',
               p_operation_ref, p_actor,
               sha256(COALESCE((SELECT string_agg(
                   crl_entry_encoding(cur.serial_der_content, cur.revoked_at,
                                      cur.reason_code, cur.invalidity_at),
                   '\x'::bytea ORDER BY cur.serial_der_content) FROM cur), '\x'::bytea)),
               v_expired
        RETURNING 1
    )
    INSERT INTO crl_entry_snapshot(ca_id, crl_number, serial_der_content,
                                   revoked_at, reason_code, invalidity_at)
    SELECT p_ca, v_number, cur.serial_der_content, cur.revoked_at,
           cur.reason_code, cur.invalidity_at
    FROM cur;

    INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), p_ca, NULL, p_actor, 'crl.reserved',
            'RESERVED:' || v_number);
    RETURN QUERY SELECT v_number, v_this, v_this + v_validity, v_expired;
END $fn$;

CREATE FUNCTION crl_snapshot_entries(p_ca UUID, p_crl_number BIGINT)
RETURNS TABLE(serial_der_content BYTEA, revoked_at TIMESTAMPTZ,
              reason_code SMALLINT, invalidity_at TIMESTAMPTZ)
LANGUAGE plpgsql AS $fn$
#variable_conflict use_column
BEGIN
    IF p_ca IS NULL OR p_crl_number IS NULL OR NOT EXISTS (
        SELECT 1 FROM crl_publication cp
        WHERE cp.ca_id = p_ca AND cp.crl_number = p_crl_number
    ) THEN
        RAISE EXCEPTION 'unknown CRL number' USING ERRCODE='22023';
    END IF;
    RETURN QUERY
        SELECT s.serial_der_content, s.revoked_at, s.reason_code, s.invalidity_at
        FROM crl_entry_snapshot s
        WHERE s.ca_id = p_ca AND s.crl_number = p_crl_number
        ORDER BY s.serial_der_content;
END $fn$;

-- The signing intent is durable before any signature is produced. The caller
-- states what it is about to sign: the digest of the entries (computed in Rust
-- from the reservation, crl_entry_encoding layout, serial order), and the
-- thisUpdate / nextUpdate / ExpiredCertsOnCRL times in whole epoch seconds.
-- Any difference from the reservation is refused before signing, so a STORED
-- row (which crl_change_covered trusts) always signed exactly its snapshot.
-- The TBS bytes themselves are bound to these values by the Rust CA core's
-- independent verifier, which rebuilds the expected TBS from the same
-- reservation; SQL cannot parse the DER.
CREATE FUNCTION record_crl_intent(
    p_ca UUID, p_crl_number BIGINT, p_operation_ref TEXT, p_tbs_sha256 BYTEA,
    p_entries_sha256 BYTEA, p_this_update_unix BIGINT, p_next_update_unix BIGINT,
    p_expired_certs_on_crl_since_unix BIGINT
)
RETURNS TEXT
LANGUAGE plpgsql AS $fn$
DECLARE
    v_pub crl_publication%ROWTYPE;
BEGIN
    IF p_ca IS NULL OR p_crl_number IS NULL
       OR p_operation_ref IS NULL OR length(p_operation_ref) NOT BETWEEN 1 AND 256
       OR p_tbs_sha256 IS NULL OR octet_length(p_tbs_sha256) <> 32
       OR p_entries_sha256 IS NULL OR octet_length(p_entries_sha256) <> 32
       OR p_this_update_unix IS NULL OR p_next_update_unix IS NULL
    THEN
        RAISE EXCEPTION 'invalid CRL intent input' USING ERRCODE='22023';
    END IF;
    SELECT * INTO v_pub FROM crl_publication cp
    WHERE cp.ca_id = p_ca AND cp.crl_number = p_crl_number FOR UPDATE;
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
    UPDATE crl_publication
    SET status = 'INTENT_RECORDED', tbs_sha256 = p_tbs_sha256
    WHERE ca_id = p_ca AND crl_number = p_crl_number;
    INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), p_ca, NULL, v_pub.actor_id, 'crl.intent',
            'INTENT_RECORDED:' || p_crl_number);
    RETURN 'INTENT_RECORDED';
END $fn$;

-- Any failure after (or, for a crash before the intent, around) signing.
CREATE FUNCTION mark_crl_uncertain(
    p_ca UUID, p_crl_number BIGINT, p_operation_ref TEXT
)
RETURNS TEXT
LANGUAGE plpgsql AS $fn$
DECLARE
    v_pub crl_publication%ROWTYPE;
BEGIN
    IF p_ca IS NULL OR p_crl_number IS NULL
       OR p_operation_ref IS NULL OR length(p_operation_ref) NOT BETWEEN 1 AND 256
    THEN
        RAISE EXCEPTION 'invalid CRL uncertain input' USING ERRCODE='22023';
    END IF;
    SELECT * INTO v_pub FROM crl_publication cp
    WHERE cp.ca_id = p_ca AND cp.crl_number = p_crl_number FOR UPDATE;
    IF NOT FOUND OR v_pub.status NOT IN ('RESERVED','INTENT_RECORDED')
       OR v_pub.operation_ref <> p_operation_ref
    THEN
        RAISE EXCEPTION 'CRL uncertain refused: unknown number, wrong operation or final state'
          USING ERRCODE='23514';
    END IF;
    UPDATE crl_publication
    SET status = 'RECONCILIATION_REQUIRED'
    WHERE ca_id = p_ca AND crl_number = p_crl_number;
    INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), p_ca, NULL, v_pub.actor_id, 'crl.uncertain',
            'RECONCILIATION_REQUIRED:' || p_crl_number);
    RETURN 'RECONCILIATION_REQUIRED';
END $fn$;

-- Persist a CRL only after the caller verified the signature independently.
-- The database re-derives what it can: state, operation, TBS hash (bound at
-- the intent, together with the caller's entries digest, number and times),
-- entries digest from the frozen snapshot and the DER hash.
CREATE FUNCTION store_verified_crl(
    p_ca UUID, p_crl_number BIGINT, p_operation_ref TEXT, p_tbs_sha256 BYTEA,
    p_crl_sha256 BYTEA, p_crl_der BYTEA
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
    THEN
        RAISE EXCEPTION 'invalid CRL store input' USING ERRCODE='22023';
    END IF;
    SELECT * INTO v_pub FROM crl_publication cp
    WHERE cp.ca_id = p_ca AND cp.crl_number = p_crl_number FOR UPDATE;
    IF NOT FOUND OR v_pub.status <> 'INTENT_RECORDED'
       OR v_pub.operation_ref <> p_operation_ref
       OR v_pub.tbs_sha256 IS DISTINCT FROM p_tbs_sha256
    THEN
        RAISE EXCEPTION 'CRL store refused: unknown number, wrong state, operation or TBS hash'
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
        RAISE EXCEPTION 'CRL store refused: snapshot does not match the reserved digest'
          USING ERRCODE='23514';
    END IF;
    UPDATE crl_publication
    SET status = 'STORED', crl_sha256 = p_crl_sha256, crl_der = p_crl_der
    WHERE ca_id = p_ca AND crl_number = p_crl_number;
    INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), p_ca, NULL, v_pub.actor_id, 'crl.stored',
            'STORED:' || p_crl_number);
    RETURN 'STORED';
END $fn$;

-- Quarantine intents whose signing never completed. Age is measured from the
-- reservation (this_update), which precedes the intent by milliseconds.
CREATE FUNCTION quarantine_stale_crl_intents(p_ca UUID, p_older_than INTERVAL)
RETURNS INTEGER
LANGUAGE plpgsql AS $fn$
DECLARE
    v_count INTEGER := 0;
    v_row RECORD;
BEGIN
    IF p_ca IS NULL OR p_older_than IS NULL OR p_older_than < INTERVAL '0 seconds' THEN
        RAISE EXCEPTION 'invalid CRL quarantine input' USING ERRCODE='22023';
    END IF;
    FOR v_row IN
        SELECT cp.crl_number, cp.actor_id FROM crl_publication cp
        WHERE cp.ca_id = p_ca AND cp.status = 'INTENT_RECORDED'
          AND cp.this_update <= clock_timestamp() - p_older_than
        ORDER BY cp.crl_number FOR UPDATE
    LOOP
        UPDATE crl_publication
        SET status = 'RECONCILIATION_REQUIRED'
        WHERE ca_id = p_ca AND crl_number = v_row.crl_number;
        INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
        VALUES (gen_random_uuid(), p_ca, NULL, v_row.actor_id, 'crl.quarantined',
                'RECONCILIATION_REQUIRED:' || v_row.crl_number);
        v_count := v_count + 1;
    END LOOP;
    RETURN v_count;
END $fn$;

-- Does a STORED CRL actually reflect this approved change? The CRL must have
-- this_update >= decided_at and its snapshot must show the outcome: SUSPEND /
-- REVOKE -> the serial is listed with the approved reason; RELEASE -> the
-- serial is not listed. A change superseded by a later approved change for the
-- same certificate is not tracked (the later one is). p_latest_only restricts
-- the test to the newest STORED CRL of the CA.
CREATE FUNCTION crl_change_covered(p_change UUID, p_latest_only BOOLEAN)
RETURNS BOOLEAN
LANGUAGE sql STABLE AS $fn$
    SELECT EXISTS (
        SELECT 1
        FROM certificate_status_change s
        JOIN crl_publication cp
          ON cp.ca_id = s.ca_id AND cp.status = 'STORED'
         AND cp.this_update >= s.decided_at
        WHERE s.change_id = p_change AND s.status = 'APPROVED'
          AND (NOT p_latest_only OR cp.crl_number = (
                SELECT max(x.crl_number) FROM crl_publication x
                WHERE x.ca_id = s.ca_id AND x.status = 'STORED'))
          AND CASE WHEN s.action = 'RELEASE'
                   THEN NOT EXISTS (
                        SELECT 1 FROM crl_entry_snapshot e
                        WHERE e.ca_id = cp.ca_id AND e.crl_number = cp.crl_number
                          AND e.serial_der_content = s.serial_der_content)
                   ELSE EXISTS (
                        SELECT 1 FROM crl_entry_snapshot e
                        WHERE e.ca_id = cp.ca_id AND e.crl_number = cp.crl_number
                          AND e.serial_der_content = s.serial_der_content
                          AND e.reason_code = s.reason_code)
              END
    )
$fn$;

-- True when a new CRL should be issued: none stored yet, the latest stored one
-- is older than crl_issue_interval, or the latest approved change of some
-- certificate is not reflected by the latest stored CRL.
CREATE FUNCTION crl_due(p_ca UUID)
RETURNS BOOLEAN
LANGUAGE plpgsql AS $fn$
DECLARE
    v_interval INTERVAL := INTERVAL '24 hours';
    v_last TIMESTAMPTZ;
BEGIN
    IF p_ca IS NULL OR NOT EXISTS (SELECT 1 FROM ca WHERE ca_id = p_ca) THEN
        RAISE EXCEPTION 'unknown CA' USING ERRCODE='22023';
    END IF;
    SELECT p.crl_issue_interval INTO v_interval
    FROM ca_revocation_policy p WHERE p.ca_id = p_ca;
    IF NOT FOUND THEN v_interval := INTERVAL '24 hours'; END IF;

    SELECT max(cp.this_update) INTO v_last FROM crl_publication cp
    WHERE cp.ca_id = p_ca AND cp.status = 'STORED';
    IF v_last IS NULL OR v_last < clock_timestamp() - v_interval THEN
        RETURN true;
    END IF;
    RETURN EXISTS (
        SELECT 1 FROM certificate_status_change s
        WHERE s.ca_id = p_ca AND s.status = 'APPROVED'
          AND NOT EXISTS (
              SELECT 1 FROM certificate_status_change l
              WHERE l.ca_id = s.ca_id AND l.serial_der_content = s.serial_der_content
                AND l.status = 'APPROVED' AND l.decided_at > s.decided_at)
          AND NOT crl_change_covered(s.change_id, true)
    );
END $fn$;

-- Status changes past status_publication_deadline (counted from the proposal)
-- that are still PROPOSED, or APPROVED but not yet published: the newest
-- approved change of a certificate must be reflected by a STORED CRL; an older
-- (superseded) one counts as published once any STORED CRL postdates its
-- decision.
CREATE FUNCTION overdue_status_changes(p_ca UUID)
RETURNS TABLE(change_id UUID, status TEXT, proposed_at TIMESTAMPTZ)
LANGUAGE plpgsql AS $fn$
#variable_conflict use_column
DECLARE
    v_deadline INTERVAL := INTERVAL '24 hours';
BEGIN
    IF p_ca IS NULL OR NOT EXISTS (SELECT 1 FROM ca WHERE ca_id = p_ca) THEN
        RAISE EXCEPTION 'unknown CA' USING ERRCODE='22023';
    END IF;
    SELECT p.status_publication_deadline INTO v_deadline
    FROM ca_revocation_policy p WHERE p.ca_id = p_ca;
    IF NOT FOUND THEN v_deadline := INTERVAL '24 hours'; END IF;

    RETURN QUERY
        SELECT s.change_id, s.status, s.proposed_at
        FROM certificate_status_change s
        WHERE s.ca_id = p_ca
          AND s.proposed_at + v_deadline < clock_timestamp()
          AND (s.status = 'PROPOSED'
               OR (s.status = 'APPROVED' AND NOT (
                   CASE WHEN EXISTS (
                            SELECT 1 FROM certificate_status_change l
                            WHERE l.ca_id = s.ca_id
                              AND l.serial_der_content = s.serial_der_content
                              AND l.status = 'APPROVED' AND l.decided_at > s.decided_at)
                        -- superseded: covered once any STORED CRL is at least
                        -- as new as its decision (a CRL reflecting the
                        -- superseding change is necessarily newer)
                        THEN EXISTS (
                            SELECT 1 FROM crl_publication cp
                            WHERE cp.ca_id = s.ca_id AND cp.status = 'STORED'
                              AND cp.this_update >= s.decided_at)
                        -- newest change: the snapshot must reflect it
                        ELSE crl_change_covered(s.change_id, false)
                   END)))
        ORDER BY s.proposed_at, s.change_id;
END $fn$;

REVOKE ALL ON FUNCTION guard_crl_publication() FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_crl_entry_snapshot() FROM PUBLIC;
REVOKE ALL ON FUNCTION crl_entry_encoding(bytea,timestamptz,smallint,timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION reserve_crl(uuid,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION crl_snapshot_entries(uuid,bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION record_crl_intent(uuid,bigint,text,bytea,bytea,bigint,bigint,bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION mark_crl_uncertain(uuid,bigint,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION store_verified_crl(uuid,bigint,text,bytea,bytea,bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION quarantine_stale_crl_intents(uuid,interval) FROM PUBLIC;
REVOKE ALL ON FUNCTION crl_change_covered(uuid,boolean) FROM PUBLIC;
REVOKE ALL ON FUNCTION crl_due(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION overdue_status_changes(uuid) FROM PUBLIC;

COMMIT;
