-- v0.59 (lab): delta CRLs (RFC 5280 5.2.4, 5.2.6). LAB ONLY.
-- Complete CRLs only, until now. A delta CRL lists what changed since a
-- base complete CRL: revocations and holds added, and entries removed
-- (released holds, pruned expired entries) with reason removeFromCRL
-- (5.3.1). Complete and delta CRLs share one numbering sequence (5.2.3).
-- * ca_revocation_policy.delta_crl_url: where the CA's delta CRLs are
--   published (plain http://, the CDP rules); NULL, the default, disables
--   deltas. Set by the owner, like the rest of the lab policy.
-- * crl_publication.base_crl_number (NULL for a complete CRL; below the
--   CRL number for a delta) and freshest_crl_url: a BEFORE INSERT trigger
--   copies the policy URL onto every complete CRL, which the Rust core then
--   signs as freshestCRL (5.2.6; OpenSSL applies a delta only to a base
--   that advertises it). Both are immutable (guard_crl_publication).
-- * crl_delta_release: the removeFromCRL entries of a delta, append-only.
-- * reserve_delta_crl(ca, actor, operation): under the CA row lock, like
--   reserve_crl. The base is the latest stored complete CRL, which must
--   advertise deltas; the delta's entries are the current CRL entries (as
--   reserve_crl computes them, pruning included) that are not in the base
--   snapshot, its releases the base entries no longer current, dated at
--   the delta's thisUpdate. nextUpdate is at most the base's. Same number
--   floor (0058), clock and isolation checks as reserve_crl. The entries
--   digest covers entries and releases (reason 8) in serial order, as the
--   Rust core computes it. The intent, signing, verification and quarantine
--   functions are the complete CRL's, unchanged; storage and
--   reconciliation re-check the digest with crl_listed_digest, which adds
--   a delta's releases to the snapshot entries.
-- * crl_delta_releases(ca, number) for the signer; published_delta_crl(ca)
--   (latest stored delta) for the distribution point.
-- * Complete CRLs only, so a delta is never taken for one: published_crl,
--   crl_due, crl_change_covered (publication deadlines), the expiry
--   pruning rule (crl_entry_pruned_from) and the omission check
--   (crl_pruned_entries, empty for a delta).
-- Apply after 0058 as a superuser.
BEGIN;

ALTER TABLE ca_revocation_policy ADD COLUMN delta_crl_url TEXT
    CONSTRAINT ca_revocation_policy_delta_crl_url_check CHECK (
        delta_crl_url IS NULL
        OR (length(delta_crl_url) <= 2048
            AND delta_crl_url ~ '^http://[^/?][!-~]*$'
            AND delta_crl_url !~ '[@#\\]'));

ALTER TABLE crl_publication
    ADD COLUMN base_crl_number BIGINT,
    ADD COLUMN freshest_crl_url TEXT,
    ADD CONSTRAINT crl_publication_delta_base CHECK (
        base_crl_number IS NULL OR (base_crl_number >= 1 AND base_crl_number < crl_number)),
    ADD CONSTRAINT crl_publication_freshest_on_complete_only CHECK (
        base_crl_number IS NULL OR freshest_crl_url IS NULL),
    ADD CONSTRAINT crl_publication_delta_no_expired_certs CHECK (
        base_crl_number IS NULL OR expired_certs_on_crl_since IS NULL);

CREATE FUNCTION crl_publication_freshest() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    IF NEW.base_crl_number IS NULL THEN
        NEW.freshest_crl_url := (SELECT p.delta_crl_url FROM public.ca_revocation_policy p
                                 WHERE p.ca_id = NEW.ca_id);
    ELSE
        NEW.freshest_crl_url := NULL;
    END IF;
    RETURN NEW;
END $fn$;
ALTER FUNCTION crl_publication_freshest() OWNER TO trust_revocation_owner;
ALTER FUNCTION crl_publication_freshest() SET search_path = pg_catalog, public, pg_temp;
REVOKE ALL ON FUNCTION crl_publication_freshest() FROM PUBLIC;
CREATE TRIGGER crl_publication_0_freshest
    BEFORE INSERT ON crl_publication
    FOR EACH ROW EXECUTE FUNCTION crl_publication_freshest();

CREATE TABLE crl_delta_release (
    ca_id UUID NOT NULL,
    crl_number BIGINT NOT NULL,
    serial_der_content BYTEA NOT NULL CHECK (octet_length(serial_der_content) BETWEEN 1 AND 20),
    released_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (ca_id, crl_number, serial_der_content),
    FOREIGN KEY (ca_id, crl_number) REFERENCES crl_publication (ca_id, crl_number)
);
ALTER TABLE crl_delta_release OWNER TO trust_revocation_owner;
REVOKE ALL ON crl_delta_release FROM PUBLIC;

CREATE FUNCTION guard_crl_delta_release() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    RAISE EXCEPTION 'crl_delta_release is append-only' USING ERRCODE = '23514';
END $fn$;
ALTER FUNCTION guard_crl_delta_release() OWNER TO trust_revocation_owner;
ALTER FUNCTION guard_crl_delta_release() SET search_path = pg_catalog, public, pg_temp;
REVOKE ALL ON FUNCTION guard_crl_delta_release() FROM PUBLIC;
CREATE TRIGGER crl_delta_release_append_only
    BEFORE UPDATE OR DELETE ON crl_delta_release
    FOR EACH ROW EXECUTE FUNCTION guard_crl_delta_release();
CREATE TRIGGER crl_delta_release_no_truncate
    BEFORE TRUNCATE ON crl_delta_release
    FOR EACH STATEMENT EXECUTE FUNCTION guard_crl_delta_release();

CREATE FUNCTION reserve_delta_crl(p_ca UUID, p_actor TEXT, p_operation_ref TEXT)
RETURNS TABLE(crl_number BIGINT, base_crl_number BIGINT, this_update TIMESTAMPTZ,
              next_update TIMESTAMPTZ)
LANGUAGE plpgsql AS $fn$
#variable_conflict use_column
DECLARE
    v_validity INTERVAL := INTERVAL '7 days';
    v_url TEXT;
    v_base BIGINT;
    v_base_next TIMESTAMPTZ;
    v_base_url TEXT;
    v_number BIGINT;
    v_reserved TIMESTAMPTZ;
    v_this TIMESTAMPTZ;
    v_next TIMESTAMPTZ;
    v_latest TIMESTAMPTZ;
BEGIN
    -- As reserve_crl: the snapshot must not predate the CA row lock.
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'reserve_delta_crl requires transaction isolation read committed (got %)',
            current_setting('transaction_isolation') USING ERRCODE='23514';
    END IF;
    IF p_ca IS NULL
       OR p_actor IS NULL OR length(p_actor) NOT BETWEEN 1 AND 1024
       OR p_operation_ref IS NULL OR length(p_operation_ref) NOT BETWEEN 1 AND 256
    THEN
        RAISE EXCEPTION 'invalid CRL reservation input' USING ERRCODE='22023';
    END IF;
    PERFORM 1 FROM ca c WHERE c.ca_id = p_ca FOR NO KEY UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown CA' USING ERRCODE='22023';
    END IF;
    SELECT p.crl_validity, p.delta_crl_url INTO v_validity, v_url
    FROM ca_revocation_policy p WHERE p.ca_id = p_ca FOR SHARE;
    IF v_url IS NULL THEN
        RAISE EXCEPTION 'delta CRLs are not enabled for this CA' USING ERRCODE='55000';
    END IF;
    SELECT cp.crl_number, cp.next_update, cp.freshest_crl_url
    INTO v_base, v_base_next, v_base_url
    FROM crl_publication cp
    WHERE cp.ca_id = p_ca AND cp.status = 'STORED' AND cp.base_crl_number IS NULL
    ORDER BY cp.crl_number DESC LIMIT 1;
    IF v_base IS NULL OR v_base_url IS NULL THEN
        RAISE EXCEPTION 'no stored complete CRL advertising delta CRLs; issue one first'
          USING ERRCODE='55000';
    END IF;
    SELECT GREATEST(COALESCE(max(cp.crl_number), 0),
                    COALESCE((SELECT max(f.floor) FROM crl_number_floor f
                              WHERE f.ca_id = p_ca), 0)) + 1 INTO v_number
    FROM crl_publication cp WHERE cp.ca_id = p_ca;
    IF v_number > 9223372036854775806 THEN
        RAISE EXCEPTION 'CRL number space exhausted' USING ERRCODE='23514';
    END IF;
    v_reserved := clock_timestamp();
    v_this := date_trunc('second', v_reserved);
    SELECT max(cp.this_update) INTO v_latest FROM crl_publication cp WHERE cp.ca_id = p_ca;
    IF v_latest > v_this THEN
        RAISE EXCEPTION 'clock is behind the latest CRL thisUpdate of this CA'
          USING ERRCODE='23514';
    END IF;
    -- A delta is only usable with its base: never valid beyond it.
    v_next := LEAST(v_this + v_validity, v_base_next);
    IF v_next <= v_this THEN
        RAISE EXCEPTION 'the base CRL has expired; issue a complete CRL' USING ERRCODE='55000';
    END IF;

    WITH cur AS MATERIALIZED (
        SELECT r.serial_der_content, r.revoked_at, r.reason_code, r.invalidity_at
        FROM revocation r WHERE r.ca_id = p_ca
          AND NOT crl_entry_pruned_from(p_ca, r.serial_der_content, v_number)
    ), base AS MATERIALIZED (
        SELECT e.serial_der_content, e.revoked_at, e.reason_code, e.invalidity_at
        FROM crl_entry_snapshot e WHERE e.ca_id = p_ca AND e.crl_number = v_base
    ), added AS MATERIALIZED (
        SELECT * FROM cur EXCEPT SELECT * FROM base
    ), released AS MATERIALIZED (
        SELECT b.serial_der_content FROM base b
        WHERE NOT EXISTS (SELECT 1 FROM cur c WHERE c.serial_der_content = b.serial_der_content)
    ), listed AS (
        SELECT a.serial_der_content,
               crl_entry_encoding(a.serial_der_content, a.revoked_at, a.reason_code,
                                  a.invalidity_at) AS encoded
        FROM added a
        UNION ALL
        SELECT r.serial_der_content,
               crl_entry_encoding(r.serial_der_content, v_this, 8::smallint, NULL)
        FROM released r
    ), pub AS (
        INSERT INTO crl_publication(
            ca_id, crl_number, this_update, next_update, status, operation_ref,
            actor_id, entries_sha256, expired_certs_on_crl_since, reserved_at, base_crl_number)
        SELECT p_ca, v_number, v_this, v_next, 'RESERVED', p_operation_ref, p_actor,
               sha256(COALESCE((SELECT string_agg(l.encoded, '\x'::bytea
                                                  ORDER BY l.serial_der_content)
                                FROM listed l), '\x'::bytea)),
               NULL, v_reserved, v_base
        RETURNING 1
    ), snapshot AS (
        INSERT INTO crl_entry_snapshot(ca_id, crl_number, serial_der_content,
                                       revoked_at, reason_code, invalidity_at)
        SELECT p_ca, v_number, a.serial_der_content, a.revoked_at, a.reason_code,
               a.invalidity_at
        FROM added a
        RETURNING 1
    )
    INSERT INTO crl_delta_release(ca_id, crl_number, serial_der_content, released_at)
    SELECT p_ca, v_number, r.serial_der_content, v_this FROM released r;

    INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), p_ca, NULL, p_actor, 'crl.delta_reserved',
            'RESERVED:' || v_number || ':base=' || v_base);
    RETURN QUERY SELECT v_number, v_base, v_this, v_next;
END $fn$;
ALTER FUNCTION reserve_delta_crl(uuid, text, text) OWNER TO trust_revocation_owner;
ALTER FUNCTION reserve_delta_crl(uuid, text, text) SECURITY DEFINER;
ALTER FUNCTION reserve_delta_crl(uuid, text, text) SET search_path = pg_catalog, public, pg_temp;
REVOKE ALL ON FUNCTION reserve_delta_crl(uuid, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION reserve_delta_crl(uuid, text, text) TO trust_crl_signer;

CREATE FUNCTION crl_delta_releases(p_ca UUID, p_crl_number BIGINT)
RETURNS TABLE(serial_der_content BYTEA, released_at TIMESTAMPTZ)
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
        SELECT d.serial_der_content, d.released_at
        FROM crl_delta_release d
        WHERE d.ca_id = p_ca AND d.crl_number = p_crl_number
        ORDER BY d.serial_der_content;
END $fn$;
ALTER FUNCTION crl_delta_releases(uuid, bigint) OWNER TO trust_revocation_owner;
ALTER FUNCTION crl_delta_releases(uuid, bigint) SECURITY DEFINER;
ALTER FUNCTION crl_delta_releases(uuid, bigint) SET search_path = pg_catalog, public, pg_temp;
REVOKE ALL ON FUNCTION crl_delta_releases(uuid, bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION crl_delta_releases(uuid, bigint) TO trust_crl_signer;

CREATE FUNCTION published_delta_crl(p_ca UUID)
RETURNS TABLE(crl_number BIGINT, this_update_unix BIGINT, next_update_unix BIGINT,
              crl_der BYTEA, issuer_certificate_der BYTEA)
LANGUAGE sql STABLE AS $fn$
    SELECT p.crl_number, extract(epoch FROM p.this_update)::bigint,
           extract(epoch FROM p.next_update)::bigint, p.crl_der, i.certificate_der
    FROM crl_publication p
    JOIN ca_issuer_certificate i ON i.ca_id = p.ca_id
    WHERE p.ca_id = p_ca AND p.status = 'STORED' AND p.base_crl_number IS NOT NULL
    ORDER BY p.crl_number DESC
    LIMIT 1
$fn$;
ALTER FUNCTION published_delta_crl(uuid) OWNER TO trust_revocation_owner;
ALTER FUNCTION published_delta_crl(uuid) SECURITY DEFINER;
ALTER FUNCTION published_delta_crl(uuid) SET search_path = pg_catalog, public, pg_temp;
REVOKE ALL ON FUNCTION published_delta_crl(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION published_delta_crl(uuid) TO trust_crl_publisher;

-- Complete CRLs only from here on (bodies as of 0058, one condition added).
CREATE OR REPLACE FUNCTION public.published_crl(p_ca uuid)
 RETURNS TABLE(crl_number bigint, this_update_unix bigint, next_update_unix bigint, crl_der bytea, issuer_certificate_der bytea)
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
    SELECT p.crl_number, extract(epoch FROM p.this_update)::bigint,
           extract(epoch FROM p.next_update)::bigint, p.crl_der, i.certificate_der
    FROM crl_publication p
    JOIN ca_issuer_certificate i ON i.ca_id = p.ca_id
    WHERE p.ca_id = p_ca AND p.status = 'STORED' AND p.base_crl_number IS NULL
    ORDER BY p.crl_number DESC
    LIMIT 1
$function$;

CREATE OR REPLACE FUNCTION public.crl_due(p_ca uuid)
 RETURNS boolean
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
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
    WHERE cp.ca_id = p_ca AND cp.status = 'STORED' AND cp.base_crl_number IS NULL;
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
END $function$;

CREATE OR REPLACE FUNCTION public.crl_change_covered(p_change uuid, p_latest_only boolean)
 RETURNS boolean
 LANGUAGE sql
 STABLE
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
    SELECT EXISTS (
        SELECT 1
        FROM certificate_status_change s
        JOIN crl_publication cp
          ON cp.ca_id = s.ca_id AND cp.status = 'STORED' AND cp.base_crl_number IS NULL
         AND COALESCE(cp.reserved_at, cp.this_update) >= s.decided_at
        WHERE s.change_id = p_change AND s.status = 'APPROVED'
          AND (NOT p_latest_only OR cp.crl_number = (
                SELECT max(x.crl_number) FROM crl_publication x
                WHERE x.ca_id = s.ca_id AND x.status = 'STORED'
                  AND x.base_crl_number IS NULL))
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
                        -- 0031: legitimately pruned after expiry.
                        OR crl_entry_pruned_from(cp.ca_id, s.serial_der_content, cp.crl_number)
              END
    )
$function$;

CREATE OR REPLACE FUNCTION public.crl_entry_pruned_from(p_ca uuid, p_serial bytea, p_crl_number bigint)
 RETURNS boolean
 LANGUAGE sql
 STABLE
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
    SELECT EXISTS (
        SELECT 1
        FROM certificate c
        JOIN ca_revocation_policy pol ON pol.ca_id = c.ca_id AND NOT pol.keep_expired_on_crl
        JOIN crl_publication q ON q.ca_id = c.ca_id AND q.status = 'STORED'
             AND q.base_crl_number IS NULL
             AND q.crl_number < p_crl_number AND q.this_update > c.not_after
        JOIN crl_entry_snapshot e ON e.ca_id = q.ca_id AND e.crl_number = q.crl_number
             AND e.serial_der_content = c.serial_der_content
        WHERE c.ca_id = p_ca AND c.serial_der_content = p_serial
          AND c.not_after IS NOT NULL)
$function$;

CREATE OR REPLACE FUNCTION public.crl_pruned_entries(p_ca uuid, p_crl_number bigint)
 RETURNS TABLE(serial_der_content bytea, not_after_unix bigint, certificate_der bytea)
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
    SELECT r.serial_der_content, floor(extract(epoch FROM c.not_after))::bigint,
           c.certificate_der
    FROM crl_publication p
    JOIN revocation r ON r.ca_id = p.ca_id
    LEFT JOIN certificate_status_change s ON s.change_id = r.change_id
    LEFT JOIN certificate c ON c.ca_id = r.ca_id AND c.serial_der_content = r.serial_der_content
    WHERE p.ca_id = p_ca AND p.crl_number = p_crl_number AND p.base_crl_number IS NULL
      AND (s.decided_at IS NULL OR s.decided_at <= coalesce(p.reserved_at, p.this_update))
      AND NOT EXISTS (SELECT 1 FROM crl_entry_snapshot e
                      WHERE e.ca_id = p.ca_id AND e.crl_number = p.crl_number
                        AND e.serial_der_content = r.serial_der_content)
    ORDER BY r.serial_der_content
$function$;

CREATE OR REPLACE FUNCTION public.guard_crl_publication()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
BEGIN
    IF TG_OP IN ('DELETE','TRUNCATE') THEN
        RAISE EXCEPTION 'crl_publication is append-only' USING ERRCODE='23514';
    END IF;
    IF (OLD.status, NEW.status) NOT IN (
            ('RESERVED','INTENT_RECORDED'),
            ('RESERVED','RECONCILIATION_REQUIRED'),
            ('RESERVED','ABANDONED'),
            ('INTENT_RECORDED','STORED'),
            ('INTENT_RECORDED','RECONCILIATION_REQUIRED'),
            ('RECONCILIATION_REQUIRED','STORED'))
       OR (NEW.ca_id, NEW.crl_number, NEW.this_update, NEW.next_update,
           NEW.operation_ref, NEW.actor_id, NEW.entries_sha256,
           NEW.expired_certs_on_crl_since, NEW.published_at, NEW.reserved_at,
           NEW.base_crl_number, NEW.freshest_crl_url)
          IS DISTINCT FROM
          (OLD.ca_id, OLD.crl_number, OLD.this_update, OLD.next_update,
           OLD.operation_ref, OLD.actor_id, OLD.entries_sha256,
           OLD.expired_certs_on_crl_since, OLD.published_at, OLD.reserved_at,
           OLD.base_crl_number, OLD.freshest_crl_url)
       OR (OLD.status <> 'RESERVED'
           AND NEW.tbs_sha256 IS DISTINCT FROM OLD.tbs_sha256)
       -- only a quarantined row that recorded an intent can be reconciled
       OR (OLD.status = 'RECONCILIATION_REQUIRED' AND OLD.tbs_sha256 IS NULL)
       OR (NEW.intent_recorded_at IS DISTINCT FROM OLD.intent_recorded_at
           AND (OLD.status, NEW.status) <> ('RESERVED','INTENT_RECORDED'))
       OR (OLD.status = 'RESERVED' AND NEW.status = 'INTENT_RECORDED'
           AND NEW.intent_recorded_at IS NULL)
    THEN
        RAISE EXCEPTION 'illegal crl_publication change % -> %', OLD.status, NEW.status
          USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $function$;

-- Storage and reconciliation re-check the listed digest, releases included.
-- What the stored CRL must list, as the Rust core digests it: the snapshot
-- entries and a delta's releases (reason 8, at their release time), in
-- serial order. For a complete CRL this is the 0015 digest.
CREATE FUNCTION crl_listed_digest(p_ca UUID, p_crl_number BIGINT)
RETURNS BYTEA
LANGUAGE sql STABLE AS $fn$
    SELECT sha256(COALESCE(string_agg(x.encoded, '\x'::bytea ORDER BY x.serial), '\x'::bytea))
    FROM (SELECT s.serial_der_content AS serial,
                 crl_entry_encoding(s.serial_der_content, s.revoked_at, s.reason_code,
                                    s.invalidity_at) AS encoded
          FROM crl_entry_snapshot s
          WHERE s.ca_id = p_ca AND s.crl_number = p_crl_number
          UNION ALL
          SELECT d.serial_der_content,
                 crl_entry_encoding(d.serial_der_content, d.released_at, 8::smallint, NULL)
          FROM crl_delta_release d
          WHERE d.ca_id = p_ca AND d.crl_number = p_crl_number) x
$fn$;
ALTER FUNCTION crl_listed_digest(uuid, bigint) OWNER TO trust_revocation_owner;
ALTER FUNCTION crl_listed_digest(uuid, bigint) SET search_path = pg_catalog, public, pg_temp;
REVOKE ALL ON FUNCTION crl_listed_digest(uuid, bigint) FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.store_verified_crl(p_ca uuid, p_crl_number bigint, p_operation_ref text, p_tbs_sha256 bytea, p_crl_sha256 bytea, p_crl_der bytea)
 RETURNS text
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
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
    -- 0059: entries and, for a delta CRL, its releases.
    v_digest := crl_listed_digest(p_ca, p_crl_number);
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
END $function$;

CREATE OR REPLACE FUNCTION public.store_reconciled_crl(p_ca uuid, p_crl_number bigint, p_operation_ref text, p_tbs_sha256 bytea, p_crl_sha256 bytea, p_crl_der bytea, p_actor text, p_issuer_sha256 bytea DEFAULT NULL::bytea)
 RETURNS text
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
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
    -- 0059: entries and, for a delta CRL, its releases.
    v_digest := crl_listed_digest(p_ca, p_crl_number);
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
END $function$;

SELECT acknowledge_schema_changes('0059_delta_crl');

COMMIT;
