-- Migration 0035: automatic CRL renewal in the laboratory (ADR-0021,
-- Proposed). Until now a CRL was renewed only when a registration officer
-- published; nothing published before nextUpdate (seven days).
--
-- A new per-CA role, crl-publisher, held by the API's renewal task under a
-- system principal the database owner grants, may run the CRL publication
-- functions of migration 0031, and only for a CRL that is due: none was
-- published yet, or the latest published one reaches nextUpdate within two
-- days (the same rule as management_crl_status). It cannot revoke, decide,
-- issue or read anything else. The publication path is unchanged: journaled
-- intent, separate signer, independent verification, never a resend.
BEGIN;

ALTER TABLE management_role_grant DROP CONSTRAINT management_role_grant_lifecycle_role_check;
ALTER TABLE management_role_grant ADD CONSTRAINT management_role_grant_lifecycle_role_check
    CHECK (lifecycle_role IN ('profile-editor', 'policy-approver', 'ca-operator',
                              'certificate-requester', 'registration-officer', 'crl-publisher'));

-- Whether the CA's CRL must be (re)published now: no CRL yet, or the latest
-- published one reaches nextUpdate within two days.
CREATE FUNCTION crl_renewal_due(p_ca UUID) RETURNS BOOLEAN
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $fn$
    SELECT coalesce((SELECT i.next_update <= now() + interval '2 days'
                     FROM crl_document d JOIN crl_signing_intent i ON i.intent_id = d.intent_id
                     WHERE d.ca_id = p_ca ORDER BY d.crl_number DESC LIMIT 1), true)
$fn$;
REVOKE ALL ON FUNCTION crl_renewal_due(UUID) FROM PUBLIC;

-- Who may run the CRL publication functions: an officer, or the renewer.
CREATE FUNCTION crl_publication_granted(p_issuer TEXT, p_subject TEXT, p_ca UUID) RETURNS BOOLEAN
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $fn$
    SELECT certificate_role_granted(p_issuer, p_subject, p_ca, 'registration-officer')
        OR certificate_role_granted(p_issuer, p_subject, p_ca, 'crl-publisher')
$fn$;
REVOKE ALL ON FUNCTION crl_publication_granted(TEXT, TEXT, UUID) FROM PUBLIC;

CREATE OR REPLACE FUNCTION begin_crl_publication_lab(
    p_issuer TEXT, p_subject TEXT, p_ca UUID, p_operation UUID, p_request_sha256 BYTEA
) RETURNS TABLE (intent_id UUID, crl_number BIGINT, this_update TEXT, next_update TEXT, outcome TEXT,
                 issuer_certificate_der BYTEA, replayed BOOLEAN)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_prior crl_signing_intent%ROWTYPE;
    v_number BIGINT;
    v_instant TIMESTAMPTZ;
    v_intent UUID;
    v_replayed BOOLEAN := false;
BEGIN
    IF p_issuer IS NULL OR p_subject IS NULL OR p_ca IS NULL OR p_operation IS NULL
       OR p_request_sha256 IS NULL OR octet_length(p_request_sha256) <> 32
       OR length(p_subject) NOT BETWEEN 1 AND 256 OR length(p_issuer) NOT BETWEEN 1 AND 1024 THEN
        RAISE EXCEPTION 'invalid CRL parameters' USING ERRCODE = '22023';
    END IF;
    IF NOT crl_publication_granted(p_issuer, p_subject, p_ca) THEN
        RAISE EXCEPTION 'no registration-officer or crl-publisher grant for this CA' USING ERRCODE = '42501';
    END IF;
    -- The automatic renewer publishes only a CRL that is due (ADR-0021).
    IF NOT certificate_role_granted(p_issuer, p_subject, p_ca, 'registration-officer')
       AND NOT crl_renewal_due(p_ca) THEN
        RAISE EXCEPTION 'the CRL of this CA is not due for renewal' USING ERRCODE = 'TP409';
    END IF;
    PERFORM crl_lock(p_ca);
    SELECT * INTO v_prior FROM crl_signing_intent i WHERE i.operation_id = p_operation;
    IF FOUND THEN
        IF v_prior.ca_id <> p_ca OR v_prior.request_sha256 <> p_request_sha256
           OR v_prior.actor_issuer <> p_issuer OR v_prior.actor_subject <> p_subject THEN
            RAISE EXCEPTION 'idempotency key already used for another request' USING ERRCODE = 'TP409';
        END IF;
        v_intent := v_prior.intent_id;
        v_replayed := true;
    ELSE
        IF NOT certificate_ca_publishes(p_ca) THEN
            RAISE EXCEPTION 'the CA neither issues nor publishes' USING ERRCODE = 'TP409';
        END IF;
        IF NOT EXISTS (SELECT 1 FROM ca_issuer_certificate c WHERE c.ca_id = p_ca) THEN
            RAISE EXCEPTION 'the CA has no registered issuer certificate' USING ERRCODE = 'P0002';
        END IF;
        SELECT COALESCE(max(i.crl_number), 0) + 1 INTO v_number FROM crl_signing_intent i WHERE i.ca_id = p_ca;
        v_instant := clock_timestamp();
        INSERT INTO crl_signing_intent (ca_id, crl_number, entries_until, this_update, next_update,
                                        operation_id, request_sha256, actor_issuer, actor_subject)
        VALUES (p_ca, v_number, v_instant, date_trunc('second', v_instant),
                date_trunc('second', v_instant) + interval '7 days',
                p_operation, p_request_sha256, p_issuer, p_subject)
        RETURNING crl_signing_intent.intent_id INTO v_intent;
        INSERT INTO audit_event (event_id, ca_id, actor_id, event_type, decision)
        VALUES (gen_random_uuid(), p_ca, p_subject, 'crl.prepared', 'allow');
    END IF;
    RETURN QUERY
    SELECT i.intent_id, i.crl_number,
           to_char(i.this_update AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
           to_char(i.next_update AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
           i.outcome, c.certificate_der, v_replayed
    FROM crl_signing_intent i JOIN ca_issuer_certificate c ON c.ca_id = i.ca_id
    WHERE i.intent_id = v_intent;
END
$fn$;
REVOKE ALL ON FUNCTION begin_crl_publication_lab(TEXT, TEXT, UUID, UUID, BYTEA) FROM PUBLIC;

CREATE OR REPLACE FUNCTION crl_publication_entries_lab(p_issuer TEXT, p_subject TEXT, p_ca UUID, p_intent UUID)
RETURNS TABLE (serial BYTEA, revoked_at TEXT, reason_code SMALLINT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
BEGIN
    IF NOT crl_publication_granted(p_issuer, p_subject, p_ca) THEN
        RAISE EXCEPTION 'no registration-officer or crl-publisher grant for this CA' USING ERRCODE = '42501';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM crl_signing_intent i WHERE i.intent_id = p_intent AND i.ca_id = p_ca) THEN
        RAISE EXCEPTION 'unknown CRL intent' USING ERRCODE = 'P0002';
    END IF;
    RETURN QUERY
    SELECT e.serial, to_char(e.revoked_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), e.reason_code
    FROM crl_intent_entries(p_intent) e;
END
$fn$;
REVOKE ALL ON FUNCTION crl_publication_entries_lab(TEXT, TEXT, UUID, UUID) FROM PUBLIC;

CREATE OR REPLACE FUNCTION record_crl_signing_intent_lab(
    p_issuer TEXT, p_subject TEXT, p_ca UUID, p_intent UUID, p_tbs_sha256 BYTEA
) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_intent crl_signing_intent%ROWTYPE;
BEGIN
    IF p_tbs_sha256 IS NULL OR octet_length(p_tbs_sha256) <> 32 THEN
        RAISE EXCEPTION 'invalid TBS digest' USING ERRCODE = '22023';
    END IF;
    IF NOT crl_publication_granted(p_issuer, p_subject, p_ca) THEN
        RAISE EXCEPTION 'no registration-officer or crl-publisher grant for this CA' USING ERRCODE = '42501';
    END IF;
    PERFORM crl_lock(p_ca);
    SELECT * INTO v_intent FROM crl_signing_intent i WHERE i.intent_id = p_intent AND i.ca_id = p_ca;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown CRL intent' USING ERRCODE = 'P0002';
    END IF;
    IF v_intent.outcome <> 'PREPARED' THEN
        RETURN true;
    END IF;
    IF NOT certificate_ca_publishes(p_ca)
       OR EXISTS (SELECT 1 FROM crl_signing_intent i WHERE i.ca_id = p_ca AND i.crl_number > v_intent.crl_number) THEN
        RAISE EXCEPTION 'this CRL intent can no longer be signed' USING ERRCODE = 'TP409';
    END IF;
    UPDATE crl_signing_intent SET tbs_sha256 = p_tbs_sha256, outcome = 'UNCONFIRMED' WHERE intent_id = p_intent;
    RETURN false;
END
$fn$;
REVOKE ALL ON FUNCTION record_crl_signing_intent_lab(TEXT, TEXT, UUID, UUID, BYTEA) FROM PUBLIC;

CREATE OR REPLACE FUNCTION store_crl_lab(p_issuer TEXT, p_subject TEXT, p_ca UUID, p_intent UUID, p_crl_der BYTEA)
RETURNS TEXT
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_intent crl_signing_intent%ROWTYPE;
BEGIN
    IF NOT crl_publication_granted(p_issuer, p_subject, p_ca) THEN
        RAISE EXCEPTION 'no registration-officer or crl-publisher grant for this CA' USING ERRCODE = '42501';
    END IF;
    PERFORM crl_lock(p_ca);
    SELECT * INTO v_intent FROM crl_signing_intent i WHERE i.intent_id = p_intent AND i.ca_id = p_ca;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown CRL intent' USING ERRCODE = 'P0002';
    END IF;
    IF v_intent.outcome <> 'UNCONFIRMED'
       OR NOT EXISTS (SELECT 1 FROM lab_signer_crl_claim k WHERE k.intent_id = p_intent) THEN
        RAISE EXCEPTION 'this CRL intent cannot be stored' USING ERRCODE = 'TP409';
    END IF;
    INSERT INTO crl_publication (ca_id, crl_number, this_update, next_update, crl_sha256, published_at)
    VALUES (p_ca, v_intent.crl_number, v_intent.this_update, v_intent.next_update, digest(p_crl_der, 'sha256'),
            clock_timestamp());
    INSERT INTO crl_document (ca_id, crl_number, intent_id, crl_der)
    VALUES (p_ca, v_intent.crl_number, p_intent, p_crl_der);
    UPDATE crl_signing_intent SET outcome = 'PUBLISHED' WHERE intent_id = p_intent;
    INSERT INTO audit_event (event_id, ca_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), p_ca, p_subject, 'crl.published', 'allow');
    RETURN 'PUBLISHED';
END
$fn$;
REVOKE ALL ON FUNCTION store_crl_lab(TEXT, TEXT, UUID, UUID, BYTEA) FROM PUBLIC;

CREATE OR REPLACE FUNCTION mark_crl_signing_uncertain_lab(p_issuer TEXT, p_subject TEXT, p_ca UUID, p_intent UUID)
RETURNS TEXT
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
BEGIN
    IF NOT crl_publication_granted(p_issuer, p_subject, p_ca) THEN
        RAISE EXCEPTION 'no registration-officer or crl-publisher grant for this CA' USING ERRCODE = '42501';
    END IF;
    PERFORM crl_lock(p_ca);
    UPDATE crl_signing_intent SET outcome = 'RECONCILIATION_REQUIRED'
    WHERE intent_id = p_intent AND ca_id = p_ca AND outcome = 'UNCONFIRMED';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no unconfirmed CRL intent' USING ERRCODE = 'TP409';
    END IF;
    INSERT INTO audit_event (event_id, ca_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), p_ca, p_subject, 'crl.reconciliation_required', 'deny');
    RETURN 'RECONCILIATION_REQUIRED';
END
$fn$;
REVOKE ALL ON FUNCTION mark_crl_signing_uncertain_lab(TEXT, TEXT, UUID, UUID) FROM PUBLIC;

-- The CAs whose CRL the renewer should publish now: granted to it, still
-- publishing (ACTIVE or SUSPENDED), and due.
CREATE FUNCTION crl_renewal_candidates_lab(p_issuer TEXT, p_subject TEXT)
RETURNS TABLE (ca_id UUID)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
    SELECT g.ca_id FROM management_role_grant g
    WHERE g.issuer = p_issuer AND g.subject = p_subject AND g.lifecycle_role = 'crl-publisher'
      AND certificate_ca_publishes(g.ca_id) AND crl_renewal_due(g.ca_id)
    ORDER BY g.ca_id
$fn$;
REVOKE ALL ON FUNCTION crl_renewal_candidates_lab(TEXT, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION crl_renewal_candidates_lab(TEXT, TEXT) TO trust_profile_writer;

-- Readers see whether the CA's CRL is renewed automatically.
CREATE OR REPLACE VIEW management_crl_status WITH (security_barrier = true) AS
SELECT c.ca_id::text AS ca_id,
       CASE WHEN p.ca_id IS NOT NULL
            THEN p.base_url || '/v1/public/crls/' || c.ca_id::text || '/latest.crl' END AS distribution_point,
       latest.crl_number AS latest_crl_number,
       to_char(latest.next_update AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS next_update,
       latest.crl_number IS NULL OR latest.next_update <= now() + interval '2 days' AS renewal_due,
       latest.crl_number IS NOT NULL AND latest.next_update <= now() AS expired,
       -- Whether the automatic renewer (migration 0035) holds this CA.
       EXISTS (SELECT 1 FROM management_role_grant r
               WHERE r.ca_id = c.ca_id AND r.issuer = 'urn:trust-platform:system'
                 AND r.subject = 'crl-renewer' AND r.lifecycle_role = 'crl-publisher') AS auto_renewal
FROM ca_activation c
LEFT JOIN ca_crl_distribution_point p ON p.ca_id = c.ca_id
LEFT JOIN LATERAL (
    SELECT d.crl_number, i.next_update
    FROM crl_document d JOIN crl_signing_intent i ON i.intent_id = d.intent_id
    WHERE d.ca_id = c.ca_id ORDER BY d.crl_number DESC LIMIT 1
) latest ON true
WHERE EXISTS (
    SELECT 1 FROM management_reader_grant g
    WHERE g.issuer = current_setting('trust.reader_issuer', true)
      AND g.subject = current_setting('trust.reader_subject', true)
      AND g.ca_id = c.ca_id
);

CREATE FUNCTION management_crl_renewal_version() RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $fn$ SELECT 1 $fn$;
REVOKE ALL ON FUNCTION management_crl_renewal_version() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION management_crl_renewal_version() TO trust_api_reader, trust_profile_writer;

COMMIT;
