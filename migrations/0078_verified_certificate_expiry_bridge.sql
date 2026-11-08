-- Laboratory integration: make the verified profile issuance entry point store
-- the expiry required by revocation/CRL pruning in the same transaction.
-- Historical NULL expiry values still use the governed backfill from 0067.
BEGIN;

GRANT UPDATE (subject_cn, not_before_utc, not_after_utc, san_dns)
    ON certificate TO trust_issuance_owner;
-- The existing SAN sync trigger runs with the writer's rights. Its derived
-- table is still unreachable by the login role; only the NOLOGIN function
-- owner can maintain rows through verified issuance.
GRANT SELECT (request_id), INSERT, DELETE
    ON certificate_san_dns TO trust_issuance_owner;

CREATE OR REPLACE FUNCTION store_signed_certificate(
    p_ca_id UUID, p_request_id UUID, p_actor_id TEXT,
    p_serial BYTEA, p_tbs_sha256 BYTEA, p_cert_sha256 BYTEA, p_cert_der BYTEA,
    p_subject_cn TEXT, p_not_before TEXT, p_not_after TEXT, p_san_dns TEXT[]
)
RETURNS TEXT
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp AS $fn$
DECLARE
    v_result TEXT;
BEGIN
    IF p_subject_cn IS NOT NULL AND
       (length(p_subject_cn) NOT BETWEEN 1 AND 255 OR p_subject_cn ~ '[[:cntrl:]]')
       OR p_not_before IS NULL OR p_not_after IS NULL
       OR p_not_before !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
       OR p_not_after !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
       OR p_san_dns IS NULL OR cardinality(p_san_dns) > 100
       OR EXISTS (SELECT 1 FROM unnest(p_san_dns) AS entry(value)
                  WHERE value IS NULL OR length(value) NOT BETWEEN 1 AND 253
                     OR value ~ '[[:cntrl:]]') THEN
        RAISE EXCEPTION 'invalid verified certificate metadata' USING ERRCODE='22023';
    END IF;

    -- This overload inserts certificate.not_after while the 11-argument
    -- profile path still records CN and SAN metadata. Both values originate
    -- from the independently verified certificate DER in the Rust journal.
    v_result := store_signed_certificate(
        p_ca_id,p_request_id,p_actor_id,p_serial,p_tbs_sha256,p_cert_sha256,
        p_cert_der,p_not_after::timestamptz
    );
    UPDATE certificate SET subject_cn=p_subject_cn,
        not_before_utc=p_not_before::timestamptz,
        not_after_utc=p_not_after::timestamptz, san_dns=p_san_dns
    WHERE ca_id=p_ca_id AND request_id=p_request_id;
    RETURN v_result;
END
$fn$;

ALTER FUNCTION store_signed_certificate(UUID,UUID,TEXT,BYTEA,BYTEA,BYTEA,BYTEA,TEXT,TEXT,TEXT,TEXT[])
    OWNER TO trust_issuance_owner;
REVOKE ALL ON FUNCTION store_signed_certificate(UUID,UUID,TEXT,BYTEA,BYTEA,BYTEA,BYTEA,TEXT,TEXT,TEXT,TEXT[])
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION store_signed_certificate(UUID,UUID,TEXT,BYTEA,BYTEA,BYTEA,BYTEA,TEXT,TEXT,TEXT,TEXT[])
    TO trust_issuance_service;

SELECT acknowledge_schema_changes('0078_verified_certificate_expiry_bridge');

COMMIT;
