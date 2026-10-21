-- Preserve validity and DNS SANs extracted only after independent certificate
-- verification. Existing rows remain unknown rather than inferred from CSR data.
BEGIN;

ALTER TABLE certificate
    ADD COLUMN not_before_utc TIMESTAMPTZ,
    ADD COLUMN not_after_utc TIMESTAMPTZ,
    ADD COLUMN san_dns TEXT[],
    ADD CONSTRAINT certificate_verified_metadata_complete CHECK (
        (not_before_utc IS NULL AND not_after_utc IS NULL AND san_dns IS NULL)
        OR (not_before_utc IS NOT NULL AND not_after_utc IS NOT NULL
            AND not_before_utc < not_after_utc AND san_dns IS NOT NULL
            AND cardinality(san_dns) <= 100)
    );

CREATE OR REPLACE VIEW management_certificate WITH (security_barrier = true) AS
SELECT c.ca_id::text AS ca_id, encode(c.serial_der_content, 'hex') AS serial_hex,
       encode(c.fingerprint_sha256, 'hex') AS fingerprint_sha256,
       c.request_id::text AS request_id, r.state,
       to_char(c.signed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS signed_at,
       to_char(c.published_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS published_at,
       c.subject_cn,
       to_char(c.not_before_utc AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS not_before,
       to_char(c.not_after_utc AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS not_after,
       c.san_dns
FROM certificate c
JOIN certificate_request r ON (r.ca_id = c.ca_id AND r.request_id = c.request_id);

CREATE FUNCTION store_signed_certificate(
    p_ca_id UUID, p_request_id UUID, p_actor_id TEXT,
    p_serial BYTEA, p_tbs_sha256 BYTEA, p_cert_sha256 BYTEA, p_cert_der BYTEA,
    p_subject_cn TEXT, p_not_before TEXT, p_not_after TEXT, p_san_dns TEXT[]
)
RETURNS TEXT LANGUAGE plpgsql AS $fn$
DECLARE v_result TEXT;
BEGIN
    IF p_not_before IS NULL OR p_not_after IS NULL
       OR p_not_before !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
       OR p_not_after !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
       OR p_san_dns IS NULL OR cardinality(p_san_dns) > 100
       OR EXISTS (SELECT 1 FROM unnest(p_san_dns) AS entry(value)
                  WHERE value IS NULL OR length(value) NOT BETWEEN 1 AND 253
                     OR value ~ '[[:cntrl:]]') THEN
        RAISE EXCEPTION 'invalid verified certificate metadata' USING ERRCODE='22023';
    END IF;
    v_result := store_signed_certificate(
        p_ca_id,p_request_id,p_actor_id,p_serial,p_tbs_sha256,p_cert_sha256,p_cert_der,p_subject_cn
    );
    UPDATE certificate SET not_before_utc=p_not_before::timestamptz,
        not_after_utc=p_not_after::timestamptz, san_dns=p_san_dns
    WHERE ca_id=p_ca_id AND request_id=p_request_id;
    RETURN v_result;
END
$fn$;

REVOKE ALL ON FUNCTION store_signed_certificate(UUID,UUID,TEXT,BYTEA,BYTEA,BYTEA,BYTEA,TEXT,TEXT,TEXT,TEXT[]) FROM PUBLIC;

COMMIT;
