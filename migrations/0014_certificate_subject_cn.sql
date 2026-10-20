-- Add the verified certificate subject CN to the restricted management projection.
-- Historical rows remain NULL; never infer a CN from requester identity or CA name.
BEGIN;

ALTER TABLE certificate ADD COLUMN subject_cn TEXT
    CHECK (subject_cn IS NULL OR (length(subject_cn) BETWEEN 1 AND 255 AND subject_cn !~ '[[:cntrl:]]'));

CREATE OR REPLACE VIEW management_certificate WITH (security_barrier = true) AS
SELECT c.ca_id::text AS ca_id, encode(c.serial_der_content, 'hex') AS serial_hex,
       encode(c.fingerprint_sha256, 'hex') AS fingerprint_sha256,
       c.request_id::text AS request_id, r.state,
       to_char(c.signed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS signed_at,
       to_char(c.published_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS published_at,
       c.subject_cn
FROM certificate c
JOIN certificate_request r ON (r.ca_id = c.ca_id AND r.request_id = c.request_id);

-- The original seven-argument function remains available for historical lab callers.
-- The Rust journal calls this overload only after independent X.509 verification.
CREATE FUNCTION store_signed_certificate(
    p_ca_id UUID, p_request_id UUID, p_actor_id TEXT,
    p_serial BYTEA, p_tbs_sha256 BYTEA, p_cert_sha256 BYTEA, p_cert_der BYTEA,
    p_subject_cn TEXT
)
RETURNS TEXT LANGUAGE plpgsql AS $fn$
DECLARE v_result TEXT;
BEGIN
    IF p_subject_cn IS NOT NULL AND
       (length(p_subject_cn) NOT BETWEEN 1 AND 255 OR p_subject_cn ~ '[[:cntrl:]]') THEN
        RAISE EXCEPTION 'invalid certificate subject CN' USING ERRCODE='22023';
    END IF;
    v_result := store_signed_certificate(
        p_ca_id,p_request_id,p_actor_id,p_serial,p_tbs_sha256,p_cert_sha256,p_cert_der
    );
    UPDATE certificate SET subject_cn=p_subject_cn
    WHERE ca_id=p_ca_id AND request_id=p_request_id;
    RETURN v_result;
END
$fn$;

REVOKE ALL ON FUNCTION store_signed_certificate(UUID,UUID,TEXT,BYTEA,BYTEA,BYTEA,BYTEA,TEXT) FROM PUBLIC;

COMMIT;
