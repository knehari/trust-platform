-- v0.32 (lab): what a CRL leaves out, for the Rust core to re-check before
-- signing (closes the residual risk recorded for 0031). LAB ONLY.
-- * crl_pruned_entries(ca, n) lists the CA's revocations that are absent
--   from reservation n's snapshot although they are not newer than it (their
--   approving change was decided at or before the reservation), with the
--   stored not_after and the stored certificate DER. Under 0031 that is
--   exactly the set pruned after expiry.
-- * PgRevocationStore's CRL journal parses each DER before recording the
--   intent: the serial must match, its notAfter must equal the stored
--   not_after and precede thisUpdate (crl::check_pruned_entry). A not_after
--   recorded earlier than the certificate's real expiry, or any other
--   unexplained omission, is refused before anything is signed.
-- Granted to trust_crl_signer only.
-- Apply after 0031 as a superuser.
BEGIN;

CREATE FUNCTION crl_pruned_entries(p_ca UUID, p_crl_number BIGINT)
RETURNS TABLE (serial_der_content BYTEA, not_after_unix BIGINT, certificate_der BYTEA)
LANGUAGE sql STABLE AS $fn$
    SELECT r.serial_der_content, floor(extract(epoch FROM c.not_after))::bigint,
           c.certificate_der
    FROM crl_publication p
    JOIN revocation r ON r.ca_id = p.ca_id
    LEFT JOIN certificate_status_change s ON s.change_id = r.change_id
    LEFT JOIN certificate c ON c.ca_id = r.ca_id AND c.serial_der_content = r.serial_der_content
    WHERE p.ca_id = p_ca AND p.crl_number = p_crl_number
      AND (s.decided_at IS NULL OR s.decided_at <= coalesce(p.reserved_at, p.this_update))
      AND NOT EXISTS (SELECT 1 FROM crl_entry_snapshot e
                      WHERE e.ca_id = p.ca_id AND e.crl_number = p.crl_number
                        AND e.serial_der_content = r.serial_der_content)
    ORDER BY r.serial_der_content
$fn$;
ALTER FUNCTION crl_pruned_entries(uuid,bigint) OWNER TO trust_revocation_owner;
ALTER FUNCTION crl_pruned_entries(uuid,bigint) SECURITY DEFINER;
ALTER FUNCTION crl_pruned_entries(uuid,bigint) SET search_path = pg_catalog, public, pg_temp;
REVOKE ALL ON FUNCTION crl_pruned_entries(uuid,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION crl_pruned_entries(uuid,bigint) TO trust_crl_signer;

SELECT acknowledge_schema_changes('0032_crl_pruned_entries');

COMMIT;
