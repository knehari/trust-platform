-- v0.41 (lab): offline audit of signed evidence (ADR-0007 §7, Proposed;
-- implemented in lab at the owner's request). LAB ONLY.
-- The database cannot verify ECDSA, so a holder of the officer API or CA
-- admin role could store a forged assertion; re-verification in Rust exposes
-- it, but only roles that can also act could run it.
-- * signed_evidence_index(ca): every change of the CA carrying signatures,
--   by family (STATUS_CHANGE, CA_ADMIN, CREDENTIAL, ADMIN_CREDENTIAL), with
--   its status: a PROPOSED change legitimately has only its maker's
--   signature so far.
-- * trust_audit_verifier (0027) gets it and the read-only functions the
--   Rust core re-verifies with (signatures and challenge claims), and
--   nothing that acts. PgRevocationStore::audit_signed_evidence and the
--   signed_evidence_audit example run under it.
-- Apply after 0040 as a superuser.
BEGIN;

CREATE FUNCTION signed_evidence_index(p_ca UUID)
RETURNS TABLE (family TEXT, change_id UUID, status TEXT)
LANGUAGE sql STABLE AS $fn$
    SELECT DISTINCT 'STATUS_CHANGE', s.change_id, c.status
    FROM status_change_signature s
    JOIN certificate_status_change c USING (change_id)
    WHERE c.ca_id = p_ca
    UNION
    SELECT DISTINCT s.family, s.change_id, coalesce(a.status, o.status, k.status)
    FROM ca_admin_signature s
    JOIN ca_admin_challenge ch USING (challenge_id)
    LEFT JOIN ca_admin_change a ON s.family = 'CA_ADMIN' AND a.change_id = s.change_id
    LEFT JOIN officer_credential_change o
           ON s.family = 'CREDENTIAL' AND o.change_id = s.change_id
    LEFT JOIN ca_admin_credential_change k
           ON s.family = 'ADMIN_CREDENTIAL' AND k.change_id = s.change_id
    WHERE ch.ca_id = p_ca
    ORDER BY 1, 2
$fn$;
ALTER FUNCTION signed_evidence_index(uuid) OWNER TO trust_revocation_owner;
ALTER FUNCTION signed_evidence_index(uuid) SECURITY DEFINER;
ALTER FUNCTION signed_evidence_index(uuid) SET search_path = pg_catalog, public, pg_temp;
REVOKE ALL ON FUNCTION signed_evidence_index(uuid) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION signed_evidence_index(uuid),
    status_change_signatures(uuid),
    status_change_challenge_claim(uuid),
    ca_admin_signatures(text, uuid),
    ca_admin_challenge_claim(uuid)
    TO trust_audit_verifier;

SELECT acknowledge_schema_changes('0041_signed_evidence_audit');

COMMIT;
