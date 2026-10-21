-- v0.44 (lab): what a CA admin may read about pending CA-admin changes.
-- LAB ONLY.
-- A checker signs the content digest of a pending change (0037, 0040, 0042);
-- to review it they need the content itself, not only the digest.
-- * pending_admin_changes(ca): every PROPOSED change of the CA in the three
--   families, oldest first (at most 500), with its kind, content (issuer
--   certificate, officer or admin identity, credential id, person, key),
--   stored content digest, maker and whether the maker signed. The Rust
--   core recomputes the digest from the content before showing it.
-- Granted to trust_ca_admin only.
-- Apply after 0043 as a superuser.
BEGIN;

CREATE FUNCTION pending_admin_changes(p_ca UUID)
RETURNS TABLE (family TEXT, change_id UUID, kind TEXT, certificate_der BYTEA,
               officer_issuer TEXT, officer_subject TEXT, credential_id BYTEA,
               person_id TEXT, public_key_sec1 BYTEA, content_sha256 BYTEA,
               maker_issuer TEXT, maker_subject TEXT, proposed_at TIMESTAMPTZ,
               maker_signed BOOLEAN)
LANGUAGE sql STABLE AS $fn$
    SELECT * FROM (
        SELECT 'CA_ADMIN', a.change_id, a.kind, a.certificate_der, a.officer_issuer,
               a.officer_subject, NULL::bytea, NULL::text, NULL::bytea, a.content_sha256,
               a.maker_issuer, a.maker_subject, a.proposed_at,
               EXISTS (SELECT 1 FROM ca_admin_signature s
                       WHERE s.family = 'CA_ADMIN' AND s.change_id = a.change_id
                         AND s.role = 'MAKER')
        FROM ca_admin_change a
        WHERE a.ca_id = p_ca AND a.status = 'PROPOSED'
        UNION ALL
        SELECT 'CREDENTIAL', o.change_id, o.kind, NULL, o.officer_issuer, o.officer_subject,
               o.credential_id, o.person_id, o.public_key_sec1, o.content_sha256,
               o.maker_issuer, o.maker_subject, o.proposed_at,
               EXISTS (SELECT 1 FROM ca_admin_signature s
                       WHERE s.family = 'CREDENTIAL' AND s.change_id = o.change_id
                         AND s.role = 'MAKER')
        FROM officer_credential_change o
        WHERE o.ca_id = p_ca AND o.status = 'PROPOSED'
        UNION ALL
        SELECT 'ADMIN_CREDENTIAL', k.change_id, k.kind, NULL, k.admin_issuer, k.admin_subject,
               k.credential_id, k.person_id, k.public_key_sec1, k.content_sha256,
               k.maker_issuer, k.maker_subject, k.proposed_at,
               EXISTS (SELECT 1 FROM ca_admin_signature s
                       WHERE s.family = 'ADMIN_CREDENTIAL' AND s.change_id = k.change_id
                         AND s.role = 'MAKER')
        FROM ca_admin_credential_change k
        WHERE k.ca_id = p_ca AND k.status = 'PROPOSED'
    ) pending
    ORDER BY 13, 2
    LIMIT 500
$fn$;
ALTER FUNCTION pending_admin_changes(uuid) OWNER TO trust_revocation_owner;
ALTER FUNCTION pending_admin_changes(uuid) SECURITY DEFINER;
ALTER FUNCTION pending_admin_changes(uuid) SET search_path = pg_catalog, public, pg_temp;
REVOKE ALL ON FUNCTION pending_admin_changes(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pending_admin_changes(uuid) TO trust_ca_admin;

SELECT acknowledge_schema_changes('0044_pending_admin_changes');

COMMIT;
