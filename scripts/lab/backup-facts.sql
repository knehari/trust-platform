-- Laboratory backup facts (scripts/lab/backup.sh, restore.sh; ADR-0041).
-- Run as the database owner. One JSON object: counts and digests of the
-- records a restore must bring back unchanged, and the schema's version
-- markers, which a restore must find identical in the code it runs.
SELECT json_build_object(
    'schema_sha256', (SELECT encode(digest(coalesce(string_agg(p.proname, ',' ORDER BY p.proname), ''), 'sha256'), 'hex')
                      FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                      WHERE n.nspname = 'public' AND p.proname LIKE 'management\_%\_version'),
    'certificates', (SELECT count(*) FROM certificate),
    'certificates_sha256', (SELECT encode(digest(coalesce(string_agg(fingerprint_sha256, ''::bytea
                                ORDER BY ca_id, serial_der_content), ''::bytea), 'sha256'), 'hex') FROM certificate),
    'serial_reservations', (SELECT count(*) FROM serial_reservation),
    'revocations', (SELECT count(*) FROM revocation),
    'crls', (SELECT count(*) FROM crl_document),
    'crls_sha256', (SELECT encode(digest(coalesce(string_agg(crl_sha256, ''::bytea
                        ORDER BY ca_id, crl_number), ''::bytea), 'sha256'), 'hex') FROM crl_document),
    'audit_events', (SELECT count(*) FROM audit_event),
    'audit_head_seq', (SELECT coalesce(max(seq), 0) FROM audit_chain_link),
    'audit_head_hash', coalesce((SELECT encode(chain_hash, 'hex') FROM audit_chain_link
                                 ORDER BY seq DESC LIMIT 1), ''),
    'checkpoint_seq', (SELECT coalesce(max(seq), 0) FROM audit_chain_checkpoint)
);
