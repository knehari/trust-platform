-- Migration 0045: operational metrics for the background worker (ADR-0038,
-- Proposed).
--
-- AGENTS.md asks for metrics on expiry, signing errors, publication delays and
-- operations awaiting reconciliation. This function returns them as
-- aggregated numbers per CA: counts and durations, never a certificate, a
-- subject, an actor or a request. Only the worker's role may call it; the
-- worker exposes the numbers to a metrics scraper on a loopback listener.
BEGIN;

CREATE FUNCTION operational_metrics_lab()
RETURNS TABLE (metric TEXT, ca_id TEXT, value DOUBLE PRECISION)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
    -- Certificates in force (not expired, not revoked), and those of them
    -- that expire within 30 days, per CA (verified metadata, migration 0015).
    SELECT 'certificates_expiring_30d', c.ca_id::text, count(*)::double precision
    FROM certificate c
    WHERE c.not_after_utc > now() AND c.not_after_utc <= now() + interval '30 days'
      AND NOT EXISTS (SELECT 1 FROM revocation r
                      WHERE r.ca_id = c.ca_id AND r.serial_der_content = c.serial_der_content)
    GROUP BY c.ca_id
    UNION ALL
    SELECT 'certificates_valid', c.ca_id::text, count(*)::double precision
    FROM certificate c
    WHERE c.not_after_utc > now()
      AND NOT EXISTS (SELECT 1 FROM revocation r
                      WHERE r.ca_id = c.ca_id AND r.serial_der_content = c.serial_der_content)
    GROUP BY c.ca_id
    -- Certificate signing outcomes awaiting reconciliation (a confirmed void,
    -- migration 0034, resolves one), and intents still unconfirmed five
    -- minutes after they were journaled (a signer or a store that did not
    -- answer).
    UNION ALL
    SELECT 'issuance_reconciliation_required', s.ca_id::text, count(*)::double precision
    FROM signing_intent s
    WHERE s.outcome = 'RECONCILIATION_REQUIRED'
      AND NOT EXISTS (SELECT 1 FROM certificate_application_void v
                      WHERE v.ca_id = s.ca_id AND v.request_id = s.request_id AND v.voided_at IS NOT NULL)
    GROUP BY s.ca_id
    UNION ALL
    SELECT 'issuance_unconfirmed_stale', s.ca_id::text, count(*)::double precision
    FROM signing_intent s
    WHERE s.outcome = 'UNCONFIRMED' AND s.created_at < now() - interval '5 minutes'
    GROUP BY s.ca_id
    -- CRL signing outcomes awaiting reconciliation.
    UNION ALL
    SELECT 'crl_reconciliation_required', i.ca_id::text, count(*)::double precision
    FROM crl_signing_intent i WHERE i.outcome = 'RECONCILIATION_REQUIRED'
    GROUP BY i.ca_id
    -- Seconds until the latest published CRL's nextUpdate (negative once
    -- expired), and revocations not yet listed in a published CRL.
    UNION ALL
    SELECT 'crl_next_update_seconds', l.ca_id::text,
           extract(epoch FROM l.next_update - now())::double precision
    FROM (SELECT DISTINCT ON (d.ca_id) d.ca_id, i.next_update
          FROM crl_document d JOIN crl_signing_intent i ON i.intent_id = d.intent_id
          ORDER BY d.ca_id, d.crl_number DESC) l
    UNION ALL
    SELECT 'crl_unpublished_entries', a.ca_id::text, crl_unpublished_entries(a.ca_id)::double precision
    FROM ca_activation a
    -- The audit chain: events not yet sealed, the head, and the age of the
    -- latest signed checkpoint.
    UNION ALL
    SELECT 'audit_unsealed_events', NULL,
           (SELECT count(*) FROM audit_event e
            WHERE NOT EXISTS (SELECT 1 FROM audit_chain_link l WHERE l.event_id = e.event_id))::double precision
    UNION ALL
    SELECT 'audit_chain_head_seq', NULL, coalesce((SELECT max(seq) FROM audit_chain_link), 0)::double precision
    UNION ALL
    SELECT 'audit_checkpoint_age_seconds', NULL,
           extract(epoch FROM now() - max(k.signed_at))::double precision
    FROM audit_chain_checkpoint k HAVING count(*) > 0
$fn$;
REVOKE ALL ON FUNCTION operational_metrics_lab() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION operational_metrics_lab() TO trust_worker;

CREATE FUNCTION management_operational_metrics_version() RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $fn$ SELECT 1 $fn$;
REVOKE ALL ON FUNCTION management_operational_metrics_version() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION management_operational_metrics_version()
    TO trust_api_reader, trust_profile_writer, trust_worker;

COMMIT;
