-- v0.43 (lab): least privilege for policy administration, reconciliation
-- and evidence (completes 0035). LAB ONLY.
-- These functions were still SECURITY INVOKER owned by the migration login,
-- so their callers needed the owner's table rights (and could write the
-- policy, grant, receipt, reconciliation and evidence tables directly).
-- * They are now owned by trust_issuance_owner (0035), SECURITY DEFINER with
--   a pinned search_path; the owner gains only the table rights they and
--   their triggers need.
-- * trust_policy_admin (NOLOGIN capability role): CA public observation,
--   CP/CPS draft registration, draft approval, policy gate activation,
--   presign grants, dual-signature receipts and enforcement. EXECUTE only.
-- * trust_reconciliation_operator (NOLOGIN capability role): reconciliation
--   observations, review proposals and decisions, collector evidence and
--   the issued-certificate-to-draft trace. EXECUTE only.
-- Neither can issue; trust_issuance_service cannot administer policy or
-- record evidence. Actor identities stay asserted by the caller (lab); the
-- two-actor policy checks are unchanged.
-- Apply after 0042 as a superuser.
BEGIN;

DO $roles$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trust_policy_admin') THEN
        CREATE ROLE trust_policy_admin NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trust_reconciliation_operator') THEN
        CREATE ROLE trust_reconciliation_operator NOLOGIN;
    END IF;
END $roles$;

GRANT SELECT, INSERT ON ca_policy_enforcement, approved_policy_edition, issuance_policy_grant,
    policy_dual_signature_receipt, ca_dual_signature_enforcement, ca_public_observation,
    cp_cps_draft_snapshot, signing_reconciliation_observation, signing_collector_evidence,
    issued_certificate_draft_trace
    TO trust_issuance_owner;
GRANT SELECT, INSERT, UPDATE ON signing_reconciliation_review TO trust_issuance_owner;
-- Row lock only (persist_verified_dual_policy_receipt_lab locks the edition
-- FOR SHARE, which needs UPDATE); immutable_approved_policy refuses any
-- actual UPDATE.
GRANT UPDATE ON approved_policy_edition TO trust_issuance_owner;

DO $fns$
DECLARE
    f TEXT;
    r TEXT;
BEGIN
    FOREACH f IN ARRAY ARRAY[
        'register_ca_public_observation(uuid,text,bytea,bytea,bytea)',
        'register_cp_cps_draft(uuid,text,uuid,text,text,text,text,bytea,text,text,bytea,bytea)',
        'approve_policy_draft_lab(uuid,uuid,text,text,bytea,bytea,timestamptz,timestamptz)',
        'activate_ca_policy_gate_lab(uuid,text)',
        'grant_request_approved_policy_lab(uuid,uuid,uuid,text,bytea,text)',
        'persist_verified_dual_policy_receipt_lab(uuid,uuid,uuid,text,text,bytea,bytea,bytea,bytea,bytea,bytea,text,text,timestamptz,timestamptz)',
        'require_dual_signature_policy_lab(uuid,text)',
        'record_signing_reconciliation_observation(uuid,uuid,text,text,bytea)',
        'propose_reconciliation_review(uuid,uuid,uuid,text,text,bytea,bytea)',
        'review_reconciliation_proposal(uuid,uuid,text,bytea,bytea)',
        'persist_signing_collector_evidence(uuid,uuid,text,text,text,text,text,bigint,text,bytea,bytea,bytea,bytea,bytea)',
        'trace_issued_certificate_to_draft(uuid,uuid,text,uuid,bytea,bytea,bytea,bytea,bytea,text)'] LOOP
        r := CASE WHEN f ~ '^(record_signing|propose_reconciliation|review_reconciliation|persist_signing|trace_issued)'
                  THEN 'trust_reconciliation_operator' ELSE 'trust_policy_admin' END;
        EXECUTE format('ALTER FUNCTION %s OWNER TO trust_issuance_owner', f);
        EXECUTE format('ALTER FUNCTION %s SECURITY DEFINER', f);
        EXECUTE format('ALTER FUNCTION %s SET search_path = pg_catalog, public, pg_temp', f);
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
        EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO %I', f, r);
    END LOOP;
END $fns$;

SELECT acknowledge_schema_changes('0043_policy_and_reconciliation_least_privilege');

COMMIT;
