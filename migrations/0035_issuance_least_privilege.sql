-- v0.35 (lab): least privilege on the issuance path. LAB ONLY.
-- Until now the issuance functions (0001..0004, 0031) were SECURITY INVOKER
-- owned by the migration login, so the issuance service had to run with the
-- owner's table rights: such a login could INSERT a certificate that never
-- went through a signing intent, rewrite an intent or bypass the policy gate
-- triggers' intent. Same model as revocation (0023):
-- * trust_issuance_owner (NOLOGIN) owns the issuance functions, which run
--   SECURITY DEFINER with a pinned search_path. It holds exactly the table
--   rights those functions and the signing_intent policy-gate triggers
--   (0008, 0009, 0011) need; UPDATE on ca is limited to policy_gate_epoch.
-- * trust_issuance_service (NOLOGIN capability role, granted to a login)
--   holds EXECUTE on the issuance functions only: no table access at all.
-- Not covered (still the migration login): the lab policy-administration
-- functions (policy gate activation, draft approval, presign grants, dual
-- signature receipts), reconciliation review and collector evidence. They
-- are separate operator paths, recorded as a residual risk in the threat
-- model. The historical 7-argument store_signed_certificate keeps no grant.
-- Apply after 0034 as a superuser.
BEGIN;

DO $roles$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trust_issuance_owner') THEN
        CREATE ROLE trust_issuance_owner NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trust_issuance_service') THEN
        CREATE ROLE trust_issuance_service NOLOGIN;
    END IF;
END $roles$;

GRANT SELECT, INSERT, UPDATE ON certificate_request, serial_reservation, signing_intent
    TO trust_issuance_owner;
GRANT SELECT, INSERT ON certificate TO trust_issuance_owner;
GRANT INSERT ON audit_event TO trust_issuance_owner;
GRANT SELECT, UPDATE (policy_gate_epoch) ON ca TO trust_issuance_owner;
GRANT SELECT ON approved_policy_edition, ca_policy_enforcement, issuance_policy_grant,
    ca_dual_signature_enforcement, policy_dual_signature_receipt TO trust_issuance_owner;
-- The state machine helper the functions call (PUBLIC execute revoked).
GRANT EXECUTE ON FUNCTION allowed_issuance_transition(text, text) TO trust_issuance_owner;

DO $fns$
DECLARE
    f TEXT;
BEGIN
    FOREACH f IN ARRAY ARRAY[
        'create_issuance_request(uuid,text,bytea,text,text)',
        'transition_issuance_request(uuid,uuid,text,text,text)',
        'reserve_issuance_serial(uuid,uuid,text)',
        'create_signing_intent(uuid,uuid,text,text,bytea,text,text)',
        'mark_signing_uncertain(uuid,uuid,text)',
        'store_signed_certificate(uuid,uuid,text,bytea,bytea,bytea,bytea,timestamptz)',
        'quarantine_stale_signing_intents(uuid,timestamptz,integer,text)'] LOOP
        EXECUTE format('ALTER FUNCTION %s OWNER TO trust_issuance_owner', f);
        EXECUTE format('ALTER FUNCTION %s SECURITY DEFINER', f);
        EXECUTE format('ALTER FUNCTION %s SET search_path = pg_catalog, public, pg_temp', f);
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
        EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO trust_issuance_service', f);
    END LOOP;
END $fns$;

SELECT acknowledge_schema_changes('0035_issuance_least_privilege');

COMMIT;
