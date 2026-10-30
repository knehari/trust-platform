-- v0.23 (lab): least-privilege write model for revocation and CRLs
-- (ADR-0006 part A, status Proposed; implemented in lab at the owner's
-- request, not an accepted security design). LAB ONLY.
--
-- * trust_revocation_owner (NOLOGIN) owns the revocation/CRL tables and
--   functions. No login is a member; migrations run as a superuser or a
--   migration role.
-- * Every function a service calls is SECURITY DEFINER with
--   search_path = pg_catalog, public, pg_temp (temporary objects are looked
--   up last, so a caller cannot shadow a table or function).
-- * Capability roles (NOLOGIN, granted to separate service logins by the
--   deployment) get EXECUTE on their functions only and no table DML:
--     trust_revocation_officer_api  status-change lifecycle (+ SELECT policy)
--     trust_crl_signer              CRL reservation, intent, store
--                                   (+ SELECT crl_publication)
--     trust_crl_operator            due/overdue reports and housekeeping
--     trust_ca_admin                issuer certificate registration
--   Direct writes that bypassed maker-checker or the CRL pipeline (insert a
--   revocation, delete a hold, insert into a CRL snapshot, insert a STORED
--   publication) are therefore impossible from every service login.
-- * The owner needs SELECT/UPDATE on ca and certificate (row locks) and
--   INSERT on audit_event; it is reachable only through the definer
--   functions.
-- Superusers and the table owner still bypass all of this (trigger guards
-- remain). Signed, key-distinct double control (ADR-0006 part B) is not
-- part of this migration.
-- Apply after 0022 as a superuser.
BEGIN;

DO $roles$
DECLARE
    r TEXT;
BEGIN
    FOREACH r IN ARRAY ARRAY['trust_revocation_owner', 'trust_revocation_officer_api',
                             'trust_crl_signer', 'trust_crl_operator', 'trust_ca_admin'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
            EXECUTE format('CREATE ROLE %I NOLOGIN', r);
        END IF;
    END LOOP;
END $roles$;

ALTER TABLE revocation OWNER TO trust_revocation_owner;
ALTER TABLE certificate_status_change OWNER TO trust_revocation_owner;
ALTER TABLE revocation_officer_grant OWNER TO trust_revocation_owner;
ALTER TABLE ca_revocation_policy OWNER TO trust_revocation_owner;
ALTER TABLE crl_publication OWNER TO trust_revocation_owner;
ALTER TABLE crl_entry_snapshot OWNER TO trust_revocation_owner;
ALTER TABLE ca_issuer_certificate OWNER TO trust_revocation_owner;

GRANT SELECT, UPDATE ON ca, certificate TO trust_revocation_owner;
GRANT INSERT ON audit_event TO trust_revocation_owner;

DO $fns$
DECLARE
    f TEXT;
BEGIN
    -- Called by services: definer rights, fixed search_path.
    FOREACH f IN ARRAY ARRAY[
        'certificate_status(uuid,bytea)',
        'propose_certificate_status_change(uuid,bytea,text,smallint,timestamp with time zone,text,text)',
        'approve_certificate_status_change(uuid,text,text,text,smallint)',
        'reject_certificate_status_change(uuid,text,text)',
        'withdraw_certificate_status_change(uuid,text,text)',
        'reserve_crl(uuid,text,text)',
        'crl_snapshot_entries(uuid,bigint)',
        'record_crl_intent(uuid,bigint,text,bytea,bytea,bigint,bigint,bigint,bytea)',
        'mark_crl_uncertain(uuid,bigint,text)',
        'store_verified_crl(uuid,bigint,text,bytea,bytea,bytea)',
        'store_reconciled_crl(uuid,bigint,text,bytea,bytea,bytea,text,bytea)',
        'quarantine_stale_crl_intents(uuid,interval)',
        'abandon_stale_crl_reservations(uuid,interval)',
        'crl_due(uuid)',
        'overdue_status_changes(uuid)',
        'register_ca_issuer(uuid,bytea,text)'] LOOP
        EXECUTE format('ALTER FUNCTION %s OWNER TO trust_revocation_owner', f);
        EXECUTE format('ALTER FUNCTION %s SECURITY DEFINER', f);
        EXECUTE format('ALTER FUNCTION %s SET search_path = pg_catalog, public, pg_temp', f);
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
    END LOOP;
    -- Internal helpers and trigger functions: owned, invoker rights, never
    -- granted to a service.
    FOREACH f IN ARRAY ARRAY[
        'crl_change_covered(uuid,boolean)',
        'crl_entry_encoding(bytea,timestamp with time zone,smallint,timestamp with time zone)',
        'guard_revocation()',
        'guard_certificate_status_change()',
        'guard_crl_publication()',
        'guard_crl_entry_snapshot()',
        'guard_ca_issuer_certificate()'] LOOP
        EXECUTE format('ALTER FUNCTION %s OWNER TO trust_revocation_owner', f);
        EXECUTE format('ALTER FUNCTION %s SET search_path = pg_catalog, public, pg_temp', f);
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
    END LOOP;
END $fns$;

GRANT EXECUTE ON FUNCTION
    certificate_status(uuid,bytea),
    propose_certificate_status_change(uuid,bytea,text,smallint,timestamp with time zone,text,text),
    approve_certificate_status_change(uuid,text,text,text,smallint),
    reject_certificate_status_change(uuid,text,text),
    withdraw_certificate_status_change(uuid,text,text)
TO trust_revocation_officer_api;
GRANT SELECT ON ca_revocation_policy TO trust_revocation_officer_api;

GRANT EXECUTE ON FUNCTION
    reserve_crl(uuid,text,text),
    crl_snapshot_entries(uuid,bigint),
    record_crl_intent(uuid,bigint,text,bytea,bytea,bigint,bigint,bigint,bytea),
    mark_crl_uncertain(uuid,bigint,text),
    store_verified_crl(uuid,bigint,text,bytea,bytea,bytea),
    store_reconciled_crl(uuid,bigint,text,bytea,bytea,bytea,text,bytea)
TO trust_crl_signer;
GRANT SELECT ON crl_publication TO trust_crl_signer;

GRANT EXECUTE ON FUNCTION
    crl_due(uuid),
    overdue_status_changes(uuid),
    abandon_stale_crl_reservations(uuid,interval),
    quarantine_stale_crl_intents(uuid,interval)
TO trust_crl_operator;

GRANT EXECUTE ON FUNCTION register_ca_issuer(uuid,bytea,text) TO trust_ca_admin;

COMMIT;
