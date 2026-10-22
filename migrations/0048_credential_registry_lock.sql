-- v0.48 (lab): serialise enrolment across the three credential registries
-- (ADR-0007 §3 and §6, Proposed). LAB ONLY.
-- The registries stay disjoint by triggers that read the other registries
-- before an insert: keys are never shared (0037, 0045), a person is never
-- both officer and admin on a CA (0037) nor custodian and signer (0046).
-- Those reads only see committed rows, so two concurrent enrolments (for
-- example a custodian and an admin key for the same person) could both
-- pass and both commit.
-- * lock_credential_registries(): a BEFORE INSERT trigger on
--   officer_credential, ca_admin_credential and ca_breakglass_credential
--   that takes one transaction-scoped advisory lock shared by all three.
--   Its trigger names sort before the checking triggers, so the checks run
--   after the lock, on a fresh snapshot that includes the other enrolment.
--   Keys are unique across CAs, so the lock is global, not per CA;
--   enrolments are rare.
-- Apply after 0047 as a superuser.
BEGIN;

CREATE FUNCTION lock_credential_registries() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('credential_registries', 0));
    RETURN NEW;
END $fn$;
ALTER FUNCTION lock_credential_registries() OWNER TO trust_revocation_owner;
ALTER FUNCTION lock_credential_registries() SET search_path = pg_catalog, public, pg_temp;
REVOKE ALL ON FUNCTION lock_credential_registries() FROM PUBLIC;

-- Triggers of one event fire in name order: "_0_" sorts before the checks.
CREATE TRIGGER officer_credential_0_registry_lock
    BEFORE INSERT ON officer_credential
    FOR EACH ROW EXECUTE FUNCTION lock_credential_registries();
CREATE TRIGGER ca_admin_credential_0_registry_lock
    BEFORE INSERT ON ca_admin_credential
    FOR EACH ROW EXECUTE FUNCTION lock_credential_registries();
CREATE TRIGGER ca_breakglass_credential_0_registry_lock
    BEFORE INSERT ON ca_breakglass_credential
    FOR EACH ROW EXECUTE FUNCTION lock_credential_registries();

SELECT acknowledge_schema_changes('0048_credential_registry_lock');

COMMIT;
