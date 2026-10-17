-- TRUST-89 / C-01: serialize gate enrollment and intent policy checks per issuer.
-- Existing migrations remain immutable. This is a lab concurrency boundary,
-- not authentication, SQL role hardening, or human approval verification.
BEGIN;

ALTER TABLE ca ADD COLUMN policy_gate_epoch BIGINT NOT NULL DEFAULT 0
    CHECK (policy_gate_epoch >= 0);

CREATE FUNCTION serialize_policy_gate_boundary()
RETURNS TRIGGER LANGUAGE plpgsql AS $fn$
BEGIN
    -- A real non-key UPDATE is essential: a lock alone leaves REPEATABLE READ
    -- snapshots stale. Concurrent stale snapshots must fail with SQLSTATE 40001.
    -- The non-key row lock also remains compatible with existing CA foreign keys.
    UPDATE ca SET policy_gate_epoch = policy_gate_epoch + 1
      WHERE ca_id = NEW.ca_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown issuer' USING ERRCODE = '23503';
    END IF;

    IF TG_TABLE_NAME IN ('ca_policy_enforcement', 'ca_dual_signature_enforcement')
       AND EXISTS (SELECT 1 FROM signing_intent WHERE ca_id = NEW.ca_id)
    THEN
        RAISE EXCEPTION 'cannot activate policy gate after signing attempts exist'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $fn$;

-- PostgreSQL executes same-event triggers alphabetically. This fence must run
-- before enforce_approved_policy_on_new_signing_intent and signed_policy_decision_gate.
CREATE TRIGGER aa_serialize_policy_gate_boundary
    BEFORE INSERT ON signing_intent FOR EACH ROW
    EXECUTE FUNCTION serialize_policy_gate_boundary();
CREATE TRIGGER aa_serialize_policy_gate_boundary
    BEFORE INSERT ON ca_policy_enforcement FOR EACH ROW
    EXECUTE FUNCTION serialize_policy_gate_boundary();
CREATE TRIGGER aa_serialize_policy_gate_boundary
    BEFORE INSERT ON ca_dual_signature_enforcement FOR EACH ROW
    EXECUTE FUNCTION serialize_policy_gate_boundary();

REVOKE ALL ON FUNCTION serialize_policy_gate_boundary() FROM PUBLIC;
COMMIT;
