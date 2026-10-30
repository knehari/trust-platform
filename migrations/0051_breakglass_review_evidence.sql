-- v0.51 (lab): reviewers re-verify a break-glass use before reviewing it
-- (ADR-0007 §6 and §7, Proposed). LAB ONLY.
-- The database cannot verify ECDSA, so a holder of trust_ca_admin could
-- store a break-glass use with a forged emergency signature while the CA
-- has fewer than two admin keys; until now only the offline audit
-- (trust_audit_verifier) would expose it, and admins reviewed a use
-- without seeing what it enrolled.
-- * breakglass_evidence(ca) (0045, read-only) is also granted to
--   trust_ca_admin. The Rust core shows reviewers the enrolled content and
--   refuses to issue a review challenge for a use whose evidence does not
--   re-verify (PgRevocationStore::breakglass_use_evidence), so a forged use
--   stays open and housekeeping keeps alerting.
-- Apply after 0050 as a superuser.
BEGIN;

GRANT EXECUTE ON FUNCTION breakglass_evidence(uuid) TO trust_ca_admin;

SELECT acknowledge_schema_changes('0051_breakglass_review_evidence');

COMMIT;
