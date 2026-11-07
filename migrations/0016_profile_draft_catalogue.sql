-- Inert, immutable proposals for later certificate-profile governance.
-- No profile in this table is approved, active or usable for issuance.
BEGIN;

CREATE TABLE certificate_profile_draft (
    ca_id UUID NOT NULL REFERENCES ca(ca_id),
    profile_id TEXT NOT NULL CHECK (
        length(profile_id) BETWEEN 2 AND 64
        AND profile_id ~ '^[a-z][a-z0-9-]+$'
    ),
    revision INTEGER NOT NULL CHECK (revision BETWEEN 1 AND 1000000),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 255),
    policy_version TEXT NOT NULL CHECK (length(policy_version) BETWEEN 1 AND 128),
    max_validity_days INTEGER NOT NULL CHECK (max_validity_days BETWEEN 1 AND 825),
    max_dns_sans INTEGER NOT NULL CHECK (max_dns_sans BETWEEN 1 AND 100),
    proposed_dns_zones TEXT[] NOT NULL CHECK (
        cardinality(proposed_dns_zones) BETWEEN 1 AND 32
        AND array_position(proposed_dns_zones, NULL) IS NULL
    ),
    proposed_signature_suites TEXT[] NOT NULL CHECK (
        cardinality(proposed_signature_suites) BETWEEN 1 AND 16
        AND array_position(proposed_signature_suites, NULL) IS NULL
    ),
    created_by TEXT NOT NULL CHECK (length(created_by) BETWEEN 1 AND 256),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (ca_id, profile_id, revision)
);

REVOKE ALL ON certificate_profile_draft FROM PUBLIC;

CREATE FUNCTION prevent_profile_draft_change() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    RAISE EXCEPTION 'profile draft revisions are immutable';
END
$fn$;

REVOKE ALL ON FUNCTION prevent_profile_draft_change() FROM PUBLIC;

CREATE TRIGGER prevent_profile_draft_update
    BEFORE UPDATE OR DELETE ON certificate_profile_draft
    FOR EACH ROW EXECUTE FUNCTION prevent_profile_draft_change();

CREATE VIEW management_profile_draft WITH (security_barrier = true) AS
SELECT ca_id::text AS ca_id, profile_id, revision, display_name,
       policy_version, max_validity_days, max_dns_sans,
       proposed_dns_zones, proposed_signature_suites,
       created_by,
       to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at
FROM certificate_profile_draft;

GRANT SELECT ON management_profile_draft TO trust_api_reader;

COMMIT;
