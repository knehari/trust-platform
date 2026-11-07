-- Server-owned CA reader grants. The API login may read only the projection,
-- never create or alter grants. Apply after 0012 as the migration owner.
BEGIN;

CREATE TABLE management_reader_grant (
    issuer text NOT NULL CHECK (length(issuer) BETWEEN 1 AND 1024),
    subject text NOT NULL CHECK (length(subject) BETWEEN 1 AND 512),
    ca_id uuid NOT NULL REFERENCES ca(ca_id) ON DELETE CASCADE,
    PRIMARY KEY (issuer, subject, ca_id)
);

REVOKE ALL ON management_reader_grant FROM PUBLIC;

CREATE VIEW management_reader_scope WITH (security_barrier = true) AS
SELECT issuer, subject, ca_id::text AS ca_id FROM management_reader_grant;

GRANT SELECT ON management_reader_scope TO trust_api_reader;

COMMIT;
