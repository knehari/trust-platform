-- One row per certificate and lowered DNS SAN, so that the history SAN
-- filter reads an index through a security-barrier view instead of
-- unnesting every certificate's array above the barrier
-- (docs/operations/lab-history-san-table.md). Option 2.1 of the scale
-- study; the barrier stays on every management view.
--
-- The table is derived data. It is written only by the trigger below, in
-- the same transaction as the certificate row, from that row alone, so it
-- cannot disagree with certificate.san_dns. Nobody but its owner holds a
-- privilege on it; the reader sees it only through the view.
BEGIN;

CREATE TABLE certificate_san_dns (
    request_id UUID NOT NULL
        REFERENCES certificate (request_id) ON UPDATE CASCADE ON DELETE CASCADE,
    ca_id UUID NOT NULL,
    signed_at TIMESTAMPTZ NOT NULL,
    name_lower TEXT NOT NULL,
    PRIMARY KEY (request_id, name_lower)
);
REVOKE ALL ON certificate_san_dns FROM PUBLIC;

-- Keeps ca_id and signed_at equal to the certificate's, so the view's text
-- time and cursor order are those of management_certificate. lower() is
-- the function the API's previous SAN predicate applied to each name.
CREATE FUNCTION sync_certificate_san_dns() RETURNS trigger
LANGUAGE plpgsql SET search_path = public, pg_temp AS $fn$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        DELETE FROM certificate_san_dns WHERE request_id IN (OLD.request_id, NEW.request_id);
    END IF;
    INSERT INTO certificate_san_dns (request_id, ca_id, signed_at, name_lower)
    SELECT DISTINCT NEW.request_id, NEW.ca_id, NEW.signed_at, lower(entry.name)
    FROM unnest(NEW.san_dns) AS entry(name)
    WHERE entry.name IS NOT NULL;
    RETURN NULL;
END
$fn$;
REVOKE ALL ON FUNCTION sync_certificate_san_dns() FROM PUBLIC;

CREATE TRIGGER certificate_san_dns_sync
AFTER INSERT OR UPDATE OF request_id, ca_id, signed_at, san_dns ON certificate
FOR EACH ROW EXECUTE FUNCTION sync_certificate_san_dns();

INSERT INTO certificate_san_dns (request_id, ca_id, signed_at, name_lower)
SELECT DISTINCT c.request_id, c.ca_id, c.signed_at, lower(entry.name)
FROM certificate c, unnest(c.san_dns) AS entry(name)
WHERE entry.name IS NOT NULL;

-- Same columns, text formats and window as management_certificate.
CREATE VIEW management_certificate_san WITH (security_barrier = true) AS
SELECT ca_id::text AS ca_id, request_id::text AS request_id, name_lower AS san_dns,
       to_char(signed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS signed_at,
       date_trunc('milliseconds', signed_at AT TIME ZONE 'UTC') AS signed_at_window
FROM certificate_san_dns;
GRANT SELECT ON management_certificate_san TO trust_api_reader;

-- Equality on the CA and the name, then a range on the window: the leakproof
-- predicates the API sends through the barrier.
CREATE INDEX certificate_san_dns_lookup ON certificate_san_dns
    ((ca_id::text), name_lower, (date_trunc('milliseconds', signed_at AT TIME ZONE 'UTC')));
-- The second step reads the matched certificates by their text request id.
CREATE INDEX certificate_management_request_text ON certificate ((request_id::text));

COMMIT;
