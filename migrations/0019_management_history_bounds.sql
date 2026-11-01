-- Start a first history page at the authority's own newest (or oldest) row
-- instead of the current time or the CA's creation
-- (docs/operations/lab-history-bounds.md). Since 0016 a page is read in time
-- slices outward from that anchor; when the authority's rows were far from
-- it (a CA that stopped issuing), the slices found nothing and the page fell
-- back to scanning the whole authority. Every management view keeps its
-- barrier, and no planner setting is involved.
--
-- The view computes each bound with a scalar subquery on the base table
-- inside its own definition, where PostgreSQL answers min() and max() with
-- one index probe. It shows the first and last signing and recording time of
-- each authority, which the history views already show.
BEGIN;

CREATE INDEX certificate_management_ca_signed ON certificate (ca_id, signed_at);
CREATE INDEX audit_event_management_ca_recorded ON audit_event (ca_id, recorded_at);

CREATE VIEW management_history_bounds WITH (security_barrier = true) AS
SELECT ca.ca_id::text AS ca_id,
       date_trunc('milliseconds',
           (SELECT max(c.signed_at) FROM certificate c WHERE c.ca_id = ca.ca_id) AT TIME ZONE 'UTC')
           AS newest_signed_window,
       date_trunc('milliseconds',
           (SELECT min(c.signed_at) FROM certificate c WHERE c.ca_id = ca.ca_id) AT TIME ZONE 'UTC')
           AS oldest_signed_window,
       date_trunc('milliseconds',
           (SELECT max(a.recorded_at) FROM audit_event a WHERE a.ca_id = ca.ca_id) AT TIME ZONE 'UTC')
           AS newest_recorded_window,
       date_trunc('milliseconds',
           (SELECT min(a.recorded_at) FROM audit_event a WHERE a.ca_id = ca.ca_id) AT TIME ZONE 'UTC')
           AS oldest_recorded_window
FROM ca;
GRANT SELECT ON management_history_bounds TO trust_api_reader;

COMMIT;
