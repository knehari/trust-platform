-- Compare pre-management fixture values across additive management migrations.
-- Nullable certificate metadata added in 0014–0015 is checked separately.
SELECT CASE WHEN
    (SELECT count(*) FROM ca) = 2 AND
    (SELECT count(*) FROM certificate_request) = 1 AND
    (SELECT count(*) FROM serial_reservation) = 1 AND
    (SELECT count(*) FROM certificate) = 1 AND
    (SELECT count(*) FROM audit_event) = 1
THEN md5(jsonb_build_object(
    'ca', (SELECT jsonb_agg(to_jsonb(c) ORDER BY c.ca_id) FROM ca c),
    'requests', (SELECT jsonb_agg(to_jsonb(r) ORDER BY r.request_id) FROM certificate_request r),
    'serials', (SELECT jsonb_agg(to_jsonb(s) ORDER BY s.ca_id, s.serial_der_content) FROM serial_reservation s),
    'certificates', (SELECT jsonb_agg(to_jsonb(c) - 'subject_cn' - 'not_before_utc' - 'not_after_utc' - 'san_dns' ORDER BY c.ca_id, c.serial_der_content) FROM certificate c),
    'audit', (SELECT jsonb_agg(to_jsonb(a) ORDER BY a.event_id) FROM audit_event a)
)::text) END;
