-- CI-only synthetic metadata. Apply to a fresh Compose laboratory volume after
-- the one-record API smoke, never to a real certificate database.
DO $seed$ BEGIN
  IF (SELECT count(*) FROM certificate WHERE ca_id='eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee') <> 1 THEN
    RAISE EXCEPTION 'browser fixture requires the fresh Compose laboratory database';
  END IF;
END $seed$;

INSERT INTO certificate_request(request_id,ca_id,idempotency_key,csr_sha256,requester_id,policy_version,state)
SELECT ('11111111-1111-4111-8111-' || lpad(to_hex(i),12,'0'))::uuid,
       'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'::uuid,
       'browser-e2e-' || i, decode(repeat('01',32),'hex'), 'compose-fixture','v1','SIGNED'
FROM generate_series(3,102) AS i;

INSERT INTO serial_reservation(ca_id,serial_der_content,request_id)
SELECT 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'::uuid,
       decode(lpad(to_hex(65536+i),6,'0'),'hex'),
       ('11111111-1111-4111-8111-' || lpad(to_hex(i),12,'0'))::uuid
FROM generate_series(3,102) AS i;

INSERT INTO certificate(ca_id,serial_der_content,request_id,fingerprint_sha256,certificate_der,signed_at,subject_cn)
SELECT 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'::uuid,
       decode(lpad(to_hex(65536+i),6,'0'),'hex'),
       ('11111111-1111-4111-8111-' || lpad(to_hex(i),12,'0'))::uuid,
       decode(repeat('02',32),'hex'), decode('3000','hex'),
       '2026-10-01T12:00:00Z'::timestamptz + i * interval '1 minute',
       'paged-' || lpad(i::text,4,'0') || '.lab.invalid'
FROM generate_series(3,102) AS i;

INSERT INTO audit_event(event_id,ca_id,actor_id,event_type,decision,policy_version,recorded_at)
SELECT ('33333333-3333-4333-8333-' || lpad(to_hex(i),12,'0'))::uuid,
       'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'::uuid,
       'private-compose-actor','certificate.signed','allow','v1',
       '2026-10-01T12:00:00Z'::timestamptz + i * interval '1 minute'
FROM generate_series(3,102) AS i;
