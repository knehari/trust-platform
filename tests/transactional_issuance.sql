-- PostgreSQL 16 regression suite for transactional issuance primitives.
-- Executed with ON_ERROR_STOP in a disposable database; rolls back all sample data.
BEGIN;

INSERT INTO ca (ca_id, display_name, policy_version) VALUES
 ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'Tx CA A', 'v1'),
 ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'Tx CA B', 'v1');

DO $test$
DECLARE
    v_ca UUID := 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
    v_other_ca UUID := 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
    v_id UUID;
    v_replay UUID;
    v_serial BYTEA;
    v_again BYTEA;
    v_second UUID;
    v_diff_issuer UUID;
    v_event_count BIGINT;
BEGIN
    SELECT r.request_id INTO STRICT v_id FROM create_issuance_request(
        v_ca, 'idempotency-key-1', decode(repeat('ab',32),'hex'), 'actor1', 'v1'
    ) r WHERE NOT r.replay;

    -- Exact replay must return the same request and not append a duplicate event.
    SELECT r.request_id INTO STRICT v_replay FROM create_issuance_request(
        v_ca, 'idempotency-key-1', decode(repeat('ab',32),'hex'), 'actor1', 'v1'
    ) r WHERE r.replay;
    IF v_id <> v_replay THEN RAISE EXCEPTION 'replay returned different request'; END IF;
    SELECT count(*) INTO v_event_count FROM audit_event WHERE request_id = v_id;
    IF v_event_count <> 1 THEN RAISE EXCEPTION 'replay duplicated audit'; END IF;

    -- Same key and differing CSR digest must be rejected.
    BEGIN
      PERFORM create_issuance_request(
        v_ca, 'idempotency-key-1', decode(repeat('cd',32),'hex'), 'actor1', 'v1'
      );
      RAISE EXCEPTION 'conflicting idempotency accepted';
    EXCEPTION WHEN unique_violation THEN NULL; END;

    -- Unauthorized reservation from RECEIVED must be refused.
    BEGIN
      PERFORM reserve_issuance_serial(v_ca, v_id, 'actor1');
      RAISE EXCEPTION 'serial allocated without authorization';
    EXCEPTION WHEN check_violation THEN NULL; END;

    -- Cannot skip CSR validation or authorization.
    BEGIN
      PERFORM transition_issuance_request(v_ca, v_id, 'RECEIVED','SIGNING','actor1');
      RAISE EXCEPTION 'transition skip accepted';
    EXCEPTION WHEN invalid_parameter_value THEN NULL; END;

    PERFORM transition_issuance_request(v_ca, v_id, 'RECEIVED','CSR_VALIDATED','actor1');
    PERFORM transition_issuance_request(v_ca, v_id, 'CSR_VALIDATED','AUTHORIZED','actor1');
    v_serial := reserve_issuance_serial(v_ca, v_id, 'actor1');
    IF octet_length(v_serial) <> 16 OR get_byte(v_serial,0) < 64
       OR get_byte(v_serial,0) >= 128 THEN
        RAISE EXCEPTION 'invalid random serial representation';
    END IF;
    SELECT sr.serial_der_content INTO STRICT v_again
    FROM serial_reservation sr WHERE sr.ca_id=v_ca AND sr.request_id=v_id;
    IF v_again <> v_serial THEN RAISE EXCEPTION 'reservation was not persisted'; END IF;
    IF (SELECT state FROM certificate_request WHERE request_id=v_id) <> 'SERIAL_RESERVED' THEN
        RAISE EXCEPTION 'state/reservation not atomic';
    END IF;
    -- Same request and same caller replay remains idempotent.
    IF reserve_issuance_serial(v_ca, v_id, 'actor1') <> v_serial THEN
        RAISE EXCEPTION 'replayed serial is different';
    END IF;

    -- Two independent new requests for same CA produce distinct serials.
    SELECT r.request_id INTO STRICT v_second FROM create_issuance_request(
        v_ca,'idempotency-key-2',decode(repeat('ef',32),'hex'),'actor1','v1'
    ) r;
    PERFORM transition_issuance_request(v_ca,v_second,'RECEIVED','CSR_VALIDATED','actor1');
    PERFORM transition_issuance_request(v_ca,v_second,'CSR_VALIDATED','AUTHORIZED','actor1');
    IF reserve_issuance_serial(v_ca,v_second,'actor1')=v_serial THEN
        RAISE EXCEPTION 'two requests allocated the same serial';
    END IF;

    -- Same idempotency key on different CA is a separate request.
    SELECT r.request_id INTO STRICT v_diff_issuer FROM create_issuance_request(
        v_other_ca,'idempotency-key-1',decode(repeat('ab',32),'hex'),'actor1','v1'
    ) r;
    IF v_id=v_diff_issuer THEN RAISE EXCEPTION 'cross-CA request aliasing'; END IF;

    -- Signing -> Signed transition requires a real persisted certificate.
    PERFORM transition_issuance_request(v_ca,v_id,'SERIAL_RESERVED','SIGNING','actor1');
    BEGIN
      PERFORM transition_issuance_request(v_ca,v_id,'SIGNING','SIGNED','actor1');
      RAISE EXCEPTION 'signed without certificate persisted';
    EXCEPTION WHEN check_violation THEN NULL; END;
    PERFORM transition_issuance_request(v_ca,v_id,'SIGNING','RECONCILIATION_REQUIRED','actor1');
    -- Ambiguous outcome may never blindly transition to SIGNING again.
    BEGIN
      PERFORM transition_issuance_request(v_ca,v_id,'RECONCILIATION_REQUIRED','SIGNING','actor1');
      RAISE EXCEPTION 'unsafe blind retry accepted';
    EXCEPTION WHEN invalid_parameter_value THEN NULL; END;

    -- Audit transitions and intake are recorded in the same transaction.
    SELECT count(*) INTO v_event_count FROM audit_event WHERE request_id=v_id;
    IF v_event_count <> 6 THEN
        RAISE EXCEPTION 'expected 6 durable audit events, got %',v_event_count;
    END IF;
END
$test$;

ROLLBACK;
