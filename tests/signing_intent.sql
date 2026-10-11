-- Signing-intent contract regression (not a cryptographic X.509 validation).
BEGIN;
INSERT INTO ca(ca_id,display_name,policy_version) VALUES
('dddddddd-dddd-4ddd-8ddd-dddddddddddd','Signing Intent CI','v1');
DO $test$
DECLARE
  v_ca UUID:='dddddddd-dddd-4ddd-8ddd-dddddddddddd';
  v_req UUID;
  v_req2 UUID;
  v_serial BYTEA;
  v_serial2 BYTEA;
  v_intent UUID;
  v_again UUID;
  v_replayed BOOLEAN;
  v_events BIGINT;
BEGIN
  SELECT r.request_id INTO STRICT v_req FROM create_issuance_request(
    v_ca,'intent-test',decode(repeat('ab',32),'hex'),'test-actor','v1') r;
  PERFORM transition_issuance_request(v_ca,v_req,'RECEIVED','CSR_VALIDATED','test-actor');
  PERFORM transition_issuance_request(v_ca,v_req,'CSR_VALIDATED','AUTHORIZED','test-actor');
  v_serial:=reserve_issuance_serial(v_ca,v_req,'test-actor');
  SELECT i.intent_id,i.replay INTO STRICT v_intent,v_replayed
  FROM create_signing_intent(v_ca,v_req,'test-actor','lab-key',
    decode(repeat('ee',32),'hex'),'v1','op-1') i;
  IF v_replayed OR v_intent IS NULL THEN RAISE EXCEPTION 'new intent not created'; END IF;
  IF (SELECT state FROM certificate_request WHERE request_id=v_req) <> 'SIGNING'
    THEN RAISE EXCEPTION 'signing state not persisted'; END IF;
  SELECT i.intent_id,i.replay INTO STRICT v_again,v_replayed FROM create_signing_intent(
    v_ca,v_req,'test-actor','lab-key',decode(repeat('ee',32),'hex'),'v1','op-1') i;
  IF v_intent<>v_again OR NOT v_replayed
    THEN RAISE EXCEPTION 'intent replay corrupted'; END IF;

  BEGIN
    PERFORM create_signing_intent(v_ca,v_req,'test-actor','other-key',
      decode(repeat('ee',32),'hex'),'v1','op-1');
    RAISE EXCEPTION 'modified intent permitted';
  EXCEPTION WHEN unique_violation THEN NULL; END;
  BEGIN
    UPDATE signing_intent SET signer_key_ref='tampered' WHERE request_id=v_req;
    RAISE EXCEPTION 'immutable intent changed';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM <> 'immutable signing-intent fields changed' THEN RAISE; END IF;
  END;

  -- Wrong serial cannot be stored, even with a matching arbitrary DER blob.
  BEGIN
    PERFORM store_signed_certificate(v_ca,v_req,'test-actor',
       decode('aa','hex'),decode(repeat('ee',32),'hex'),
       digest(decode('010203','hex'),'sha256'),decode('010203','hex'));
    RAISE EXCEPTION 'mismatched serial accepted';
  EXCEPTION WHEN check_violation THEN NULL; END;

  -- A signer timeout must remain ambiguous, never automatically retry.
  IF mark_signing_uncertain(v_ca,v_req,'test-actor') <> 'RECONCILIATION_REQUIRED'
    THEN RAISE EXCEPTION 'uncertain not persisted'; END IF;
  IF mark_signing_uncertain(v_ca,v_req,'test-actor') <> 'RECONCILIATION_REQUIRED'
    THEN RAISE EXCEPTION 'uncertain replay changed state'; END IF;
  BEGIN
    PERFORM transition_issuance_request(v_ca,v_req,
       'RECONCILIATION_REQUIRED','SIGNING','test-actor');
    RAISE EXCEPTION 'blind re-sign allowed';
  EXCEPTION WHEN invalid_parameter_value THEN NULL; END;

  SELECT r.request_id INTO STRICT v_req2 FROM create_issuance_request(
    v_ca,'intent-test-2',decode(repeat('cd',32),'hex'),'test-actor','v1') r;
  PERFORM transition_issuance_request(v_ca,v_req2,'RECEIVED','CSR_VALIDATED','test-actor');
  PERFORM transition_issuance_request(v_ca,v_req2,'CSR_VALIDATED','AUTHORIZED','test-actor');
  v_serial2:=reserve_issuance_serial(v_ca,v_req2,'test-actor');

  BEGIN
    PERFORM create_signing_intent(v_ca,v_req2,'test-actor','lab-key',
        decode(repeat('dd',32),'hex'),'v1','op-1');
    RAISE EXCEPTION 'operation ref reused';
  EXCEPTION WHEN unique_violation THEN NULL; END;
  PERFORM create_signing_intent(v_ca,v_req2,'test-actor','lab-key',
    decode(repeat('dd',32),'hex'),'v1','op-2');

  -- This deliberately tests persistence constraints ONLY, not X.509 validation.
  IF store_signed_certificate(v_ca,v_req2,'test-actor',v_serial2,
      decode(repeat('dd',32),'hex'),
      digest(decode('010203','hex'),'sha256'),decode('010203','hex')) <> 'SIGNED'
    THEN RAISE EXCEPTION 'signed record not stored'; END IF;
  IF (SELECT outcome FROM signing_intent WHERE request_id=v_req2) <> 'CERTIFICATE_STORED'
    THEN RAISE EXCEPTION 'intent outcome not stored'; END IF;
  BEGIN
    PERFORM store_signed_certificate(v_ca,v_req2,'test-actor',v_serial2,
      decode(repeat('dd',32),'hex'),
      digest(decode('010203','hex'),'sha256'),decode('010203','hex'));
    RAISE EXCEPTION 'duplicate certificate persisted';
  EXCEPTION WHEN check_violation THEN NULL; END;
  IF (SELECT count(*) FROM certificate WHERE request_id=v_req2) <> 1
    THEN RAISE EXCEPTION 'certificate duplicate'; END IF;

  SELECT count(*) INTO v_events FROM audit_event
   WHERE request_id=v_req AND event_type='signing.intent';
  IF v_events <> 1 THEN RAISE EXCEPTION 'intent replay duplicated audit'; END IF;
END $test$;
ROLLBACK;
