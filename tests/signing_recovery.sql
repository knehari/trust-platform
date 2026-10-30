-- v0.8: test durable crash quarantine, issuer isolation, idempotence and audit.
BEGIN;
INSERT INTO ca (ca_id,display_name,policy_version) VALUES
('11111111-1111-4111-8111-111111111111','Recovery CA A','v1'),
('22222222-2222-4222-8222-222222222222','Recovery CA B','v1');

DO $tests$
DECLARE
    ca_a UUID := '11111111-1111-4111-8111-111111111111';
    ca_b UUID := '22222222-2222-4222-8222-222222222222';
    req_a UUID;
    req_b UUID;
    req_done UUID;
    reserved BYTEA;
    found_req UUID;
    found_intent UUID;
    found_op TEXT;
    found_key TEXT;
    found_hash BYTEA;
    observation UUID;
    counts BIGINT;
BEGIN
    SELECT r.request_id INTO STRICT req_a FROM create_issuance_request(
        ca_a,'crash-lab-a',decode(repeat('11',32),'hex'),'requester','v1') r;
    PERFORM transition_issuance_request(ca_a,req_a,'RECEIVED','CSR_VALIDATED','requester');
    PERFORM transition_issuance_request(ca_a,req_a,'CSR_VALIDATED','AUTHORIZED','requester');
    reserved := reserve_issuance_serial(ca_a,req_a,'requester');
    PERFORM create_signing_intent(ca_a,req_a,'requester','key-a',
        decode(repeat('ab',32),'hex'),'v1','crash-op-a');

    SELECT r.request_id INTO STRICT req_b FROM create_issuance_request(
        ca_b,'crash-lab-b',decode(repeat('22',32),'hex'),'requester','v1') r;
    PERFORM transition_issuance_request(ca_b,req_b,'RECEIVED','CSR_VALIDATED','requester');
    PERFORM transition_issuance_request(ca_b,req_b,'CSR_VALIDATED','AUTHORIZED','requester');
    PERFORM reserve_issuance_serial(ca_b,req_b,'requester');
    PERFORM create_signing_intent(ca_b,req_b,'requester','key-b',
        decode(repeat('bc',32),'hex'),'v1','crash-op-b');

    -- Completed certificate must NEVER be quarantined.
    SELECT r.request_id INTO STRICT req_done FROM create_issuance_request(
        ca_a,'completed',decode(repeat('33',32),'hex'),'requester','v1') r;
    PERFORM transition_issuance_request(ca_a,req_done,'RECEIVED','CSR_VALIDATED','requester');
    PERFORM transition_issuance_request(ca_a,req_done,'CSR_VALIDATED','AUTHORIZED','requester');
    reserved := reserve_issuance_serial(ca_a,req_done,'requester');
    PERFORM create_signing_intent(ca_a,req_done,'requester','key-done',
        decode(repeat('ef',32),'hex'),'v1','completed-op');
    -- Opaque test bytes exercise the DB contract, NOT cryptographic validation.
    PERFORM store_signed_certificate(ca_a,req_done,'requester',reserved,
        decode(repeat('ef',32),'hex'),digest(decode('123456','hex'),'sha256'),
        decode('123456','hex'));

    BEGIN
        PERFORM record_signing_reconciliation_observation(
            ca_a,req_a,'reviewer','SIGNATURE_POSSIBLE',
            decode(repeat('cc',32),'hex'));
        RAISE EXCEPTION 'evidence written before quarantine';
    EXCEPTION WHEN check_violation THEN NULL; END;

    -- Old cutoff and invalid caller must have no effects.
    SELECT count(*) INTO counts FROM quarantine_stale_signing_intents(
        ca_a,'2000-01-01'::timestamptz,100,'scanner');
    IF counts <> 0 THEN RAISE EXCEPTION 'scan returned non-stale intent'; END IF;
    BEGIN
        PERFORM quarantine_stale_signing_intents(
            ca_a,clock_timestamp()+interval '1 day',100,'scanner');
        RAISE EXCEPTION 'future cutoff accepted';
    EXCEPTION WHEN invalid_parameter_value THEN NULL; END;
    BEGIN
        PERFORM quarantine_stale_signing_intents(ca_a,clock_timestamp(),0,'scanner');
        RAISE EXCEPTION 'zero limit accepted';
    EXCEPTION WHEN invalid_parameter_value THEN NULL; END;

    SELECT q.request_id,q.intent_id,q.operation_ref,q.signer_key_ref,q.tbs_sha256
      INTO STRICT found_req,found_intent,found_op,found_key,found_hash
      FROM quarantine_stale_signing_intents(ca_a,clock_timestamp(),100,'scanner') q;
    IF found_req <> req_a OR found_intent IS NULL OR found_op <> 'crash-op-a'
       OR found_key <> 'key-a'
       OR found_hash <> decode(repeat('ab',32),'hex') THEN
        RAISE EXCEPTION 'recovery correlation corrupted';
    END IF;

    IF (SELECT state FROM certificate_request WHERE request_id=req_a)
        <> 'RECONCILIATION_REQUIRED'
       OR (SELECT outcome FROM signing_intent WHERE request_id=req_a)
        <> 'RECONCILIATION_REQUIRED'
    THEN RAISE EXCEPTION 'stale signing intent was not quarantined'; END IF;

    SELECT count(*) INTO counts FROM quarantine_stale_signing_intents(
        ca_a,clock_timestamp(),100,'scanner');
    IF counts <> 0 THEN RAISE EXCEPTION 'repeat scan not idempotent'; END IF;

    IF (SELECT state FROM certificate_request WHERE request_id=req_done) <> 'SIGNED'
    THEN RAISE EXCEPTION 'completed certificate was changed'; END IF;
    IF (SELECT state FROM certificate_request WHERE request_id=req_b) <> 'SIGNING'
    THEN RAISE EXCEPTION 'other issuer modified'; END IF;

    observation := record_signing_reconciliation_observation(
        ca_a,req_a,'auditor','SIGNATURE_POSSIBLE',decode(repeat('cc',32),'hex'));
    IF observation IS NULL THEN RAISE EXCEPTION 'missing evidence record'; END IF;
    BEGIN
        UPDATE signing_reconciliation_observation
           SET actor_id='tampered' WHERE observation_id=observation;
        RAISE EXCEPTION 'append only observation mutated';
    EXCEPTION WHEN raise_exception THEN
        IF SQLERRM <> 'audit_event records may not be updated or deleted' THEN
            RAISE;
        END IF;
    END;
    BEGIN
        PERFORM record_signing_reconciliation_observation(
            ca_a,req_a,'auditor','PROVIDER_RESULT_OBSERVED',decode(repeat('00',32),'hex'));
        RAISE EXCEPTION 'zero evidence digest accepted';
    EXCEPTION WHEN invalid_parameter_value THEN NULL; END;
    BEGIN
        PERFORM transition_issuance_request(
            ca_a,req_a,'RECONCILIATION_REQUIRED','SIGNING','scanner');
        RAISE EXCEPTION 'unsafe retry permitted';
    EXCEPTION WHEN invalid_parameter_value THEN NULL; END;

    SELECT count(*) INTO counts FROM audit_event WHERE request_id=req_a
      AND event_type='request.transition'
      AND decision='SIGNING -> RECONCILIATION_REQUIRED';
    IF counts <> 1 THEN RAISE EXCEPTION 'quarantine audit event duplicated'; END IF;

    SELECT count(*) INTO counts FROM quarantine_stale_signing_intents(
        ca_b,clock_timestamp(),100,'scanner');
    IF counts <> 1 THEN RAISE EXCEPTION 'second issuer not quarantined'; END IF;
END
$tests$;
ROLLBACK;
