-- v0.9: negative and positive tests for signer evidence review separation.
-- These fixture digests are NOT actual X.509 or provider attestations.
BEGIN;

INSERT INTO ca(ca_id,display_name,policy_version)
VALUES ('44444444-4444-4444-8444-444444444444','Review Lab CA','v1');

DO $test$
DECLARE
    v_ca UUID := '44444444-4444-4444-8444-444444444444';
    v_request UUID;
    v_observation UUID;
    v_wrong_observation UUID;
    v_evidence BYTEA:=decode(repeat('bb',32),'hex');
    v_cert BYTEA:=decode(repeat('cc',32),'hex');
    v_tbs BYTEA:=decode(repeat('dd',32),'hex');
    v_count BIGINT;
BEGIN
    SELECT r.request_id INTO STRICT v_request FROM create_issuance_request(
       v_ca,'review-test',decode(repeat('ab',32),'hex'),'actor','v1') r;
    PERFORM transition_issuance_request(v_ca,v_request,'RECEIVED','CSR_VALIDATED','actor');
    PERFORM transition_issuance_request(v_ca,v_request,'CSR_VALIDATED','AUTHORIZED','actor');
    PERFORM reserve_issuance_serial(v_ca,v_request,'actor');
    PERFORM create_signing_intent(v_ca,v_request,'actor','lab-key',v_tbs,'v1','lab-op');
    PERFORM mark_signing_uncertain(v_ca,v_request,'actor');

    v_wrong_observation := record_signing_reconciliation_observation(
      v_ca,v_request,'maker','NO_PROVIDER_EVIDENCE',v_evidence);
    BEGIN
      PERFORM propose_reconciliation_review(v_ca,v_request,v_wrong_observation,
          'maker','lab-op',v_tbs,v_cert);
      RAISE EXCEPTION 'no-result evidence incorrectly accepted';
    EXCEPTION WHEN check_violation THEN NULL; END;

    v_observation := record_signing_reconciliation_observation(
      v_ca,v_request,'maker','PROVIDER_RESULT_OBSERVED',v_evidence);
    BEGIN
      PERFORM propose_reconciliation_review(v_ca,v_request,v_observation,
          'maker','other-operation',v_tbs,v_cert);
      RAISE EXCEPTION 'incorrect operation correlation accepted';
    EXCEPTION WHEN check_violation THEN NULL; END;
    BEGIN
      PERFORM propose_reconciliation_review(v_ca,v_request,v_observation,
          'maker','lab-op',decode(repeat('ee',32),'hex'),v_cert);
      RAISE EXCEPTION 'incorrect TBS digest accepted';
    EXCEPTION WHEN check_violation THEN NULL; END;
    BEGIN
      PERFORM propose_reconciliation_review(v_ca,v_request,v_observation,
          'maker','lab-op',v_tbs,decode(repeat('00',32),'hex'));
      RAISE EXCEPTION 'zero certificate digest accepted';
    EXCEPTION WHEN invalid_parameter_value THEN NULL; END;

    IF propose_reconciliation_review(v_ca,v_request,v_observation,'maker',
      'lab-op',v_tbs,v_cert) <> 'PROPOSED' THEN
      RAISE EXCEPTION 'proposal not persisted';
    END IF;

    BEGIN
      PERFORM review_reconciliation_proposal(v_ca,v_request,'maker',v_cert,v_evidence);
      RAISE EXCEPTION 'same-maker checker accepted';
    EXCEPTION WHEN check_violation THEN NULL; END;

    BEGIN
      PERFORM review_reconciliation_proposal(v_ca,v_request,'checker',
           decode(repeat('ff',32),'hex'),v_evidence);
      RAISE EXCEPTION 'changed certificate digest accepted';
    EXCEPTION WHEN check_violation THEN NULL; END;

    BEGIN
      PERFORM review_reconciliation_proposal(v_ca,v_request,'checker',
           v_cert,decode(repeat('ee',32),'hex'));
      RAISE EXCEPTION 'changed evidence digest accepted';
    EXCEPTION WHEN check_violation THEN NULL; END;

    IF review_reconciliation_proposal(v_ca,v_request,'checker',v_cert,v_evidence)
       <> 'REVIEWED_FOR_MANUAL_DISPOSITION'
    THEN RAISE EXCEPTION 'checker review failed'; END IF;

    BEGIN
      PERFORM review_reconciliation_proposal(v_ca,v_request,'different-checker',
           v_cert,v_evidence);
      RAISE EXCEPTION 'duplicate review accepted';
    EXCEPTION WHEN check_violation THEN NULL; END;

    BEGIN
      UPDATE signing_reconciliation_review SET maker_actor='tampered'
      WHERE ca_id=v_ca AND request_id=v_request;
      RAISE EXCEPTION 'maker mutation accepted';
    EXCEPTION WHEN raise_exception THEN
      IF SQLERRM<>'immutable review proposal modified' THEN RAISE; END IF;
    END;

    BEGIN
      DELETE FROM signing_reconciliation_review
      WHERE ca_id=v_ca AND request_id=v_request;
      RAISE EXCEPTION 'review deletion accepted';
    EXCEPTION WHEN raise_exception THEN
      IF SQLERRM<>'review records cannot be deleted' THEN RAISE; END IF;
    END;

    -- Two actors have *reviewed evidence*, but neither issuance nor signing
    -- authorization, completion or publication should be resumed by these APIs.
    IF (SELECT state FROM certificate_request WHERE request_id=v_request)
        <> 'RECONCILIATION_REQUIRED'
      OR (SELECT count(*) FROM certificate WHERE request_id=v_request)<>0
    THEN RAISE EXCEPTION 'maker-checker incorrectly changed issuance state'; END IF;

    SELECT count(*) INTO v_count FROM audit_event
    WHERE request_id=v_request AND event_type IN (
      'signing.reconciliation.proposed','signing.reconciliation.reviewed'
    );
    IF v_count<>2 THEN RAISE EXCEPTION 'unexpected review audit count %',v_count; END IF;
END $test$;
ROLLBACK;
