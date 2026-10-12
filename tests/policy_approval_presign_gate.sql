-- Lab governance SQL contract, synthetic DER only. Rust must independently
-- validate the REAL TBS OID before granting authorization in any deployment.
BEGIN;
INSERT INTO ca(ca_id,display_name,policy_version)
VALUES('77777777-7777-4777-8777-777777777777','Policy Approval Gate Lab CA','v1');

DO $lab$
DECLARE
    v_ca UUID:='77777777-7777-4777-8777-777777777777';
    v_obs UUID; v_draft UUID; v_approved UUID;
    v_root BYTEA:=decode('3003020101','hex');
    v_cp TEXT:='Lab CP DRAFT — unapproved until separate operation';
    v_cps TEXT:='Lab CPS DRAFT — not proof of deployed practice';
    v_cp_hash BYTEA;
    v_cps_hash BYTEA;
    v_tbs BYTEA:=decode(repeat('aa',32),'hex');
    v_request UUID; v_req2 UUID; v_req3 UUID; v_serial BYTEA;
    v_result TEXT; v_events BIGINT;
BEGIN
    v_cp_hash:=digest(convert_to(v_cp,'UTF8'),'sha256');
    v_cps_hash:=digest(convert_to(v_cps,'UTF8'),'sha256');
    v_obs:=register_ca_public_observation(v_ca,'ca-observer',
        digest(v_root,'sha256'),decode(repeat('ef',32),'hex'),v_root);
    v_draft:=register_cp_cps_draft(v_ca,'draft-preparer',v_obs,
        'lab-server','v1','1.3.6.1.4.1.55555.1.1','edition-1',
        decode(repeat('da',32),'hex'),v_cp,v_cps,v_cp_hash,v_cps_hash);

    BEGIN
        PERFORM approve_policy_draft_lab(v_ca,v_draft,'maker','maker',
            v_cp_hash,v_cps_hash,now()-interval '1 hour',now()+interval '1 hour');
        RAISE EXCEPTION 'self-approved CP/CPS accepted';
    EXCEPTION WHEN invalid_parameter_value THEN NULL; END;
    BEGIN
        PERFORM approve_policy_draft_lab(v_ca,v_draft,'maker','checker',
            decode(repeat('77',32),'hex'),v_cps_hash,
            now()-interval '1 hour',now()+interval '1 hour');
        RAISE EXCEPTION 'forged CP hash approval accepted';
    EXCEPTION WHEN check_violation THEN NULL; END;

    v_approved:=approve_policy_draft_lab(v_ca,v_draft,
        'lab-preparer','lab-independent-checker',
        v_cp_hash,v_cps_hash,now()-interval '1 hour',now()+interval '1 hour');
    v_result:=activate_ca_policy_gate_lab(v_ca,'security-operator');
    IF v_result<>'ENFORCE_ALL_NEW_SIGNING_INTENTS'
    THEN RAISE EXCEPTION 'gate was not activated'; END IF;

    SELECT r.request_id INTO STRICT v_request FROM create_issuance_request(
        v_ca,'gated-issue-1',decode(repeat('01',32),'hex'),'lab-actor','v1') r;
    PERFORM transition_issuance_request(v_ca,v_request,'RECEIVED','CSR_VALIDATED','lab-actor');
    PERFORM transition_issuance_request(v_ca,v_request,'CSR_VALIDATED','AUTHORIZED','lab-actor');
    v_serial:=reserve_issuance_serial(v_ca,v_request,'lab-actor');

    -- Can't sign even through old create_signing_intent without a policy grant.
    BEGIN
        PERFORM create_signing_intent(v_ca,v_request,'lab-actor','lab-key',
            v_tbs,'v1','gated-op-1');
        RAISE EXCEPTION 'unchecked signing allowed';
    EXCEPTION WHEN check_violation THEN NULL; END;

    BEGIN
        PERFORM grant_request_approved_policy_lab(v_ca,v_request,v_approved,
            '1.3.6.1.4.1.55555.1.99',v_tbs,'lab-actor');
        RAISE EXCEPTION 'wrong certificate policy OID grant accepted';
    EXCEPTION WHEN check_violation THEN NULL; END;

    IF grant_request_approved_policy_lab(
        v_ca,v_request,v_approved,'1.3.6.1.4.1.55555.1.1',
        v_tbs,'lab-actor')<>'GRANTED_FOR_THIS_TBS_ONLY'
    THEN RAISE EXCEPTION 'effective grant missing'; END IF;

    BEGIN
        PERFORM create_signing_intent(v_ca,v_request,'lab-actor','lab-key',
            decode(repeat('b1',32),'hex'),'v1','gated-op-1');
        RAISE EXCEPTION 'different TBS allowed after approval';
    EXCEPTION WHEN check_violation THEN NULL; END;

    PERFORM create_signing_intent(v_ca,v_request,'lab-actor','lab-key',
        v_tbs,'v1','gated-op-1');

    BEGIN
        UPDATE approved_policy_edition SET effective_until=now()-interval '5 minutes'
        WHERE approval_id=v_approved;
        RAISE EXCEPTION 'approved document mutated';
    EXCEPTION WHEN raise_exception THEN
        IF SQLERRM<>'audit_event records may not be updated or deleted' THEN RAISE; END IF;
    END;

    SELECT r.request_id INTO STRICT v_req2 FROM create_issuance_request(
        v_ca,'gated-issue-2',decode(repeat('02',32),'hex'),'lab-actor','v1') r;
    PERFORM transition_issuance_request(v_ca,v_req2,'RECEIVED','CSR_VALIDATED','lab-actor');
    PERFORM transition_issuance_request(v_ca,v_req2,'CSR_VALIDATED','AUTHORIZED','lab-actor');
    PERFORM reserve_issuance_serial(v_ca,v_req2,'lab-actor');
    BEGIN
        PERFORM activate_ca_policy_gate_lab(v_ca,'security-operator');
        RAISE EXCEPTION 're-activation after signing allowed';
    EXCEPTION WHEN check_violation THEN NULL; END;

    SELECT count(*) INTO v_events FROM audit_event
    WHERE ca_id=v_ca AND event_type='policy.edition.lab_approved';
    IF v_events<>1 THEN RAISE EXCEPTION 'approval audit count not one'; END IF;
    SELECT count(*) INTO v_events FROM audit_event
    WHERE request_id=v_request AND event_type='policy.issuance.lab_grant';
    IF v_events<>1 THEN RAISE EXCEPTION 'grant audit count not one'; END IF;
    IF (SELECT state FROM certificate_request WHERE request_id=v_request)<>'SIGNING'
    THEN RAISE EXCEPTION 'unexpected signed issuance state'; END IF;
END $lab$;
ROLLBACK;
