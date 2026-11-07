-- SQL metadata invariants only. Synthetic certificate bytes below do NOT
-- demonstrate X.509 validity; Rust integration separately verifies real DER.
BEGIN;
INSERT INTO ca(ca_id,display_name,policy_version) VALUES (
    '66666666-6666-4666-8666-666666666666','Policy Draft Trace CI','v1'
);

DO $tests$
DECLARE
    v_ca UUID := '66666666-6666-4666-8666-666666666666';
    v_actor TEXT := 'lab-provenance-operator';
    v_obs UUID;
    v_obs_replay UUID;
    v_draft UUID;
    v_request UUID;
    v_serial BYTEA;
    v_der BYTEA:=decode('302003010203','hex');
    v_root BYTEA:=decode('3011010203040506070809','hex');
    v_spki BYTEA:=decode(repeat('d2',32),'hex');
    v_source BYTEA:=decode(repeat('e3',32),'hex');
    v_cp TEXT:='NOT APPROVED CP DRAFT SECTION 1';
    v_cps TEXT:='NOT APPROVED CPS DRAFT SECTION 1';
    v_oid TEXT:='1.3.6.1.4.1.55555.1.1';
    v_cert_hash BYTEA;
    v_count BIGINT;
BEGIN
    BEGIN
        PERFORM register_ca_public_observation(
            v_ca,v_actor,decode(repeat('11',32),'hex'),v_spki,v_root);
        RAISE EXCEPTION 'fake certificate DER hash accepted';
    EXCEPTION WHEN invalid_parameter_value THEN NULL; END;

    v_obs:=register_ca_public_observation(v_ca,v_actor,digest(v_root,'sha256'),v_spki,v_root);
    v_obs_replay:=register_ca_public_observation(
        v_ca,v_actor,digest(v_root,'sha256'),v_spki,v_root);
    IF v_obs<>v_obs_replay THEN RAISE EXCEPTION 'identical root observation duplicated'; END IF;

    SELECT count(*) INTO v_count FROM audit_event WHERE ca_id=v_ca
        AND event_type='ca.public_certificate.observed';
    IF v_count<>1 THEN RAISE EXCEPTION 'observed duplicate generated audit event'; END IF;

    BEGIN
        PERFORM register_cp_cps_draft(v_ca,v_actor,v_obs,'lab-profile',
            'v2',v_oid,'lab-v1',v_source,v_cp,v_cps,
            digest(convert_to(v_cp,'UTF8'),'sha256'),
            digest(convert_to(v_cps,'UTF8'),'sha256'));
        RAISE EXCEPTION 'policy revision drift allowed';
    EXCEPTION WHEN check_violation THEN NULL; END;

    BEGIN
        PERFORM register_cp_cps_draft(v_ca,v_actor,v_obs,'lab-profile',
            'v1',v_oid,'lab-v1',v_source,v_cp,v_cps,
            decode(repeat('55',32),'hex'),
            digest(convert_to(v_cps,'UTF8'),'sha256'));
        RAISE EXCEPTION 'CP content hash mismatch allowed';
    EXCEPTION WHEN invalid_parameter_value THEN NULL; END;

    v_draft:=register_cp_cps_draft(v_ca,v_actor,v_obs,'lab-profile',
        'v1',v_oid,'lab-v1',v_source,v_cp,v_cps,
        digest(convert_to(v_cp,'UTF8'),'sha256'),
        digest(convert_to(v_cps,'UTF8'),'sha256'));

    BEGIN
        UPDATE cp_cps_draft_snapshot SET state='DRAFT_UNAPPROVED'
        WHERE draft_id=v_draft;
        RAISE EXCEPTION 'mutable draft snapshot';
    EXCEPTION WHEN raise_exception THEN
        IF SQLERRM<>'audit_event records may not be updated or deleted' THEN RAISE; END IF;
    END;

    -- Retrospective linking is rejected before any signed certificate exists.
    SELECT r.request_id INTO STRICT v_request FROM create_issuance_request(
        v_ca,'draft-trace-ci',decode(repeat('13',32),'hex'),v_actor,'v1') r;
    BEGIN
        PERFORM trace_issued_certificate_to_draft(
            v_ca,v_request,v_actor,v_draft,digest(v_der,'sha256'),
            digest(v_root,'sha256'),v_source,
            digest(convert_to(v_cp,'UTF8'),'sha256'),
            digest(convert_to(v_cps,'UTF8'),'sha256'),v_oid);
        RAISE EXCEPTION 'accepted draft trace before issuance';
    EXCEPTION WHEN no_data_found THEN NULL; END;

    PERFORM transition_issuance_request(v_ca,v_request,'RECEIVED','CSR_VALIDATED',v_actor);
    PERFORM transition_issuance_request(v_ca,v_request,'CSR_VALIDATED','AUTHORIZED',v_actor);
    v_serial:=reserve_issuance_serial(v_ca,v_request,v_actor);
    PERFORM create_signing_intent(
        v_ca,v_request,v_actor,'lab-key',decode(repeat('ee',32),'hex'),
        'v1','lab-op-trace');
    v_cert_hash:=digest(v_der,'sha256');
    PERFORM store_signed_certificate(
        v_ca,v_request,v_actor,v_serial,decode(repeat('ee',32),'hex'),
        v_cert_hash,v_der);

    BEGIN
        PERFORM trace_issued_certificate_to_draft(
            v_ca,v_request,v_actor,v_draft,v_cert_hash,
            digest(v_root,'sha256'),v_source,
            digest(convert_to(v_cp,'UTF8'),'sha256'),
            digest(convert_to(v_cps,'UTF8'),'sha256'),'1.3.6.1.4.1.99');
        RAISE EXCEPTION 'OID mismatch permitted';
    EXCEPTION WHEN check_violation THEN NULL; END;

    BEGIN
        PERFORM trace_issued_certificate_to_draft(
            v_ca,v_request,v_actor,v_draft,v_cert_hash,
            digest(v_root,'sha256'),v_source,
            digest(convert_to(v_cp,'UTF8'),'sha256'),
            decode(repeat('11',32),'hex'),v_oid);
        RAISE EXCEPTION 'CPS digest mismatch permitted';
    EXCEPTION WHEN check_violation THEN NULL; END;

    BEGIN
        PERFORM trace_issued_certificate_to_draft(
            v_ca,v_request,v_actor,v_draft,v_cert_hash,
            digest(decode('000011','hex'),'sha256'),v_source,
            digest(convert_to(v_cp,'UTF8'),'sha256'),
            digest(convert_to(v_cps,'UTF8'),'sha256'),v_oid);
        RAISE EXCEPTION 'CA observation substitution accepted';
    EXCEPTION WHEN check_violation THEN NULL; END;

    IF trace_issued_certificate_to_draft(
        v_ca,v_request,v_actor,v_draft,v_cert_hash,
        digest(v_root,'sha256'),v_source,
        digest(convert_to(v_cp,'UTF8'),'sha256'),
        digest(convert_to(v_cps,'UTF8'),'sha256'),v_oid)
        <> 'DRAFT_REFERENCE_ONLY'
    THEN RAISE EXCEPTION 'no draft reference stored'; END IF;

    BEGIN
        PERFORM trace_issued_certificate_to_draft(
            v_ca,v_request,v_actor,v_draft,v_cert_hash,
            digest(v_root,'sha256'),v_source,
            digest(convert_to(v_cp,'UTF8'),'sha256'),
            digest(convert_to(v_cps,'UTF8'),'sha256'),v_oid);
        RAISE EXCEPTION 'duplicate draft reference stored';
    EXCEPTION WHEN unique_violation THEN NULL; END;

    IF (SELECT state FROM certificate_request WHERE request_id=v_request)<>'SIGNED'
       OR (SELECT state FROM cp_cps_draft_snapshot WHERE draft_id=v_draft)<>'DRAFT_UNAPPROVED'
    THEN RAISE EXCEPTION 'approval or issuance state changed unexpectedly'; END IF;

    BEGIN
        DELETE FROM issued_certificate_draft_trace WHERE request_id=v_request;
        RAISE EXCEPTION 'draft trace erased';
    EXCEPTION WHEN raise_exception THEN
        IF SQLERRM<>'audit_event records may not be updated or deleted' THEN RAISE; END IF;
    END;

    SELECT count(*) INTO v_count FROM audit_event WHERE request_id=v_request
        AND event_type='certificate.policy_draft.trace';
    IF v_count<>1 THEN RAISE EXCEPTION 'draft trace audit not exactly once'; END IF;
END
$tests$;
ROLLBACK;
