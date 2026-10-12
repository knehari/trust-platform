-- SQL-level invariants. Synthetic signatures are intentionally NOT verified here.
BEGIN;
INSERT INTO ca(ca_id,display_name,policy_version)
VALUES('99999999-9999-4999-8999-999999999999','Signed Policy Receipt CI','v1');
DO $test$
DECLARE
  v_ca UUID:='99999999-9999-4999-8999-999999999999';
  v_root BYTEA:=decode('3003020101','hex');
  v_cp TEXT:='Draft CP v1';v_cps TEXT:='Draft CPS v1';
  v_draft UUID;v_observed UUID;v_approval UUID;
  v_req UUID;v_tbs BYTEA:=decode(repeat('ef',32),'hex');
  v_sig BYTEA:=decode(repeat('a1',70),'hex');
  v_claim BYTEA:=decode(repeat('55',180),'hex');
  v_digest BYTEA:=decode(repeat('77',32),'hex');
  v_nonce BYTEA:=decode(repeat('32',32),'hex');
BEGIN
  v_observed:=register_ca_public_observation(v_ca,'operator',
    digest(v_root,'sha256'),decode(repeat('ab',32),'hex'),v_root);
  v_draft:=register_cp_cps_draft(v_ca,'author',v_observed,
    'lab-server','v1','1.3.6.1.4.1.55555.1.1','v1',
    v_nonce,v_cp,v_cps,
    digest(convert_to(v_cp,'UTF8'),'sha256'),
    digest(convert_to(v_cps,'UTF8'),'sha256'));
  v_approval:=approve_policy_draft_lab(v_ca,v_draft,'maker','checker',
    digest(convert_to(v_cp,'UTF8'),'sha256'),
    digest(convert_to(v_cps,'UTF8'),'sha256'),
    now()-interval '1 hour',now()+interval '1 hour');
  PERFORM activate_ca_policy_gate_lab(v_ca,'operator');
  PERFORM require_dual_signature_policy_lab(v_ca,'operator');

  SELECT r.request_id INTO STRICT v_req FROM create_issuance_request(
    v_ca,'signed-policy-req',v_nonce,'app','v1') r;
  PERFORM transition_issuance_request(v_ca,v_req,'RECEIVED','CSR_VALIDATED','app');
  PERFORM transition_issuance_request(v_ca,v_req,'CSR_VALIDATED','AUTHORIZED','app');
  PERFORM reserve_issuance_serial(v_ca,v_req,'app');
  PERFORM grant_request_approved_policy_lab(
    v_ca,v_req,v_approval,'1.3.6.1.4.1.55555.1.1',v_tbs,'app');

  BEGIN
    PERFORM create_signing_intent(v_ca,v_req,'app','lab-key',v_tbs,'v1','signed-op');
    RAISE EXCEPTION 'unsigned approved policy was allowed to sign';
  EXCEPTION WHEN check_violation THEN NULL; END;

  BEGIN
    PERFORM persist_verified_dual_policy_receipt_lab(
      v_ca,v_approval,v_draft,'maker-key','checker-key',
      v_claim,v_sig,v_sig,v_digest,decode(repeat('ee',32),'hex'),
      digest(convert_to(v_cps,'UTF8'),'sha256'),
      '1.3.6.1.4.1.55555.1.1','v1');
    RAISE EXCEPTION 'tampered CP hash allowed';
  EXCEPTION WHEN check_violation THEN NULL; END;

  PERFORM persist_verified_dual_policy_receipt_lab(
    v_ca,v_approval,v_draft,'maker-key','checker-key',
    v_claim,v_sig,v_sig,v_digest,
    digest(convert_to(v_cp,'UTF8'),'sha256'),
    digest(convert_to(v_cps,'UTF8'),'sha256'),
    '1.3.6.1.4.1.55555.1.1','v1');
  BEGIN
    PERFORM persist_verified_dual_policy_receipt_lab(
      v_ca,v_approval,v_draft,'maker-key','checker-key',
      v_claim,v_sig,v_sig,v_digest,
      digest(convert_to(v_cp,'UTF8'),'sha256'),
      digest(convert_to(v_cps,'UTF8'),'sha256'),
      '1.3.6.1.4.1.55555.1.1','v1');
    RAISE EXCEPTION 'duplicate proof replay allowed';
  EXCEPTION WHEN unique_violation THEN NULL; END;

  PERFORM create_signing_intent(v_ca,v_req,'app','lab-key',v_tbs,'v1','signed-op');
  IF (SELECT state FROM certificate_request WHERE request_id=v_req)<>'SIGNING'
  THEN RAISE EXCEPTION 'approved signature gate did not admit intent'; END IF;

  BEGIN
    DELETE FROM policy_dual_signature_receipt WHERE approval_id=v_approval;
    RAISE EXCEPTION 'deleted immutable receipt';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM<>'audit_event records may not be updated or deleted' THEN RAISE; END IF;
  END;
  BEGIN
    PERFORM require_dual_signature_policy_lab(v_ca,'operator');
    RAISE EXCEPTION 'retroactive gate activation was allowed';
  EXCEPTION WHEN check_violation THEN NULL; END;
END $test$;
ROLLBACK;
