-- v1.4 laboratory CP/CPS approval registry with opt-in pre-sign SQL gate.
-- This is NOT an authenticated policy-authority service, OID ownership proof,
-- or HSM-proven effective policy. All actors here are caller-supplied strings.
BEGIN;

CREATE TABLE ca_policy_enforcement (
    ca_id UUID PRIMARY KEY REFERENCES ca(ca_id),
    enforced BOOLEAN NOT NULL DEFAULT TRUE CHECK(enforced),
    activated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TRIGGER immutable_policy_enforcement
    BEFORE UPDATE OR DELETE ON ca_policy_enforcement
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

CREATE TABLE approved_policy_edition (
    approval_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ca_id UUID NOT NULL,
    draft_id UUID NOT NULL,
    policy_oid TEXT NOT NULL CHECK(length(policy_oid) BETWEEN 3 AND 128),
    policy_revision TEXT NOT NULL CHECK(length(policy_revision) BETWEEN 1 AND 128),
    cp_sha256 BYTEA NOT NULL CHECK(octet_length(cp_sha256)=32),
    cps_sha256 BYTEA NOT NULL CHECK(octet_length(cps_sha256)=32),
    proposer TEXT NOT NULL CHECK(length(proposer) BETWEEN 1 AND 256),
    approver TEXT NOT NULL CHECK(length(approver) BETWEEN 1 AND 256),
    effective_from TIMESTAMPTZ NOT NULL,
    effective_until TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK(proposer<>approver),
    CHECK(effective_until>effective_from),
    FOREIGN KEY(ca_id,draft_id) REFERENCES cp_cps_draft_snapshot(ca_id,draft_id),
    UNIQUE(ca_id,approval_id),
    UNIQUE(ca_id,draft_id),
    UNIQUE(ca_id,policy_revision,policy_oid,effective_from)
);
CREATE TRIGGER immutable_approved_policy
    BEFORE UPDATE OR DELETE ON approved_policy_edition
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

CREATE TABLE issuance_policy_grant (
    ca_id UUID NOT NULL,
    request_id UUID NOT NULL,
    approval_id UUID NOT NULL,
    document_oid TEXT NOT NULL CHECK(length(document_oid) BETWEEN 3 AND 128),
    tbs_sha256 BYTEA NOT NULL CHECK(octet_length(tbs_sha256)=32),
    issued_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(ca_id,request_id),
    FOREIGN KEY(ca_id,request_id) REFERENCES certificate_request(ca_id,request_id),
    FOREIGN KEY(ca_id,approval_id) REFERENCES approved_policy_edition(ca_id,approval_id)
);
CREATE TRIGGER immutable_issuance_policy_grant
    BEFORE UPDATE OR DELETE ON issuance_policy_grant
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

-- Separate an explicit proposer from a different approver, and pin the exact
-- original draft hashes. Caller strings are NOT authenticated roles.
CREATE FUNCTION approve_policy_draft_lab(
    p_ca UUID,p_draft UUID,p_proposer TEXT,p_approver TEXT,
    p_cp_sha256 BYTEA,p_cps_sha256 BYTEA,
    p_from TIMESTAMPTZ,p_until TIMESTAMPTZ
) RETURNS UUID LANGUAGE plpgsql AS $fn$
DECLARE v_draft cp_cps_draft_snapshot%ROWTYPE;
        v_approval UUID;
BEGIN
    IF p_proposer IS NULL OR p_approver IS NULL
       OR length(p_proposer) NOT BETWEEN 1 AND 256
       OR length(p_approver) NOT BETWEEN 1 AND 256
       OR p_proposer=p_approver
       OR p_cp_sha256 IS NULL OR octet_length(p_cp_sha256)<>32
       OR p_cps_sha256 IS NULL OR octet_length(p_cps_sha256)<>32
       OR p_from IS NULL OR p_until IS NULL OR p_until<=p_from
    THEN RAISE EXCEPTION 'invalid lab policy approval actors or time window'
        USING ERRCODE='22023'; END IF;
    SELECT * INTO STRICT v_draft FROM cp_cps_draft_snapshot
        WHERE ca_id=p_ca AND draft_id=p_draft;
    IF v_draft.cp_sha256<>p_cp_sha256 OR v_draft.cps_sha256<>p_cps_sha256
    THEN RAISE EXCEPTION 'approval hash does not match immutable draft'
        USING ERRCODE='23514'; END IF;

    INSERT INTO approved_policy_edition(
        ca_id,draft_id,policy_oid,policy_revision,cp_sha256,cps_sha256,
        proposer,approver,effective_from,effective_until
    ) VALUES (
        p_ca,p_draft,v_draft.policy_oid,v_draft.policy_revision,
        p_cp_sha256,p_cps_sha256,p_proposer,p_approver,p_from,p_until
    ) RETURNING approval_id INTO v_approval;
    INSERT INTO audit_event(
        event_id,ca_id,actor_id,event_type,decision,policy_version
    ) VALUES (
        gen_random_uuid(),p_ca,p_approver,'policy.edition.lab_approved',
        'SEPARATE_ACTOR_STRINGS_NOT_AUTHENTICATED',v_draft.policy_revision
    );
    RETURN v_approval;
END $fn$;

-- Persistent issuer-granted intent. This function is required only for CAs
-- explicitly enrolled in ca_policy_enforcement. Date is checked by database.
-- Caller MUST have already verified actual X509 TBS certificatePolicies OID
-- (not merely asserted it) in a server-authenticated crypto validator.
CREATE FUNCTION grant_request_approved_policy_lab(
    p_ca UUID,p_request UUID,p_approval UUID,
    p_policy_oid TEXT,p_tbs_sha256 BYTEA,p_actor TEXT
) RETURNS TEXT LANGUAGE plpgsql AS $fn$
DECLARE v_state TEXT;
        v_policy TEXT;
        v_approved approved_policy_edition%ROWTYPE;
BEGIN
    IF p_actor IS NULL OR length(p_actor) NOT BETWEEN 1 AND 256
       OR p_tbs_sha256 IS NULL OR octet_length(p_tbs_sha256)<>32
       OR p_policy_oid IS NULL OR length(p_policy_oid) NOT BETWEEN 3 AND 128
    THEN RAISE EXCEPTION 'invalid policy grant arguments' USING ERRCODE='22023'; END IF;

    SELECT cr.state,cr.policy_version INTO STRICT v_state,v_policy
    FROM certificate_request cr WHERE cr.ca_id=p_ca AND cr.request_id=p_request
    FOR UPDATE;
    SELECT * INTO STRICT v_approved FROM approved_policy_edition
    WHERE ca_id=p_ca AND approval_id=p_approval;
    IF v_state<>'SERIAL_RESERVED'
       OR v_policy<>v_approved.policy_revision
       OR v_approved.policy_oid<>p_policy_oid
       OR NOT (clock_timestamp()>=v_approved.effective_from
           AND clock_timestamp()<v_approved.effective_until)
       OR NOT EXISTS (SELECT 1 FROM ca_policy_enforcement e WHERE e.ca_id=p_ca)
    THEN RAISE EXCEPTION 'no effective policy for issuer/request'
        USING ERRCODE='23514'; END IF;

    INSERT INTO issuance_policy_grant(
        ca_id,request_id,approval_id,document_oid,tbs_sha256
    ) VALUES (p_ca,p_request,p_approval,p_policy_oid,p_tbs_sha256);

    INSERT INTO audit_event(
        event_id,ca_id,request_id,actor_id,event_type,decision,policy_version
    ) VALUES (
        gen_random_uuid(),p_ca,p_request,p_actor,
        'policy.issuance.lab_grant','GRANTED_FOR_THIS_TBS_ONLY',v_policy
    );
    RETURN 'GRANTED_FOR_THIS_TBS_ONLY';
END $fn$;

-- Opt-in, server-side fail-closed check on EACH immutable signing attempt.
-- This is inside the same transaction as create_signing_intent and holds
-- a row lock on certificate_request (already acquired by that function).
CREATE FUNCTION enforce_approved_policy_before_signing_intent()
RETURNS TRIGGER LANGUAGE plpgsql AS $fn$
DECLARE v_approval approved_policy_edition%ROWTYPE;
        v_grant issuance_policy_grant%ROWTYPE;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM ca_policy_enforcement e WHERE e.ca_id=NEW.ca_id)
    THEN RETURN NEW; END IF;

    SELECT * INTO STRICT v_grant
      FROM issuance_policy_grant
      WHERE ca_id=NEW.ca_id AND request_id=NEW.request_id;
    SELECT * INTO STRICT v_approval FROM approved_policy_edition
      WHERE ca_id=NEW.ca_id AND approval_id=v_grant.approval_id;
    IF v_grant.tbs_sha256<>NEW.tbs_sha256
       OR v_approval.policy_revision<>NEW.policy_revision
       OR v_grant.document_oid<>v_approval.policy_oid
       OR clock_timestamp()<v_approval.effective_from
       OR clock_timestamp()>=v_approval.effective_until
    THEN RAISE EXCEPTION 'signing blocked: absent/mismatched/expired lab policy'
        USING ERRCODE='23514'; END IF;
    RETURN NEW;
EXCEPTION WHEN no_data_found THEN
    RAISE EXCEPTION 'signing blocked: no approved policy grant'
        USING ERRCODE='23514';
END $fn$;
CREATE TRIGGER enforce_approved_policy_on_new_signing_intent
    BEFORE INSERT ON signing_intent FOR EACH ROW
    EXECUTE FUNCTION enforce_approved_policy_before_signing_intent();

-- Activation is intentionally one way for the lab DB. The CA may be opted in
-- only after any existing issuance attempt is completed in the test environment.
CREATE FUNCTION activate_ca_policy_gate_lab(p_ca UUID,p_actor TEXT)
RETURNS TEXT LANGUAGE plpgsql AS $fn$
BEGIN
    IF p_actor IS NULL OR length(p_actor) NOT BETWEEN 1 AND 256
    THEN RAISE EXCEPTION 'missing activation actor' USING ERRCODE='22023'; END IF;
    PERFORM 1 FROM ca WHERE ca_id=p_ca FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'unknown issuer' USING ERRCODE='23503'; END IF;
    IF EXISTS(
        SELECT 1 FROM signing_intent si WHERE si.ca_id=p_ca
    ) THEN RAISE EXCEPTION 'lab gate cannot be enabled after signing attempts exist'
        USING ERRCODE='23514'; END IF;
    INSERT INTO ca_policy_enforcement(ca_id) VALUES(p_ca);
    INSERT INTO audit_event(event_id,ca_id,actor_id,event_type,decision)
    VALUES(gen_random_uuid(),p_ca,p_actor,'policy.lab_gate.activated',
        'ENFORCE_ALL_NEW_SIGNING_INTENTS');
    RETURN 'ENFORCE_ALL_NEW_SIGNING_INTENTS';
END $fn$;

REVOKE ALL ON FUNCTION approve_policy_draft_lab(
    UUID,UUID,TEXT,TEXT,BYTEA,BYTEA,TIMESTAMPTZ,TIMESTAMPTZ
) FROM PUBLIC;
REVOKE ALL ON FUNCTION grant_request_approved_policy_lab(
    UUID,UUID,UUID,TEXT,BYTEA,TEXT
) FROM PUBLIC;
REVOKE ALL ON FUNCTION activate_ca_policy_gate_lab(UUID,TEXT) FROM PUBLIC;
COMMIT;
