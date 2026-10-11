-- v1.3: immutable lab CA public certificate observations and CP/CPS draft trace.
-- This is post-issuance INVESTIGATION provenance, not approved policy binding.
-- Database functions cannot verify X509 signatures or certify deployed CA setup.
BEGIN;

CREATE TABLE ca_public_observation (
    observation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ca_id UUID NOT NULL REFERENCES ca(ca_id),
    ca_certificate_sha256 BYTEA NOT NULL CHECK (
        octet_length(ca_certificate_sha256)=32
        AND ca_certificate_sha256<>decode(repeat('00',32),'hex')
    ),
    ca_spki_sha256 BYTEA NOT NULL CHECK (
        octet_length(ca_spki_sha256)=32
        AND ca_spki_sha256<>decode(repeat('00',32),'hex')
    ),
    ca_certificate_der BYTEA NOT NULL CHECK(
        octet_length(ca_certificate_der) BETWEEN 1 AND 65536
        AND digest(ca_certificate_der,'sha256')=ca_certificate_sha256
    ),
    observed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE(ca_id,observation_id),
    UNIQUE(ca_id,ca_certificate_sha256)
);
CREATE TRIGGER ca_observation_immutable BEFORE UPDATE OR DELETE
    ON ca_public_observation FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_modification();

CREATE TABLE cp_cps_draft_snapshot (
    draft_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ca_id UUID NOT NULL,
    observation_id UUID NOT NULL,
    policy_profile TEXT NOT NULL CHECK(length(policy_profile) BETWEEN 1 AND 128),
    policy_revision TEXT NOT NULL CHECK(length(policy_revision) BETWEEN 1 AND 128),
    policy_oid TEXT NOT NULL CHECK(length(policy_oid) BETWEEN 3 AND 128),
    document_edition TEXT NOT NULL CHECK(length(document_edition) BETWEEN 1 AND 128),
    source_sha256 BYTEA NOT NULL CHECK(
        octet_length(source_sha256)=32
        AND source_sha256<>decode(repeat('00',32),'hex')
    ),
    cp_markdown TEXT NOT NULL CHECK(length(cp_markdown) BETWEEN 1 AND 65536),
    cps_markdown TEXT NOT NULL CHECK(length(cps_markdown) BETWEEN 1 AND 65536),
    cp_sha256 BYTEA NOT NULL CHECK(
        octet_length(cp_sha256)=32
        AND digest(convert_to(cp_markdown,'UTF8'),'sha256')=cp_sha256
    ),
    cps_sha256 BYTEA NOT NULL CHECK(
        octet_length(cps_sha256)=32
        AND digest(convert_to(cps_markdown,'UTF8'),'sha256')=cps_sha256
    ),
    state TEXT NOT NULL DEFAULT 'DRAFT_UNAPPROVED'
        CHECK(state='DRAFT_UNAPPROVED'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY(ca_id,observation_id)
        REFERENCES ca_public_observation(ca_id,observation_id),
    UNIQUE(ca_id,draft_id),
    UNIQUE(ca_id,observation_id,policy_revision,document_edition,source_sha256)
);
CREATE TRIGGER cp_cps_draft_immutable BEFORE UPDATE OR DELETE
    ON cp_cps_draft_snapshot FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_modification();

-- A retrospective provenance/reference. No published CP/CPS effective
-- date, authority signature or actual qualified controls are asserted.
ALTER TABLE certificate ADD CONSTRAINT cert_issuer_request_unique UNIQUE(ca_id,request_id);

CREATE TABLE issued_certificate_draft_trace (
    ca_id UUID NOT NULL,
    request_id UUID NOT NULL,
    draft_id UUID NOT NULL,
    certificate_sha256 BYTEA NOT NULL CHECK(octet_length(certificate_sha256)=32),
    trace_state TEXT NOT NULL DEFAULT 'DRAFT_REFERENCE_ONLY'
        CHECK(trace_state='DRAFT_REFERENCE_ONLY'),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(ca_id,request_id),
    FOREIGN KEY(ca_id,request_id) REFERENCES certificate(ca_id,request_id),
    FOREIGN KEY(ca_id,draft_id) REFERENCES cp_cps_draft_snapshot(ca_id,draft_id)
);
CREATE TRIGGER issued_draft_trace_immutable BEFORE UPDATE OR DELETE
    ON issued_certificate_draft_trace FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_modification();

-- The caller must ALREADY have verified a pinned CA root certificate against
-- a trusted fingerprint. This SQL routine only stores consistent metadata.
CREATE FUNCTION register_ca_public_observation(
    p_ca UUID, p_actor TEXT,
    p_ca_certificate_sha256 BYTEA, p_ca_spki_sha256 BYTEA,
    p_ca_certificate_der BYTEA
) RETURNS UUID
LANGUAGE plpgsql AS $fn$
DECLARE
    v_observation UUID;
BEGIN
    IF p_ca IS NULL OR p_actor IS NULL OR length(p_actor) NOT BETWEEN 1 AND 256
       OR p_ca_certificate_sha256 IS NULL OR octet_length(p_ca_certificate_sha256)<>32
       OR p_ca_spki_sha256 IS NULL OR octet_length(p_ca_spki_sha256)<>32
       OR p_ca_certificate_der IS NULL OR octet_length(p_ca_certificate_der) NOT BETWEEN 1 AND 65536
       OR digest(p_ca_certificate_der,'sha256')<>p_ca_certificate_sha256
       OR p_ca_certificate_sha256=decode(repeat('00',32),'hex')
       OR p_ca_spki_sha256=decode(repeat('00',32),'hex')
    THEN RAISE EXCEPTION 'invalid CA public certificate observation'
        USING ERRCODE='22023'; END IF;

    INSERT INTO ca_public_observation(
        ca_id,ca_certificate_sha256,ca_spki_sha256,ca_certificate_der
    ) VALUES (p_ca,p_ca_certificate_sha256,p_ca_spki_sha256,p_ca_certificate_der)
    ON CONFLICT(ca_id,ca_certificate_sha256) DO NOTHING
    RETURNING observation_id INTO v_observation;

    IF v_observation IS NULL THEN
        SELECT observation_id INTO STRICT v_observation
        FROM ca_public_observation
        WHERE ca_id=p_ca AND ca_certificate_sha256=p_ca_certificate_sha256
          AND ca_spki_sha256=p_ca_spki_sha256
          AND ca_certificate_der=p_ca_certificate_der;
    ELSE
        INSERT INTO audit_event(
            event_id,ca_id,actor_id,event_type,decision
        ) VALUES (
            gen_random_uuid(),p_ca,p_actor,'ca.public_certificate.observed',
            'pinned_der_observation_asserted_by_caller'
        );
    END IF;
    RETURN v_observation;
END $fn$;

-- The documents remain DRAFT_UNAPPROVED. A real approval workflow must be
-- separately designed and must not relabel this immutable draft as approved.
CREATE FUNCTION register_cp_cps_draft(
    p_ca UUID,p_actor TEXT,p_observation_id UUID,
    p_profile TEXT,p_policy_revision TEXT,p_policy_oid TEXT,p_edition TEXT,
    p_source_sha256 BYTEA,p_cp_text TEXT,p_cps_text TEXT,
    p_cp_sha256 BYTEA,p_cps_sha256 BYTEA
) RETURNS UUID
LANGUAGE plpgsql AS $fn$
DECLARE
    v_ca_policy TEXT;
    v_draft UUID;
BEGIN
    IF p_actor IS NULL OR length(p_actor) NOT BETWEEN 1 AND 256
       OR p_profile IS NULL OR length(p_profile) NOT BETWEEN 1 AND 128
       OR p_policy_revision IS NULL OR length(p_policy_revision) NOT BETWEEN 1 AND 128
       OR p_policy_oid IS NULL OR length(p_policy_oid) NOT BETWEEN 3 AND 128
       OR p_edition IS NULL OR length(p_edition) NOT BETWEEN 1 AND 128
       OR p_source_sha256 IS NULL OR octet_length(p_source_sha256)<>32
       OR p_source_sha256=decode(repeat('00',32),'hex')
       OR p_cp_text IS NULL OR length(p_cp_text) NOT BETWEEN 1 AND 65536
       OR p_cps_text IS NULL OR length(p_cps_text) NOT BETWEEN 1 AND 65536
       OR p_cp_sha256 IS NULL OR octet_length(p_cp_sha256)<>32
       OR p_cps_sha256 IS NULL OR octet_length(p_cps_sha256)<>32
       OR digest(convert_to(p_cp_text,'UTF8'),'sha256')<>p_cp_sha256
       OR digest(convert_to(p_cps_text,'UTF8'),'sha256')<>p_cps_sha256
    THEN RAISE EXCEPTION 'invalid CP/CPS draft input' USING ERRCODE='22023'; END IF;
    SELECT c.policy_version INTO STRICT v_ca_policy FROM ca c WHERE c.ca_id=p_ca;
    IF v_ca_policy<>p_policy_revision
       OR NOT EXISTS(SELECT 1 FROM ca_public_observation o
                     WHERE o.ca_id=p_ca AND o.observation_id=p_observation_id)
    THEN RAISE EXCEPTION 'draft must match observed issuer and policy version'
        USING ERRCODE='23514'; END IF;

    INSERT INTO cp_cps_draft_snapshot(
        ca_id,observation_id,policy_profile,policy_revision,policy_oid,
        document_edition,source_sha256,cp_markdown,cps_markdown,cp_sha256,cps_sha256
    ) VALUES (
        p_ca,p_observation_id,p_profile,p_policy_revision,p_policy_oid,
        p_edition,p_source_sha256,p_cp_text,p_cps_text,p_cp_sha256,p_cps_sha256
    ) RETURNING draft_id INTO v_draft;

    INSERT INTO audit_event(event_id,ca_id,actor_id,event_type,decision,policy_version)
    VALUES (gen_random_uuid(),p_ca,p_actor,'cp_cps.draft.snapshot',
            'DRAFT_UNAPPROVED',p_policy_revision);
    RETURN v_draft;
END $fn$;

-- Lab caller MUST cryptographically verify the leaf cert's exact journaled
-- TBS, serial, signature, issuer pin, policy OID and content before this call.
-- PostgreSQL alone cannot parse arbitrary X.509 and is not a security boundary.
CREATE FUNCTION trace_issued_certificate_to_draft(
    p_ca UUID,p_request UUID,p_actor TEXT,p_draft UUID,p_cert_sha256 BYTEA,
    p_ca_sha256 BYTEA,p_source_sha256 BYTEA,p_cp_sha256 BYTEA,
    p_cps_sha256 BYTEA,p_policy_oid TEXT
) RETURNS TEXT
LANGUAGE plpgsql AS $fn$
DECLARE
    v_state TEXT;
    v_policy TEXT;
    v_actual_cert_hash BYTEA;
    v_draft_policy TEXT;
    v_observed_ca_sha256 BYTEA;
    v_source_sha256 BYTEA;
    v_cp_sha256 BYTEA;
    v_cps_sha256 BYTEA;
    v_policy_oid TEXT;
BEGIN
    IF p_actor IS NULL OR length(p_actor) NOT BETWEEN 1 AND 256
       OR p_cert_sha256 IS NULL OR octet_length(p_cert_sha256)<>32
       OR p_ca_sha256 IS NULL OR octet_length(p_ca_sha256)<>32
       OR p_source_sha256 IS NULL OR octet_length(p_source_sha256)<>32
       OR p_cp_sha256 IS NULL OR octet_length(p_cp_sha256)<>32
       OR p_cps_sha256 IS NULL OR octet_length(p_cps_sha256)<>32
       OR p_policy_oid IS NULL OR length(p_policy_oid) NOT BETWEEN 3 AND 128
    THEN RAISE EXCEPTION 'invalid draft trace request' USING ERRCODE='22023'; END IF;

    SELECT cr.state,cr.policy_version INTO STRICT v_state,v_policy
    FROM certificate_request cr
    WHERE cr.ca_id=p_ca AND cr.request_id=p_request FOR UPDATE;
    SELECT cert.fingerprint_sha256 INTO STRICT v_actual_cert_hash
    FROM certificate cert
    WHERE cert.ca_id=p_ca AND cert.request_id=p_request;
    SELECT p.policy_revision, o.ca_certificate_sha256,
           p.source_sha256,p.cp_sha256,p.cps_sha256,p.policy_oid
    INTO STRICT v_draft_policy,v_observed_ca_sha256,
        v_source_sha256,v_cp_sha256,v_cps_sha256,v_policy_oid
    FROM cp_cps_draft_snapshot p
    JOIN ca_public_observation o ON o.ca_id=p.ca_id AND o.observation_id=p.observation_id
    WHERE p.ca_id=p_ca AND p.draft_id=p_draft;

    IF v_state NOT IN ('SIGNED','PUBLISHED')
       OR v_actual_cert_hash<>p_cert_sha256
       OR v_policy<>v_draft_policy
       OR v_observed_ca_sha256<>p_ca_sha256
       OR v_source_sha256<>p_source_sha256
       OR v_cp_sha256<>p_cp_sha256
       OR v_cps_sha256<>p_cps_sha256
       OR v_policy_oid<>p_policy_oid
       OR NOT EXISTS(
           SELECT 1 FROM signing_intent si
           WHERE si.ca_id=p_ca AND si.request_id=p_request
             AND si.policy_revision=v_draft_policy
             AND si.outcome='CERTIFICATE_STORED'
       )
    THEN RAISE EXCEPTION 'certificate or policy draft correlation failure'
        USING ERRCODE='23514'; END IF;

    INSERT INTO issued_certificate_draft_trace(
        ca_id,request_id,draft_id,certificate_sha256
    ) VALUES(p_ca,p_request,p_draft,p_cert_sha256);
    INSERT INTO audit_event(
        event_id,ca_id,request_id,actor_id,event_type,decision,policy_version
    ) VALUES (
        gen_random_uuid(),p_ca,p_request,p_actor,
        'certificate.policy_draft.trace','DRAFT_REFERENCE_ONLY',v_draft_policy
    );
    RETURN 'DRAFT_REFERENCE_ONLY';
END $fn$;

REVOKE ALL ON FUNCTION register_ca_public_observation(UUID,TEXT,BYTEA,BYTEA,BYTEA) FROM PUBLIC;
REVOKE ALL ON FUNCTION register_cp_cps_draft(
    UUID,TEXT,UUID,TEXT,TEXT,TEXT,TEXT,BYTEA,TEXT,TEXT,BYTEA,BYTEA
) FROM PUBLIC;
REVOKE ALL ON FUNCTION trace_issued_certificate_to_draft(
    UUID,UUID,TEXT,UUID,BYTEA,BYTEA,BYTEA,BYTEA,BYTEA,TEXT
) FROM PUBLIC;
COMMIT;
