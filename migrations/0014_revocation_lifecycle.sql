-- v0.14 (lab): maker-checker certificate status lifecycle (suspend / release /
-- revoke), per-CA revocation policy and server-managed revocation officer
-- grants. LAB ONLY. The database does not authenticate (issuer, subject)
-- identities; a trusted identity adapter must supply them. No CRL is produced
-- here. A definitive revocation (reason <> 6) is irreversible for every caller.
-- Apply after 0013 as the migration owner.
BEGIN;

-- Per-CA policy. A CA without a row uses the defaults below with target
-- RFC5280 and no suspension (see certificate status functions).
CREATE TABLE ca_revocation_policy (
    ca_id UUID PRIMARY KEY REFERENCES ca(ca_id),
    conformance_target TEXT NOT NULL DEFAULT 'RFC5280' CHECK (
        conformance_target IN ('RFC5280','ETSI_EN_319_411_1','ETSI_EN_319_411_2')
    ),
    suspension_allowed BOOLEAN NOT NULL DEFAULT false,
    suspension_cps_ref TEXT CHECK (length(suspension_cps_ref) BETWEEN 1 AND 256),
    crl_validity INTERVAL NOT NULL DEFAULT INTERVAL '7 days' CHECK (
        crl_validity BETWEEN INTERVAL '1 hour' AND INTERVAL '90 days'
    ),
    crl_issue_interval INTERVAL NOT NULL DEFAULT INTERVAL '24 hours' CHECK (
        crl_issue_interval BETWEEN INTERVAL '1 hour' AND INTERVAL '7 days'
    ),
    status_publication_deadline INTERVAL NOT NULL DEFAULT INTERVAL '24 hours' CHECK (
        status_publication_deadline BETWEEN INTERVAL '1 hour' AND INTERVAL '7 days'
    ),
    -- Fixed to true in this slice: pruning needs a stored not_after.
    keep_expired_on_crl BOOLEAN NOT NULL DEFAULT true CHECK (keep_expired_on_crl),
    CONSTRAINT crl_validity_covers_interval CHECK (crl_validity >= crl_issue_interval),
    CONSTRAINT etsi_publication_limits CHECK (
        conformance_target = 'RFC5280'
        OR (crl_issue_interval <= INTERVAL '24 hours'
            AND status_publication_deadline <= INTERVAL '24 hours')
    ),
    CONSTRAINT etsi_suspension_needs_cps_ref CHECK (
        conformance_target = 'RFC5280'
        OR NOT suspension_allowed
        OR suspension_cps_ref IS NOT NULL
    ),
    CONSTRAINT etsi_411_2_keeps_expired CHECK (
        conformance_target <> 'ETSI_EN_319_411_2' OR keep_expired_on_crl
    )
);

-- Server-owned like management_reader_grant: no API write path.
CREATE TABLE revocation_officer_grant (
    issuer TEXT NOT NULL CHECK (length(issuer) BETWEEN 1 AND 1024),
    subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 512),
    ca_id UUID NOT NULL REFERENCES ca(ca_id) ON DELETE CASCADE,
    PRIMARY KEY (issuer, subject, ca_id)
);

-- Append-only proposal/decision history.
CREATE TABLE certificate_status_change (
    change_id UUID PRIMARY KEY,
    ca_id UUID NOT NULL,
    serial_der_content BYTEA NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('SUSPEND','RELEASE','REVOKE')),
    reason_code SMALLINT CHECK (reason_code IN (0,1,2,3,4,5,6,9,10)),
    invalidity_at TIMESTAMPTZ,
    maker_issuer TEXT NOT NULL CHECK (length(maker_issuer) BETWEEN 1 AND 1024),
    maker_subject TEXT NOT NULL CHECK (length(maker_subject) BETWEEN 1 AND 512),
    checker_issuer TEXT CHECK (length(checker_issuer) BETWEEN 1 AND 1024),
    checker_subject TEXT CHECK (length(checker_subject) BETWEEN 1 AND 512),
    status TEXT NOT NULL DEFAULT 'PROPOSED'
        CHECK (status IN ('PROPOSED','APPROVED','REJECTED','WITHDRAWN')),
    proposed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    decided_at TIMESTAMPTZ,
    FOREIGN KEY (ca_id, serial_der_content)
        REFERENCES certificate(ca_id, serial_der_content),
    -- reason_code is NULL exactly for RELEASE; SUSPEND uses 6, REVOKE never 6.
    CONSTRAINT status_change_reason_by_action CHECK (
        (action = 'RELEASE' AND reason_code IS NULL AND invalidity_at IS NULL)
        OR (action = 'SUSPEND' AND reason_code = 6)
        OR (action = 'REVOKE' AND reason_code IS NOT NULL AND reason_code <> 6)
    ),
    CONSTRAINT status_change_decision_fields CHECK (
        (status = 'PROPOSED'
            AND checker_issuer IS NULL AND checker_subject IS NULL
            AND decided_at IS NULL)
        OR (status IN ('APPROVED','REJECTED')
            AND checker_issuer IS NOT NULL AND checker_subject IS NOT NULL
            AND decided_at IS NOT NULL
            AND (checker_issuer, checker_subject) <> (maker_issuer, maker_subject))
        OR (status = 'WITHDRAWN'
            AND checker_issuer IS NULL AND checker_subject IS NULL
            AND decided_at IS NOT NULL)
    )
);

CREATE UNIQUE INDEX certificate_status_change_one_open
    ON certificate_status_change (ca_id, serial_der_content)
    WHERE status = 'PROPOSED';

CREATE FUNCTION guard_certificate_status_change() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    IF TG_OP IN ('DELETE','TRUNCATE') THEN
        RAISE EXCEPTION 'certificate_status_change is append-only'
          USING ERRCODE='23514';
    END IF;
    IF OLD.status <> 'PROPOSED'
       OR NEW.status NOT IN ('APPROVED','REJECTED','WITHDRAWN')
       OR (NEW.change_id, NEW.ca_id, NEW.serial_der_content, NEW.action,
           NEW.reason_code, NEW.invalidity_at, NEW.maker_issuer,
           NEW.maker_subject, NEW.proposed_at)
          IS DISTINCT FROM
          (OLD.change_id, OLD.ca_id, OLD.serial_der_content, OLD.action,
           OLD.reason_code, OLD.invalidity_at, OLD.maker_issuer,
           OLD.maker_subject, OLD.proposed_at)
    THEN
        RAISE EXCEPTION 'only PROPOSED may become APPROVED, REJECTED or WITHDRAWN'
          USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $fn$;

CREATE TRIGGER certificate_status_change_guard
    BEFORE UPDATE OR DELETE ON certificate_status_change
    FOR EACH ROW EXECUTE FUNCTION guard_certificate_status_change();
CREATE TRIGGER certificate_status_change_no_truncate
    BEFORE TRUNCATE ON certificate_status_change
    FOR EACH STATEMENT EXECUTE FUNCTION guard_certificate_status_change();

-- revocation (0001) is the current state: one row per revoked/suspended
-- certificate. Empty in every environment before this migration.
ALTER TABLE revocation
    ADD COLUMN change_id UUID REFERENCES certificate_status_change(change_id);
-- 0001 still allows 7 and 8 on a direct INSERT; 7 is unassigned and 8
-- (removeFromCRL) is never a stored state.
ALTER TABLE revocation
    ADD CONSTRAINT revocation_reason_code_accepted
    CHECK (reason_code IN (0,1,2,3,4,5,6,9,10));

CREATE FUNCTION guard_revocation() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    IF TG_OP IN ('TRUNCATE') THEN
        RAISE EXCEPTION 'revocation may not be truncated' USING ERRCODE='23514';
    ELSIF TG_OP = 'DELETE' THEN
        IF OLD.reason_code <> 6 THEN
            RAISE EXCEPTION 'definitive revocation is irreversible'
              USING ERRCODE='23514';
        END IF;
        RETURN OLD;
    END IF;
    IF OLD.reason_code <> 6
       OR NEW.reason_code NOT IN (0,1,2,3,4,5,9,10)
       OR NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
       OR NEW.ca_id IS DISTINCT FROM OLD.ca_id
       OR NEW.serial_der_content IS DISTINCT FROM OLD.serial_der_content
    THEN
        RAISE EXCEPTION 'revocation may only change from hold to a definitive reason'
          USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $fn$;

CREATE TRIGGER revocation_guard
    BEFORE UPDATE OR DELETE ON revocation
    FOR EACH ROW EXECUTE FUNCTION guard_revocation();
CREATE TRIGGER revocation_no_truncate
    BEFORE TRUNCATE ON revocation
    FOR EACH STATEMENT EXECUTE FUNCTION guard_revocation();

REVOKE ALL ON ca_revocation_policy, revocation_officer_grant,
    certificate_status_change FROM PUBLIC;

-- Current status. No row = VALID; reason 6 = SUSPENDED; otherwise REVOKED.
CREATE FUNCTION certificate_status(p_ca UUID, p_serial BYTEA)
RETURNS TEXT
LANGUAGE plpgsql AS $fn$
DECLARE
    v_reason SMALLINT;
BEGIN
    IF p_ca IS NULL OR p_serial IS NULL OR NOT EXISTS (
        SELECT 1 FROM certificate c
        WHERE c.ca_id = p_ca AND c.serial_der_content = p_serial
    ) THEN
        RAISE EXCEPTION 'unknown certificate' USING ERRCODE='22023';
    END IF;
    SELECT r.reason_code INTO v_reason FROM revocation r
    WHERE r.ca_id = p_ca AND r.serial_der_content = p_serial;
    IF NOT FOUND THEN RETURN 'VALID'; END IF;
    IF v_reason = 6 THEN RETURN 'SUSPENDED'; END IF;
    RETURN 'REVOKED';
END $fn$;

CREATE FUNCTION propose_certificate_status_change(
    p_ca UUID, p_serial BYTEA, p_action TEXT, p_reason SMALLINT,
    p_invalidity TIMESTAMPTZ, p_maker_issuer TEXT, p_maker_subject TEXT
)
RETURNS UUID
LANGUAGE plpgsql AS $fn$
DECLARE
    v_request UUID;
    v_status TEXT;
    v_suspension BOOLEAN;
    v_change UUID := gen_random_uuid();
BEGIN
    IF p_ca IS NULL OR p_serial IS NULL
       OR p_maker_issuer IS NULL OR length(p_maker_issuer) NOT BETWEEN 1 AND 1024
       OR p_maker_subject IS NULL OR length(p_maker_subject) NOT BETWEEN 1 AND 512
       OR p_action IS NULL OR p_action NOT IN ('SUSPEND','RELEASE','REVOKE')
       OR (p_action = 'RELEASE' AND (p_reason IS NOT NULL OR p_invalidity IS NOT NULL))
       OR (p_action <> 'RELEASE' AND (p_reason IS NULL
            OR p_reason NOT IN (0,1,2,3,4,5,6,9,10)))
    THEN
        RAISE EXCEPTION 'invalid status change proposal input' USING ERRCODE='22023';
    END IF;
    -- FOR SHARE: a concurrent grant deletion waits for this decision.
    PERFORM 1 FROM revocation_officer_grant g
    WHERE g.issuer = p_maker_issuer AND g.subject = p_maker_subject
      AND g.ca_id = p_ca FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'actor holds no revocation officer grant for this CA'
          USING ERRCODE='42501';
    END IF;

    SELECT c.request_id INTO v_request FROM certificate c
    WHERE c.ca_id = p_ca AND c.serial_der_content = p_serial FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown certificate' USING ERRCODE='22023';
    END IF;
    v_status := certificate_status(p_ca, p_serial);

    IF (p_action = 'SUSPEND' AND (v_status <> 'VALID' OR p_reason <> 6))
       OR (p_action = 'RELEASE' AND v_status <> 'SUSPENDED')
       OR (p_action = 'REVOKE' AND (v_status = 'REVOKED' OR p_reason = 6))
    THEN
        RAISE EXCEPTION 'status change % not valid for % certificate',
            p_action, v_status USING ERRCODE='23514';
    END IF;
    IF p_action = 'SUSPEND' THEN
        SELECT suspension_allowed INTO v_suspension FROM ca_revocation_policy
        WHERE ca_id = p_ca FOR SHARE;
        IF NOT COALESCE(v_suspension, false) THEN
            RAISE EXCEPTION 'suspension is not enabled for this CA'
              USING ERRCODE='23514';
        END IF;
    END IF;
    IF EXISTS (SELECT 1 FROM certificate_status_change s
               WHERE s.ca_id = p_ca AND s.serial_der_content = p_serial
                 AND s.status = 'PROPOSED') THEN
        RAISE EXCEPTION 'an open status change already exists' USING ERRCODE='23514';
    END IF;

    INSERT INTO certificate_status_change(
        change_id, ca_id, serial_der_content, action, reason_code,
        invalidity_at, maker_issuer, maker_subject
    ) VALUES (
        v_change, p_ca, p_serial, p_action, p_reason, p_invalidity,
        p_maker_issuer, p_maker_subject
    );
    INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), p_ca, v_request,
            p_maker_issuer || '|' || p_maker_subject,
            'certificate.status.proposed', p_action || ':pending_approval');
    RETURN v_change;
END $fn$;

CREATE FUNCTION approve_certificate_status_change(
    p_change UUID, p_checker_issuer TEXT, p_checker_subject TEXT,
    p_expected_action TEXT, p_expected_reason SMALLINT
)
RETURNS TEXT
LANGUAGE plpgsql AS $fn$
DECLARE
    v_ca UUID;
    v_serial BYTEA;
    v_chg certificate_status_change%ROWTYPE;
    v_request UUID;
    v_status TEXT;
    v_suspension BOOLEAN;
    v_now TIMESTAMPTZ;
BEGIN
    IF p_change IS NULL
       OR p_checker_issuer IS NULL OR length(p_checker_issuer) NOT BETWEEN 1 AND 1024
       OR p_checker_subject IS NULL OR length(p_checker_subject) NOT BETWEEN 1 AND 512
       OR p_expected_action IS NULL
    THEN
        RAISE EXCEPTION 'invalid approval input' USING ERRCODE='22023';
    END IF;
    SELECT s.ca_id, s.serial_der_content INTO v_ca, v_serial
    FROM certificate_status_change s WHERE s.change_id = p_change;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown status change' USING ERRCODE='22023';
    END IF;
    -- Lock order: certificate, then change (same as propose), then the CA row
    -- FOR SHARE. reserve_crl (0015) takes the CA row FOR UPDATE, so a CRL
    -- snapshot never interleaves with this decision: an approval either
    -- committed before the snapshot or is stamped after this_update.
    SELECT c.request_id INTO v_request FROM certificate c
    WHERE c.ca_id = v_ca AND c.serial_der_content = v_serial FOR UPDATE;
    SELECT * INTO v_chg FROM certificate_status_change s
    WHERE s.change_id = p_change FOR UPDATE;
    PERFORM 1 FROM ca WHERE ca_id = v_ca FOR SHARE;
    v_now := clock_timestamp();

    -- FOR SHARE: a concurrent grant deletion or policy change waits for this
    -- decision (and this decision waits for one already in flight).
    PERFORM 1 FROM revocation_officer_grant g
    WHERE g.issuer = p_checker_issuer AND g.subject = p_checker_subject
      AND g.ca_id = v_ca FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'actor holds no revocation officer grant for this CA'
          USING ERRCODE='42501';
    END IF;
    IF (v_chg.maker_issuer, v_chg.maker_subject)
       = (p_checker_issuer, p_checker_subject)
    THEN
        RAISE EXCEPTION 'checker must differ from maker' USING ERRCODE='23514';
    END IF;
    IF v_chg.status <> 'PROPOSED'
       OR v_chg.action <> p_expected_action
       OR v_chg.reason_code IS DISTINCT FROM p_expected_reason
    THEN
        RAISE EXCEPTION 'approval refused: closed change, maker-checker separation or mismatch'
          USING ERRCODE='23514';
    END IF;

    v_status := certificate_status(v_ca, v_serial);
    IF (v_chg.action = 'SUSPEND' AND v_status <> 'VALID')
       OR (v_chg.action = 'RELEASE' AND v_status <> 'SUSPENDED')
       OR (v_chg.action = 'REVOKE' AND v_status = 'REVOKED')
    THEN
        RAISE EXCEPTION 'status change % not valid for % certificate',
            v_chg.action, v_status USING ERRCODE='23514';
    END IF;
    IF v_chg.action = 'SUSPEND' THEN
        SELECT suspension_allowed INTO v_suspension FROM ca_revocation_policy
        WHERE ca_id = v_ca FOR SHARE;
        IF NOT COALESCE(v_suspension, false) THEN
            RAISE EXCEPTION 'suspension is not enabled for this CA'
              USING ERRCODE='23514';
        END IF;
    END IF;

    UPDATE certificate_status_change
    SET status = 'APPROVED', checker_issuer = p_checker_issuer,
        checker_subject = p_checker_subject, decided_at = v_now
    WHERE change_id = p_change;

    IF v_chg.action = 'RELEASE' THEN
        DELETE FROM revocation
        WHERE ca_id = v_ca AND serial_der_content = v_serial;
    ELSIF v_status = 'SUSPENDED' THEN
        -- hold -> definitive: reason changes, original revoked_at is kept
        UPDATE revocation
        SET reason_code = v_chg.reason_code, invalidity_at = v_chg.invalidity_at,
            actor_id = p_checker_issuer || '|' || p_checker_subject,
            change_id = p_change
        WHERE ca_id = v_ca AND serial_der_content = v_serial;
    ELSE
        INSERT INTO revocation(ca_id, serial_der_content, reason_code, revoked_at,
                               invalidity_at, actor_id, change_id)
        VALUES (v_ca, v_serial, v_chg.reason_code, v_now, v_chg.invalidity_at,
                p_checker_issuer || '|' || p_checker_subject, p_change);
    END IF;

    INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), v_ca, v_request,
            p_checker_issuer || '|' || p_checker_subject,
            'certificate.status.approved', v_chg.action || ':applied');
    RETURN 'APPROVED';
END $fn$;

CREATE FUNCTION reject_certificate_status_change(
    p_change UUID, p_checker_issuer TEXT, p_checker_subject TEXT
)
RETURNS TEXT
LANGUAGE plpgsql AS $fn$
DECLARE
    v_ca UUID;
    v_serial BYTEA;
    v_chg certificate_status_change%ROWTYPE;
    v_request UUID;
BEGIN
    IF p_change IS NULL
       OR p_checker_issuer IS NULL OR length(p_checker_issuer) NOT BETWEEN 1 AND 1024
       OR p_checker_subject IS NULL OR length(p_checker_subject) NOT BETWEEN 1 AND 512
    THEN
        RAISE EXCEPTION 'invalid rejection input' USING ERRCODE='22023';
    END IF;
    SELECT s.ca_id, s.serial_der_content INTO v_ca, v_serial
    FROM certificate_status_change s WHERE s.change_id = p_change;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown status change' USING ERRCODE='22023';
    END IF;
    SELECT c.request_id INTO v_request FROM certificate c
    WHERE c.ca_id = v_ca AND c.serial_der_content = v_serial FOR UPDATE;
    SELECT * INTO v_chg FROM certificate_status_change s
    WHERE s.change_id = p_change FOR UPDATE;

    IF NOT EXISTS (SELECT 1 FROM revocation_officer_grant g
                   WHERE g.issuer = p_checker_issuer AND g.subject = p_checker_subject
                     AND g.ca_id = v_ca) THEN
        RAISE EXCEPTION 'actor holds no revocation officer grant for this CA'
          USING ERRCODE='42501';
    END IF;
    IF v_chg.status <> 'PROPOSED'
       OR (v_chg.maker_issuer, v_chg.maker_subject)
          = (p_checker_issuer, p_checker_subject)
    THEN
        RAISE EXCEPTION 'rejection refused: closed change or maker-checker separation'
          USING ERRCODE='23514';
    END IF;

    UPDATE certificate_status_change
    SET status = 'REJECTED', checker_issuer = p_checker_issuer,
        checker_subject = p_checker_subject, decided_at = clock_timestamp()
    WHERE change_id = p_change;
    INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), v_ca, v_request,
            p_checker_issuer || '|' || p_checker_subject,
            'certificate.status.rejected', v_chg.action || ':rejected');
    RETURN 'REJECTED';
END $fn$;

CREATE FUNCTION withdraw_certificate_status_change(
    p_change UUID, p_maker_issuer TEXT, p_maker_subject TEXT
)
RETURNS TEXT
LANGUAGE plpgsql AS $fn$
DECLARE
    v_ca UUID;
    v_serial BYTEA;
    v_chg certificate_status_change%ROWTYPE;
    v_request UUID;
BEGIN
    IF p_change IS NULL
       OR p_maker_issuer IS NULL OR length(p_maker_issuer) NOT BETWEEN 1 AND 1024
       OR p_maker_subject IS NULL OR length(p_maker_subject) NOT BETWEEN 1 AND 512
    THEN
        RAISE EXCEPTION 'invalid withdrawal input' USING ERRCODE='22023';
    END IF;
    SELECT s.ca_id, s.serial_der_content INTO v_ca, v_serial
    FROM certificate_status_change s WHERE s.change_id = p_change;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown status change' USING ERRCODE='22023';
    END IF;
    SELECT c.request_id INTO v_request FROM certificate c
    WHERE c.ca_id = v_ca AND c.serial_der_content = v_serial FOR UPDATE;
    SELECT * INTO v_chg FROM certificate_status_change s
    WHERE s.change_id = p_change FOR UPDATE;

    IF NOT EXISTS (SELECT 1 FROM revocation_officer_grant g
                   WHERE g.issuer = p_maker_issuer AND g.subject = p_maker_subject
                     AND g.ca_id = v_ca) THEN
        RAISE EXCEPTION 'actor holds no revocation officer grant for this CA'
          USING ERRCODE='42501';
    END IF;
    IF v_chg.status <> 'PROPOSED'
       OR (v_chg.maker_issuer, v_chg.maker_subject)
          <> (p_maker_issuer, p_maker_subject)
    THEN
        RAISE EXCEPTION 'withdrawal refused: closed change or not the maker'
          USING ERRCODE='23514';
    END IF;

    UPDATE certificate_status_change
    SET status = 'WITHDRAWN', decided_at = clock_timestamp()
    WHERE change_id = p_change;
    INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), v_ca, v_request,
            p_maker_issuer || '|' || p_maker_subject,
            'certificate.status.withdrawn', v_chg.action || ':withdrawn');
    RETURN 'WITHDRAWN';
END $fn$;

REVOKE ALL ON FUNCTION certificate_status(uuid,bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION propose_certificate_status_change(uuid,bytea,text,smallint,timestamptz,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION approve_certificate_status_change(uuid,text,text,text,smallint) FROM PUBLIC;
REVOKE ALL ON FUNCTION reject_certificate_status_change(uuid,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION withdraw_certificate_status_change(uuid,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_certificate_status_change() FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_revocation() FROM PUBLIC;

COMMIT;
