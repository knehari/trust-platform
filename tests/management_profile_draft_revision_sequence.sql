-- Isolated schema regression for sequential, inert profile proposal revisions.
BEGIN;

INSERT INTO ca(ca_id, display_name, policy_version)
VALUES ('66666666-6666-4666-8666-666666666666', 'Revision guard CA', 'v1');

DO $test$
DECLARE message text;
BEGIN
    BEGIN
        INSERT INTO certificate_profile_draft
          (ca_id, profile_id, revision, display_name, policy_version,
           max_validity_days, max_dns_sans, proposed_dns_zones,
           proposed_signature_suites, created_by)
        VALUES ('66666666-6666-4666-8666-666666666666', 'server-lab', 2,
                'Skipped first revision', 'v1', 90, 5,
                ARRAY['lab.invalid'], ARRAY['P256-SHA256'], 'synthetic-editor');
        RAISE EXCEPTION 'revision 2 without revision 1 was accepted';
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS message = MESSAGE_TEXT;
        IF message <> 'profile draft revisions must start at 1 and be contiguous' THEN RAISE; END IF;
    END;

    INSERT INTO certificate_profile_draft
      (ca_id, profile_id, revision, display_name, policy_version,
       max_validity_days, max_dns_sans, proposed_dns_zones,
       proposed_signature_suites, created_by)
    VALUES ('66666666-6666-4666-8666-666666666666', 'server-lab', 1,
            'First revision', 'v1', 90, 5,
            ARRAY['lab.invalid'], ARRAY['P256-SHA256'], 'synthetic-editor');

    BEGIN
        INSERT INTO certificate_profile_draft
          (ca_id, profile_id, revision, display_name, policy_version,
           max_validity_days, max_dns_sans, proposed_dns_zones,
           proposed_signature_suites, created_by)
        VALUES ('66666666-6666-4666-8666-666666666666', 'server-lab', 3,
                'Skipped second revision', 'v1', 90, 5,
                ARRAY['lab.invalid'], ARRAY['P256-SHA256'], 'synthetic-editor');
        RAISE EXCEPTION 'revision gap was accepted';
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS message = MESSAGE_TEXT;
        IF message <> 'profile draft revisions must start at 1 and be contiguous' THEN RAISE; END IF;
    END;

    -- A single bulk statement may add adjacent revisions in either row order.
    INSERT INTO certificate_profile_draft
      (ca_id, profile_id, revision, display_name, policy_version,
       max_validity_days, max_dns_sans, proposed_dns_zones,
       proposed_signature_suites, created_by)
    VALUES
      ('66666666-6666-4666-8666-666666666666', 'server-lab', 3,
       'Third revision', 'v1', 90, 5, ARRAY['lab.invalid'], ARRAY['P256-SHA256'], 'synthetic-editor'),
      ('66666666-6666-4666-8666-666666666666', 'server-lab', 2,
       'Second revision', 'v1', 90, 5, ARRAY['lab.invalid'], ARRAY['P256-SHA256'], 'synthetic-editor');

    IF (SELECT count(*) FROM certificate_profile_draft
        WHERE ca_id='66666666-6666-4666-8666-666666666666' AND profile_id='server-lab') <> 3 THEN
        RAISE EXCEPTION 'contiguous bulk revisions were not stored';
    END IF;
    IF has_table_privilege('trust_api_reader', 'certificate_profile_draft', 'INSERT') THEN
        RAISE EXCEPTION 'read-only API role can insert profile revisions';
    END IF;
END $test$;

ROLLBACK;
