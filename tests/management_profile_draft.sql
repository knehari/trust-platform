-- Disposable migration contract: immutable, inert revisions and reader grant.
BEGIN;

INSERT INTO ca(ca_id, display_name, policy_version) VALUES
  ('77777777-7777-4777-8777-777777777777', 'Draft Profile CA', 'v1');

INSERT INTO certificate_profile_draft
  (ca_id, profile_id, revision, display_name, policy_version,
   max_validity_days, max_dns_sans, proposed_dns_zones,
   proposed_signature_suites, created_by)
VALUES
  ('77777777-7777-4777-8777-777777777777', 'server-lab', 1,
   'Server TLS proposal', 'v1', 90, 5,
   ARRAY['lab.invalid'], ARRAY['P256-SHA256'], 'synthetic-editor'),
  ('77777777-7777-4777-8777-777777777777', 'server-lab', 2,
   'Server TLS revised proposal', 'v1', 60, 5,
   ARRAY['lab.invalid'], ARRAY['P256-SHA256'], 'synthetic-editor');

DO $test$ DECLARE message TEXT; BEGIN
  IF (SELECT count(*) FROM management_profile_draft
      WHERE ca_id='77777777-7777-4777-8777-777777777777') <> 2 OR
     (SELECT max_validity_days FROM management_profile_draft
      WHERE ca_id='77777777-7777-4777-8777-777777777777'
        AND profile_id='server-lab' AND revision=1) <> 90 THEN
    RAISE EXCEPTION 'profile revisions were not preserved';
  END IF;
  IF has_table_privilege('trust_api_reader', 'certificate_profile_draft', 'SELECT') OR
     has_table_privilege('trust_api_reader', 'certificate_profile_draft', 'INSERT') OR
     NOT has_table_privilege('trust_api_reader', 'management_profile_draft', 'SELECT') THEN
    RAISE EXCEPTION 'profile reader privileges are not view-only';
  END IF;
  BEGIN
    UPDATE certificate_profile_draft SET max_validity_days=30
    WHERE ca_id='77777777-7777-4777-8777-777777777777' AND revision=1;
    RAISE EXCEPTION 'profile update unexpectedly succeeded';
  EXCEPTION WHEN OTHERS THEN
    GET STACKED DIAGNOSTICS message = MESSAGE_TEXT;
    IF message <> 'profile draft revisions are immutable' THEN RAISE; END IF;
  END;
  BEGIN
    DELETE FROM certificate_profile_draft
    WHERE ca_id='77777777-7777-4777-8777-777777777777' AND revision=1;
    RAISE EXCEPTION 'profile delete unexpectedly succeeded';
  EXCEPTION WHEN OTHERS THEN
    GET STACKED DIAGNOSTICS message = MESSAGE_TEXT;
    IF message <> 'profile draft revisions are immutable' THEN RAISE; END IF;
  END;
  BEGIN
    INSERT INTO certificate_profile_draft
      (ca_id,profile_id,revision,display_name,policy_version,max_validity_days,
       max_dns_sans,proposed_dns_zones,proposed_signature_suites,created_by)
    VALUES ('77777777-7777-4777-8777-777777777777','server-lab',1,
            'Duplicate','v1',90,5,ARRAY['lab.invalid'],ARRAY['P256-SHA256'],'synthetic-editor');
    RAISE EXCEPTION 'duplicate revision unexpectedly succeeded';
  EXCEPTION WHEN unique_violation THEN NULL;
  END;
END $test$;

ROLLBACK;
