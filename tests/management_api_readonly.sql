-- Run after 0012 as the migration owner. The API role may read only the views.
BEGIN;
SET LOCAL ROLE trust_api_reader;
DO $test$ BEGIN
    PERFORM count(*) FROM management_ca;
    PERFORM count(*) FROM management_certificate;
    PERFORM count(*) FROM management_audit;
    PERFORM count(*) FROM management_reader_scope;
    BEGIN
        PERFORM count(*) FROM management_reader_grant;
        RAISE EXCEPTION 'API role unexpectedly reads raw reader grants';
    EXCEPTION WHEN insufficient_privilege THEN NULL;
    END;
    BEGIN
        PERFORM count(*) FROM certificate;
        RAISE EXCEPTION 'API role unexpectedly reads raw certificate DER';
    EXCEPTION WHEN insufficient_privilege THEN NULL;
    END;
    BEGIN
        UPDATE ca SET display_name = display_name;
        RAISE EXCEPTION 'API role unexpectedly writes CA';
    EXCEPTION WHEN insufficient_privilege THEN NULL;
    END;
    BEGIN
        PERFORM create_issuance_request(
            'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'::uuid,
            'forbidden', decode(repeat('11',32),'hex'), 'api', 'v1');
        RAISE EXCEPTION 'API role unexpectedly calls issuance function';
    EXCEPTION WHEN insufficient_privilege THEN NULL;
    END;
END $test$;
ROLLBACK;
