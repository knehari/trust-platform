-- v0.63 (lab): purge of idle request budgets. LAB ONLY.
-- api_request_budget (0062) keeps one row per identity ever seen by the
-- write APIs, so it grows with the number of identities and keeps a trace
-- (digest and time of last window) of every one of them.
-- * purge_api_budgets(idle_seconds): deletes the rows whose window started
--   more than idle_seconds ago (database clock) and returns how many. The
--   bound is at least one day, the longest window consume_api_budget
--   accepts: a deleted row's window is always over, so the purge never
--   restores a spent budget early (the next request starts a new window,
--   as it would have anyway). Granted to trust_crl_operator only;
--   crl_housekeeping calls it once per run.
-- Apply after 0062 as a superuser.
BEGIN;

CREATE FUNCTION purge_api_budgets(p_idle_seconds INTEGER)
RETURNS BIGINT
LANGUAGE plpgsql AS $fn$
DECLARE
    v_purged BIGINT;
BEGIN
    IF p_idle_seconds IS NULL OR p_idle_seconds NOT BETWEEN 86400 AND 31622400 THEN
        RAISE EXCEPTION 'idle period must be between one day and 366 days' USING ERRCODE = '22023';
    END IF;
    DELETE FROM api_request_budget b
    WHERE b.window_start < clock_timestamp() - make_interval(secs => p_idle_seconds);
    GET DIAGNOSTICS v_purged = ROW_COUNT;
    RETURN v_purged;
END $fn$;
ALTER FUNCTION purge_api_budgets(integer) OWNER TO trust_revocation_owner;
ALTER FUNCTION purge_api_budgets(integer) SECURITY DEFINER;
ALTER FUNCTION purge_api_budgets(integer) SET search_path = pg_catalog, public, pg_temp;
REVOKE ALL ON FUNCTION purge_api_budgets(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION purge_api_budgets(integer) TO trust_crl_operator;

SELECT acknowledge_schema_changes('0063_purge_api_budgets');

COMMIT;
