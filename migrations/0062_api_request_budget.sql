-- v0.62 (lab): request budgets shared by every replica of the lab write
-- APIs. LAB ONLY.
-- The revocation and CA-admin APIs limit each verified identity to 60
-- requests per minute (rate_limit.rs), in memory: two replicas allow 120,
-- and a restart resets the count.
-- * api_request_budget: one row per (API scope, identity digest), with the
--   start of its fixed window and the requests used. The identity is the
--   SHA-256 the API computes over issuer, a zero byte and subject: no raw
--   identity is stored. Owned by trust_revocation_owner; no role reads or
--   writes it directly.
-- * consume_api_budget(scope, identity_sha256, limit, window_seconds):
--   under the row lock, starts a new window when the current one is over,
--   then counts the request and returns true, or returns false once the
--   window's budget is spent (a refused request is not counted). Database
--   clock. Granted to trust_revocation_officer_api and trust_ca_admin.
-- One row per identity ever seen: the table grows with the number of
-- identities, not of requests. The in-memory limit stays in front of it, so
-- a flood from one identity does not reach the database.
-- Apply after 0061 as a superuser.
BEGIN;

CREATE TABLE api_request_budget (
    scope TEXT NOT NULL CHECK (scope IN ('revocation', 'ca_admin')),
    identity_sha256 BYTEA NOT NULL CHECK (octet_length(identity_sha256) = 32),
    window_start TIMESTAMPTZ NOT NULL,
    used INTEGER NOT NULL CHECK (used >= 0),
    PRIMARY KEY (scope, identity_sha256)
);
ALTER TABLE api_request_budget OWNER TO trust_revocation_owner;
REVOKE ALL ON api_request_budget FROM PUBLIC;

CREATE FUNCTION consume_api_budget(p_scope TEXT, p_identity_sha256 BYTEA, p_limit INTEGER,
                                   p_window_seconds INTEGER)
RETURNS BOOLEAN
LANGUAGE plpgsql AS $fn$
DECLARE
    v_now TIMESTAMPTZ := clock_timestamp();
    v_row api_request_budget%ROWTYPE;
BEGIN
    IF p_scope IS NULL OR p_scope NOT IN ('revocation', 'ca_admin')
       OR p_identity_sha256 IS NULL OR octet_length(p_identity_sha256) <> 32
       OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100000
       OR p_window_seconds IS NULL OR p_window_seconds NOT BETWEEN 1 AND 86400
    THEN
        RAISE EXCEPTION 'invalid request budget input' USING ERRCODE = '22023';
    END IF;
    INSERT INTO api_request_budget (scope, identity_sha256, window_start, used)
    VALUES (p_scope, p_identity_sha256, v_now, 0)
    ON CONFLICT (scope, identity_sha256) DO NOTHING;
    SELECT * INTO v_row FROM api_request_budget b
    WHERE b.scope = p_scope AND b.identity_sha256 = p_identity_sha256 FOR UPDATE;
    IF v_now - v_row.window_start >= make_interval(secs => p_window_seconds) THEN
        v_row.window_start := v_now;
        v_row.used := 0;
    END IF;
    IF v_row.used >= p_limit THEN
        RETURN false;
    END IF;
    UPDATE api_request_budget b SET window_start = v_row.window_start, used = v_row.used + 1
    WHERE b.scope = p_scope AND b.identity_sha256 = p_identity_sha256;
    RETURN true;
END $fn$;
ALTER FUNCTION consume_api_budget(text, bytea, integer, integer) OWNER TO trust_revocation_owner;
ALTER FUNCTION consume_api_budget(text, bytea, integer, integer) SECURITY DEFINER;
ALTER FUNCTION consume_api_budget(text, bytea, integer, integer)
    SET search_path = pg_catalog, public, pg_temp;
REVOKE ALL ON FUNCTION consume_api_budget(text, bytea, integer, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consume_api_budget(text, bytea, integer, integer)
    TO trust_revocation_officer_api, trust_ca_admin;

SELECT acknowledge_schema_changes('0062_api_request_budget');

COMMIT;
