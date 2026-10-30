-- Lab-only: the status-change audit decision format has one definition
-- (migration 0065). Single transaction, rolled back. Run as a superuser.
-- The decisions themselves are checked end to end by crl_robustness.sql.
\set ON_ERROR_STOP 1
BEGIN;

CREATE FUNCTION pg_temp.must(p_ok BOOLEAN, p_what TEXT) RETURNS VOID
LANGUAGE plpgsql AS $f$
BEGIN
    IF p_ok IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'assertion failed: %', p_what;
    END IF;
END $f$;

-- Drift guard: only the helper builds the ':change=...:reason=' suffix, and
-- each of the four lifecycle bodies calls it once.
DO $t$
DECLARE
    builders TEXT;
    callers TEXT;
BEGIN
    SELECT string_agg(p.proname, ', ' ORDER BY p.proname) INTO builders
    FROM pg_proc p
    WHERE p.pronamespace = 'public'::regnamespace AND p.prokind = 'f'
      AND p.prosrc LIKE '%'':reason='' ||%'
      AND p.proname <> 'status_change_audit_decision';
    PERFORM pg_temp.must(builders IS NULL,
        'functions still building the decision format: ' || coalesce(builders, ''));
    SELECT string_agg(p.proname, ', ' ORDER BY p.proname) INTO callers
    FROM pg_proc p
    WHERE p.pronamespace = 'public'::regnamespace
      AND (length(p.prosrc) - length(replace(p.prosrc, 'status_change_audit_decision(', '')))
          / length('status_change_audit_decision(') = 1;
    PERFORM pg_temp.must(callers = 'status_change_approve_unchecked, status_change_propose_unchecked, '
                                   || 'status_change_reject_unchecked, status_change_withdraw_unchecked',
        'callers: ' || coalesce(callers, 'none'));
END $t$;

-- Same strings as the 0018/0019/0029 expressions, NULL reason included.
DO $t$
DECLARE
    c CONSTANT UUID := '5eedc0de-0000-4000-8000-000000000065';
BEGIN
    PERFORM pg_temp.must(status_change_audit_decision('REVOKE', 'applied', c, 4::smallint)
        = 'REVOKE:applied:change=' || c || ':reason=4', 'revoke');
    PERFORM pg_temp.must(status_change_audit_decision('RELEASE', 'pending_approval', c, NULL)
        = 'RELEASE:pending_approval:change=' || c || ':reason=-', 'release without reason');
    PERFORM pg_temp.must(status_change_audit_decision(NULL, 'applied', c, 4::smallint) IS NULL,
        'a NULL action still gives NULL, as the concatenation did');
END $t$;

-- The rewritten bodies kept their owner, definer rights, settings and ACL.
DO $t$
DECLARE bad TEXT;
BEGIN
    SELECT string_agg(p.proname, ', ') INTO bad
    FROM pg_proc p
    WHERE p.proname IN ('status_change_propose_unchecked', 'status_change_approve_unchecked',
                        'status_change_reject_unchecked', 'status_change_withdraw_unchecked')
      AND (NOT p.prosecdef OR p.proowner <> 'trust_revocation_owner'::regrole
           OR p.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, public, pg_temp']
           OR has_function_privilege('public', p.oid, 'EXECUTE'));
    PERFORM pg_temp.must(bad IS NULL, 'lifecycle bodies changed rights: ' || coalesce(bad, ''));
    PERFORM pg_temp.must(NOT has_function_privilege('public',
        'status_change_audit_decision(text,text,uuid,smallint)', 'EXECUTE'), 'helper not public');
    PERFORM pg_temp.must((SELECT proowner = 'trust_revocation_owner'::regrole AND NOT prosecdef
                          FROM pg_proc WHERE proname = 'status_change_audit_decision'),
        'helper owned by the revocation owner, invoker rights');
END $t$;

ROLLBACK;
