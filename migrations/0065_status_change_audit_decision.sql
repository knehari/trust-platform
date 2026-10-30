-- v0.65 (lab): one definition of the status-change audit decision. LAB ONLY.
-- The decision recorded for a status change ('<action>:<outcome>:change=
-- <id>:reason=<code or ->') was built by the same expression in four
-- function bodies (propose, approve, reject, withdraw; 0018/0019/0029).
-- * status_change_audit_decision(action, outcome, change, reason) builds
--   it, with the same concatenation (a NULL action still gives NULL, which
--   audit_event refuses). Owned by trust_revocation_owner, invoker rights,
--   no PUBLIC execute: only the definer functions below call it.
-- * The four bodies are not copied here. Each is read back from the
--   catalog (pg_get_functiondef: same body, SECURITY DEFINER and settings),
--   its decision expression is replaced by the helper call, and the
--   definition is executed again (CREATE OR REPLACE keeps the owner and the
--   ACL). Each replacement must match exactly once, or the migration fails
--   and nothing changes. tests/status_change_audit_decision.sql guards
--   against a fifth copy; tests/crl_robustness.sql checks the decisions.
-- Apply after 0064 as a superuser.
BEGIN;

CREATE FUNCTION status_change_audit_decision(p_action TEXT, p_outcome TEXT, p_change UUID,
                                             p_reason SMALLINT)
RETURNS TEXT
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog, public, pg_temp
AS $fn$
    SELECT p_action || ':' || p_outcome || ':change=' || p_change
           || ':reason=' || COALESCE(p_reason::text, '-')
$fn$;
ALTER FUNCTION status_change_audit_decision(text, text, uuid, smallint) OWNER TO trust_revocation_owner;
REVOKE ALL ON FUNCTION status_change_audit_decision(text, text, uuid, smallint) FROM PUBLIC;

DO $migrate$
DECLARE
    r RECORD;
    v_def TEXT;
    v_new TEXT;
BEGIN
    FOR r IN
        SELECT * FROM (VALUES
            ('status_change_propose_unchecked',
             $e$p_action || ':pending_approval:change=' || v_change
            || ':reason=' || COALESCE(p_reason::text, '-')$e$,
             $e$status_change_audit_decision(p_action, 'pending_approval', v_change, p_reason)$e$),
            ('status_change_approve_unchecked',
             $e$v_chg.action || ':applied:change=' || p_change
            || ':reason=' || COALESCE(v_chg.reason_code::text, '-')$e$,
             $e$status_change_audit_decision(v_chg.action, 'applied', p_change, v_chg.reason_code)$e$),
            ('status_change_reject_unchecked',
             $e$v_chg.action || ':rejected:change=' || p_change
            || ':reason=' || COALESCE(v_chg.reason_code::text, '-')$e$,
             $e$status_change_audit_decision(v_chg.action, 'rejected', p_change, v_chg.reason_code)$e$),
            ('status_change_withdraw_unchecked',
             $e$v_chg.action || ':withdrawn:change=' || p_change
            || ':reason=' || COALESCE(v_chg.reason_code::text, '-')$e$,
             $e$status_change_audit_decision(v_chg.action, 'withdrawn', p_change, v_chg.reason_code)$e$)
        ) AS t(fn, old_expr, new_expr)
    LOOP
        SELECT pg_get_functiondef(p.oid) INTO STRICT v_def
        FROM pg_proc p
        WHERE p.proname = r.fn AND p.pronamespace = 'public'::regnamespace;
        IF (length(v_def) - length(replace(v_def, r.old_expr, ''))) / length(r.old_expr) <> 1 THEN
            RAISE EXCEPTION '%: decision expression not found exactly once', r.fn;
        END IF;
        v_new := replace(v_def, r.old_expr, r.new_expr);
        EXECUTE v_new;
    END LOOP;
END $migrate$;

SELECT acknowledge_schema_changes('0065_status_change_audit_decision');

COMMIT;
