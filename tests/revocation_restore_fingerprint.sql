-- Lab only: a canonical fingerprint of a populated revocation database,
-- one sorted line per item, compared before and after a logical restore by
-- tests/revocation_backup_restore.sh. It covers what the store's guarantees
-- depend on, not just the rows:
-- * every public table's row count and digest of its sorted rows;
-- * every sequence's position (a restore that rewinds one would reissue ids);
-- * every public table's owner, ACL and row-level security flags;
--   ACLs are compared as effective privileges (a NULL ACL is the default,
--   which pg_dump does not write out; for a function it includes PUBLIC);
-- * every public function's owner, SECURITY DEFINER flag, settings
--   (search_path) and ACL;
-- * every non-internal trigger with its enabled state (ENABLE ALWAYS
--   included) and every event trigger with its owner and state;
-- * every row-level security policy.
-- Timestamps print in the session time zone, so pin it.
SET TimeZone = 'UTC';
SET DateStyle = 'ISO, YMD';
SET IntervalStyle = 'postgres';
SET extra_float_digits = 3;
SET bytea_output = 'hex';

CREATE TEMPORARY TABLE fingerprint_line (line TEXT NOT NULL);

SELECT format(
    'INSERT INTO fingerprint_line SELECT %L || count(*) || '' md5='' || coalesce(md5(string_agg(t::text, E''\n'' ORDER BY t::text)), ''-'') FROM %I.%I t',
    'table ' || c.relname || ' rows=', n.nspname, c.relname)
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
ORDER BY c.relname
\gexec

SELECT format(
    'INSERT INTO fingerprint_line SELECT %L || last_value || '' called='' || is_called FROM %I.%I',
    'sequence ' || c.relname || ' last=', n.nspname, c.relname)
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public' AND c.relkind = 'S'
ORDER BY c.relname
\gexec

INSERT INTO fingerprint_line
SELECT format('relation %s kind=%s owner=%s acl=%s rls=%s force_rls=%s',
              c.relname, c.relkind, pg_get_userbyid(c.relowner),
              coalesce(c.relacl, acldefault((CASE WHEN c.relkind = 'S' THEN 's' ELSE 'r' END)::"char", c.relowner))::text,
              c.relrowsecurity, c.relforcerowsecurity)
FROM pg_class c
WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p', 'v', 'm', 'S');

INSERT INTO fingerprint_line
SELECT format('function %s owner=%s definer=%s config=%s acl=%s md5=%s',
              p.oid::regprocedure, pg_get_userbyid(p.proowner), p.prosecdef,
              coalesce(array_to_string(p.proconfig, ','), '-'),
              coalesce(p.proacl, acldefault('f', p.proowner))::text, md5(p.prosrc))
FROM pg_proc p
WHERE p.pronamespace = 'public'::regnamespace;

INSERT INTO fingerprint_line
SELECT format('trigger %s on %s enabled=%s def=%s',
              t.tgname, t.tgrelid::regclass, t.tgenabled, pg_get_triggerdef(t.oid))
FROM pg_trigger t
JOIN pg_class c ON c.oid = t.tgrelid
WHERE c.relnamespace = 'public'::regnamespace AND NOT t.tgisinternal;

INSERT INTO fingerprint_line
SELECT format('event_trigger %s event=%s enabled=%s owner=%s function=%s tags=%s',
              e.evtname, e.evtevent, e.evtenabled, pg_get_userbyid(e.evtowner),
              e.evtfoid::regprocedure, coalesce(e.evttags::text, '-'))
FROM pg_event_trigger e;

INSERT INTO fingerprint_line
SELECT format('policy %s on %s cmd=%s permissive=%s roles=%s using=%s check=%s',
              p.policyname, p.tablename, p.cmd, p.permissive, p.roles,
              coalesce(p.qual, '-'), coalesce(p.with_check, '-'))
FROM pg_policies p
WHERE p.schemaname = 'public';

SELECT line FROM fingerprint_line ORDER BY line;
