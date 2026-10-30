-- Lab-only: one definition of the CRL entries digest (migration 0061).
-- The digest the Rust core computes (CrlReservation::entries_sha256) and the
-- database checks was written out in three function bodies (reserve_crl,
-- reserve_delta_crl, crl_listed_digest); a change to one would drift from
-- the others. Since 0061 the aggregate crl_entries_sha256 is the only place
-- that encodes entries. Checks: no other function body calls
-- crl_entry_encoding, the aggregate equals the 0015 expression on varied
-- sets (empty, NULL invalidity dates, multi-byte serials), and it is not
-- callable by PUBLIC. Single transaction, rolled back. Run as a superuser.
\set ON_ERROR_STOP 1
BEGIN;

CREATE FUNCTION pg_temp.must(p_ok BOOLEAN, p_what TEXT) RETURNS VOID
LANGUAGE plpgsql AS $f$
BEGIN
    IF p_ok IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'assertion failed: %', p_what;
    END IF;
END $f$;

-- The 0015 expression, kept here as an independent oracle.
CREATE TEMPORARY TABLE entry (
    set_id INT, serial BYTEA, at TIMESTAMPTZ, reason SMALLINT, invalidity TIMESTAMPTZ);
INSERT INTO entry
SELECT s, decode(lpad(to_hex(s * 1000 + i), 2 * (1 + (i % 4)), '0'), 'hex'),
       timestamptz '2026-01-01' + make_interval(secs => s * 7919 + i * 104729),
       (ARRAY[0,1,2,3,4,5,6,9,10])[1 + (s + i) % 9]::smallint,
       CASE WHEN i % 3 = 0 THEN NULL
            ELSE timestamptz '2025-06-01' + make_interval(secs => i * 31337) END
FROM generate_series(1, 20) s, generate_series(1, s) i;

DO $t$
DECLARE
    v_set INT;
    v_new BYTEA;
    v_old BYTEA;
BEGIN
    -- Exactly one body encodes entries.
    PERFORM pg_temp.must((SELECT string_agg(p.proname, ',' ORDER BY p.proname)
                          FROM pg_proc p
                          WHERE p.pronamespace = 'public'::regnamespace
                            AND p.prosrc LIKE '%crl_entry_encoding(%')
                         = 'crl_entries_digest_step',
        'only crl_entries_digest_step encodes CRL entries, found: ' || coalesce((
            SELECT string_agg(p.proname, ',' ORDER BY p.proname) FROM pg_proc p
            WHERE p.pronamespace = 'public'::regnamespace
              AND p.prosrc LIKE '%crl_entry_encoding(%'), 'none'));
    -- Equal to the 0015 expression on every set, and on the empty set.
    FOR v_set IN SELECT DISTINCT set_id FROM entry LOOP
        SELECT crl_entries_sha256(e.serial, e.at, e.reason, e.invalidity ORDER BY e.serial),
               sha256(COALESCE(string_agg(crl_entry_encoding(e.serial, e.at, e.reason, e.invalidity),
                                          '\x'::bytea ORDER BY e.serial), '\x'::bytea))
        INTO v_new, v_old
        FROM entry e WHERE e.set_id = v_set;
        PERFORM pg_temp.must(v_new = v_old, 'set ' || v_set || ' digests differ');
    END LOOP;
    PERFORM pg_temp.must((SELECT crl_entries_sha256(e.serial, e.at, e.reason, e.invalidity
                                                    ORDER BY e.serial)
                          FROM entry e WHERE false) = sha256(''::bytea), 'empty set');
    -- Order matters (the Rust core hashes in serial order).
    PERFORM pg_temp.must((SELECT crl_entries_sha256(e.serial, e.at, e.reason, e.invalidity
                                                    ORDER BY e.serial DESC)
                          FROM entry e WHERE e.set_id = 5)
                         <> (SELECT crl_entries_sha256(e.serial, e.at, e.reason, e.invalidity
                                                       ORDER BY e.serial)
                             FROM entry e WHERE e.set_id = 5), 'order changes the digest');
    -- Owned by the revocation owner, not callable by PUBLIC.
    PERFORM pg_temp.must((SELECT pg_get_userbyid(proowner) FROM pg_proc
                          WHERE proname = 'crl_entries_sha256') = 'trust_revocation_owner', 'owner');
    PERFORM pg_temp.must(NOT has_function_privilege('public',
        'crl_entries_sha256(bytea,timestamptz,smallint,timestamptz)', 'EXECUTE'), 'not PUBLIC');
    PERFORM pg_temp.must(NOT has_function_privilege('public',
        'crl_entries_digest_step(bytea,bytea,timestamptz,smallint,timestamptz)', 'EXECUTE'), 'step not PUBLIC');
END $t$;

ROLLBACK;
