-- Fail after 0013 has created its table but before that migration commits.
-- Install only in a disposable migration-test database.
CREATE FUNCTION management_migration_fault() RETURNS event_trigger
LANGUAGE plpgsql AS $fault$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_event_trigger_ddl_commands()
        WHERE command_tag = 'CREATE VIEW'
          AND object_identity = 'public.management_reader_scope'
    ) THEN
        RAISE EXCEPTION 'intentional lab migration fault';
    END IF;
END
$fault$;
CREATE EVENT TRIGGER management_migration_fault ON ddl_command_end
EXECUTE FUNCTION management_migration_fault();
