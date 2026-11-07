-- Inject a failure after earlier objects have been created by pg_restore.
-- Only use in a disposable target database with an operator-owned cluster.
CREATE FUNCTION management_restore_fault() RETURNS event_trigger
LANGUAGE plpgsql AS $fault$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_event_trigger_ddl_commands()
        WHERE command_tag = 'CREATE TABLE'
          AND object_identity = 'public.certificate'
    ) THEN
        RAISE EXCEPTION 'intentional lab restore fault';
    END IF;
END
$fault$;
CREATE EVENT TRIGGER management_restore_fault ON ddl_command_end
EXECUTE FUNCTION management_restore_fault();
