-- A5 inherits exactly the narrow actor runtime group, never the legacy runtime.
BEGIN;
GRANT daleel_f06scope_actor_runtime TO daleel_f06team01_actor_a5
    WITH ADMIN FALSE, INHERIT TRUE, SET FALSE;
DO $guard$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_auth_members m
        JOIN pg_catalog.pg_roles member ON member.oid=m.member
        JOIN pg_catalog.pg_roles parent ON parent.oid=m.roleid
        WHERE member.rolname='daleel_f06team01_actor_a5'
          AND parent.rolname='daleel_tenant_runtime'
    ) THEN
        RAISE EXCEPTION 'A5 unexpectedly belongs to legacy runtime';
    END IF;
END
$guard$;
COMMIT;
