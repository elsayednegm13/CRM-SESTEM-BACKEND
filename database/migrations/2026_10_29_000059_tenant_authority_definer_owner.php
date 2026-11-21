<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/**
 * FORCE RLS deliberately applies to the ordinary schema owner. Deployment lends
 * the migration owner exact ADMIN/SET (never INHERIT) membership in the isolated
 * definer role. CREATE is revoked atomically; the external grantor must revoke
 * the grantor-bound role membership immediately after migrate succeeds.
 */
return new class extends Migration
{
    public function up(): void
    {
        DB::unprepared(<<<'SQL'
            DO $roles$
            DECLARE
                v_members integer;
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_roles r WHERE r.rolname='daleel_core01_authority_definer'
                      AND NOT r.rolcanlogin AND NOT r.rolinherit AND NOT r.rolsuper
                      AND r.rolbypassrls AND NOT r.rolcreatedb AND NOT r.rolcreaterole
                      AND NOT r.rolreplication
                ) THEN
                    RAISE EXCEPTION 'CORE-01 tenant authority definer must be isolated NOLOGIN BYPASSRLS role';
                END IF;
                IF session_user <> 'daleel_b10b_owner' OR current_user <> 'daleel_b10b_owner' THEN
                    RAISE EXCEPTION 'CORE-01 authority ownership migration must run as daleel_b10b_owner';
                END IF;
                SELECT count(*) INTO v_members
                  FROM pg_auth_members m
                  JOIN pg_roles role_r ON role_r.oid=m.roleid
                  JOIN pg_roles member_r ON member_r.oid=m.member
                 WHERE role_r.rolname='daleel_core01_authority_definer'
                   AND member_r.rolname='daleel_b10b_owner'
                   AND m.admin_option AND NOT m.inherit_option AND m.set_option;
                IF v_members <> 1 OR (SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.roleid WHERE r.rolname='daleel_core01_authority_definer') <> 1 THEN
                    RAISE EXCEPTION 'CORE-01 authority definer requires the exact temporary deployment membership';
                END IF;
            END
            $roles$
        SQL);
        DB::unprepared('GRANT USAGE, CREATE ON SCHEMA public TO daleel_core01_authority_definer');
        DB::unprepared('GRANT SELECT ON public.tenants, public.tenant_staff_users, public.tenant_staff_memberships, public.core01_sql_signing_keys, public.core01_tenant_authority_sessions TO daleel_core01_authority_definer');
        // PostgreSQL requires UPDATE privilege for the FOR SHARE locks used by
        // the fixed definer functions; the role remains NOLOGIN/no-membership.
        DB::unprepared('GRANT UPDATE ON public.tenants, public.tenant_staff_users, public.tenant_staff_memberships, public.core01_sql_signing_keys TO daleel_core01_authority_definer');
        DB::unprepared('GRANT INSERT, UPDATE ON public.core01_tenant_authority_sessions TO daleel_core01_authority_definer');
        DB::unprepared('ALTER FUNCTION public.core01_tenant_authority_register_session(uuid,uuid,uuid,bigint,bigint,text,uuid,timestamptz) OWNER TO daleel_core01_authority_definer');
        DB::unprepared('ALTER FUNCTION public.core01_tenant_authority_revoke_session(text,uuid) OWNER TO daleel_core01_authority_definer');
        DB::unprepared('ALTER FUNCTION public.core01_signed_tenant_allowed(uuid) OWNER TO daleel_core01_authority_definer');
        DB::unprepared('REVOKE CREATE ON SCHEMA public FROM daleel_core01_authority_definer');
        DB::unprepared(<<<'SQL'
            DO $roles$
            BEGIN
                IF has_schema_privilege('daleel_core01_authority_definer', 'public', 'CREATE') THEN
                    RAISE EXCEPTION 'CORE-01 authority definer temporary schema CREATE survived migration';
                END IF;
                IF (SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.roleid WHERE r.rolname='daleel_core01_authority_definer') <> 1 THEN
                    RAISE EXCEPTION 'CORE-01 authority definer deployment membership changed during migration';
                END IF;
            END
            $roles$
        SQL);
    }

    public function down(): void
    {
        throw new RuntimeException('Tenant authority definer isolation is forward-only.');
    }
};
