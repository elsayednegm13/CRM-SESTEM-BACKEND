<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    public function up(): void
    {
        DB::statement(<<<'SQL'
            DO $roles$
            DECLARE unsafe_roles text;
            BEGIN
                SELECT string_agg(required.name, ', ' ORDER BY required.name)
                INTO unsafe_roles
                FROM (VALUES
                    ('daleel_hostname_resolver'),
                    ('daleel_tenant_auth_lookup'),
                    ('daleel_tenant_auth_client'),
                    ('daleel_tenant_runtime')
                ) AS required(name)
                LEFT JOIN pg_catalog.pg_roles r ON r.rolname = required.name
                WHERE r.rolname IS NULL
                   OR r.rolcanlogin
                   OR r.rolsuper
                   OR r.rolbypassrls
                   OR r.rolcreatedb
                   OR r.rolcreaterole;

                IF unsafe_roles IS NOT NULL THEN
                    RAISE EXCEPTION 'Required NOLOGIN least-privilege roles are absent or unsafe: %', unsafe_roles
                        USING ERRCODE = '55000';
                END IF;

                IF NOT pg_catalog.pg_has_role('daleel_tenant_auth_lookup', 'daleel_hostname_resolver', 'USAGE') THEN
                    RAISE EXCEPTION 'The tenant-auth function owner must inherit only the hostname resolver role'
                        USING ERRCODE = '55000';
                END IF;

                IF NOT pg_catalog.pg_has_role(current_user, 'daleel_tenant_auth_lookup', 'MEMBER') THEN
                    RAISE EXCEPTION 'The migration principal must be an authorized member of the dedicated auth function owner role'
                        USING ERRCODE = '55000';
                END IF;

                IF EXISTS (
                    SELECT 1 FROM pg_catalog.pg_class c
                    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                    JOIN pg_catalog.pg_roles r ON r.oid = c.relowner
                    WHERE n.nspname = 'public'
                      AND c.relname IN ('tenants', 'tenant_hostnames', 'tenant_staff_users', 'tenant_staff_memberships')
                      AND r.rolname = 'daleel_tenant_auth_lookup'
                ) THEN
                    RAISE EXCEPTION 'The tenant-auth function owner must not own protected tables'
                        USING ERRCODE = '55000';
                END IF;
            END
            $roles$
        SQL);

        DB::statement('GRANT USAGE ON SCHEMA public TO daleel_tenant_auth_lookup, daleel_tenant_auth_client, daleel_tenant_runtime');
        DB::statement('GRANT CREATE ON SCHEMA public TO daleel_tenant_auth_lookup');

        // The function owner receives only columns consumed by this login lookup.
        DB::statement('GRANT SELECT (tenant_id, hostname, base_domain, mapping_version) ON public.tenant_hostnames TO daleel_tenant_auth_lookup');
        DB::statement('GRANT SELECT (base_domain, mapping_version, environment_scope, is_active) ON public.tenant_registry_domains TO daleel_tenant_auth_lookup');
        DB::statement('GRANT SELECT (id, status) ON public.tenants TO daleel_tenant_auth_lookup');
        DB::statement('GRANT SELECT (id, tenant_id, canonical_email, display_email, display_name, password_hash, status, auth_version) ON public.tenant_staff_users TO daleel_tenant_auth_lookup');
        DB::statement('GRANT SELECT (id, tenant_id, staff_user_id, status, authorization_version) ON public.tenant_staff_memberships TO daleel_tenant_auth_lookup');

        // These permissive SELECT policies apply only while the dedicated definer
        // function has installed its validated, exact-host pre-auth context.
        DB::statement(<<<'SQL'
            CREATE POLICY tenants_tenant_auth_lookup ON public.tenants FOR SELECT
            TO daleel_tenant_auth_lookup
            USING (
                current_user = 'daleel_tenant_auth_lookup'
                AND current_setting('app.context_mode', true) = 'TENANT_PREAUTH'
                AND id = public.app_rls_current_tenant_id()
            )
        SQL);
        DB::statement(<<<'SQL'
            CREATE POLICY tenant_staff_users_preauth_lookup ON public.tenant_staff_users FOR SELECT
            TO daleel_tenant_auth_lookup
            USING (
                current_user = 'daleel_tenant_auth_lookup'
                AND current_setting('app.context_mode', true) = 'TENANT_PREAUTH'
                AND tenant_id = public.app_rls_current_tenant_id()
                AND canonical_email = current_setting('app.tenant_auth_email', true)
                AND current_setting('app.host_resolution_hostname', true)
                    = current_setting('app.tenant_auth_hostname', true)
            )
        SQL);
        DB::statement(<<<'SQL'
            CREATE POLICY tenant_staff_memberships_preauth_lookup ON public.tenant_staff_memberships FOR SELECT
            TO daleel_tenant_auth_lookup
            USING (
                current_user = 'daleel_tenant_auth_lookup'
                AND current_setting('app.context_mode', true) = 'TENANT_PREAUTH'
                AND tenant_id = public.app_rls_current_tenant_id()
                AND staff_user_id = public.app_rls_current_user_id()
                AND current_setting('app.host_resolution_hostname', true)
                    = current_setting('app.tenant_auth_hostname', true)
            )
        SQL);

        DB::statement(<<<'SQL'
            CREATE OR REPLACE FUNCTION public.lookup_tenant_staff_credentials(
                p_hostname text,
                p_expected_base_domain text,
                p_expected_environment_scope text,
                p_canonical_email text
            ) RETURNS TABLE (
                tenant_id uuid,
                staff_user_id uuid,
                canonical_email text,
                display_email text,
                display_name text,
                password_hash text,
                auth_version bigint,
                membership_id uuid,
                membership_authorization_version bigint
            )
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, pg_temp
            AS $function$
            DECLARE
                previous_mode text := pg_catalog.current_setting('app.context_mode', true);
                previous_host text := pg_catalog.current_setting('app.host_resolution_hostname', true);
                previous_tenant text := pg_catalog.current_setting('app.tenant_id', true);
                previous_user text := pg_catalog.current_setting('app.user_id', true);
                previous_auth_host text := pg_catalog.current_setting('app.tenant_auth_hostname', true);
                previous_auth_email text := pg_catalog.current_setting('app.tenant_auth_email', true);
                resolved_tenant uuid;
                tenant_status text;
                staff record;
                membership record;
                found_subject boolean := false;
            BEGIN
                IF p_hostname IS NULL OR length(p_hostname) NOT BETWEEN 3 AND 253
                    OR p_expected_base_domain IS NULL OR length(p_expected_base_domain) NOT BETWEEN 3 AND 253
                    OR p_expected_environment_scope IS NULL
                    OR p_expected_environment_scope NOT IN ('LOCAL_TEST', 'NON_LOCAL')
                    OR p_canonical_email IS NULL OR length(p_canonical_email) NOT BETWEEN 3 AND 254
                    OR p_canonical_email <> pg_catalog.lower(pg_catalog.btrim(p_canonical_email))
                    OR p_canonical_email !~ '^[^[:space:]@]+@[^[:space:]@]+$' THEN
                    RETURN;
                END IF;

                PERFORM pg_catalog.set_config('app.context_mode', 'HOST_RESOLUTION', true);
                PERFORM pg_catalog.set_config('app.host_resolution_hostname', p_hostname, true);

                SELECT h.tenant_id
                INTO resolved_tenant
                FROM public.tenant_hostnames h
                JOIN public.tenant_registry_domains d
                  ON d.mapping_version = h.mapping_version
                 AND d.base_domain = h.base_domain
                WHERE h.hostname = p_hostname
                  AND h.base_domain = p_expected_base_domain
                  AND d.environment_scope = p_expected_environment_scope
                  AND d.is_active;

                IF resolved_tenant IS NOT NULL THEN
                    PERFORM pg_catalog.set_config('app.context_mode', 'TENANT_PREAUTH', true);
                    PERFORM pg_catalog.set_config('app.tenant_id', resolved_tenant::text, true);
                    PERFORM pg_catalog.set_config('app.user_id', '', true);
                    PERFORM pg_catalog.set_config('app.tenant_auth_hostname', p_hostname, true);
                    PERFORM pg_catalog.set_config('app.tenant_auth_email', p_canonical_email, true);

                    SELECT t.status INTO tenant_status
                    FROM public.tenants t
                    WHERE t.id = resolved_tenant;

                    IF tenant_status = 'ACTIVE' THEN
                        SELECT u.id, u.tenant_id, u.canonical_email, u.display_email,
                               u.display_name, u.password_hash, u.auth_version, u.status
                        INTO staff
                        FROM public.tenant_staff_users u
                        WHERE u.tenant_id = resolved_tenant
                          AND u.canonical_email = p_canonical_email;

                        IF FOUND AND staff.status = 'ACTIVE' THEN
                            PERFORM pg_catalog.set_config('app.user_id', staff.id::text, true);

                            SELECT m.id, m.status, m.authorization_version
                            INTO membership
                            FROM public.tenant_staff_memberships m
                            WHERE m.tenant_id = resolved_tenant
                              AND m.staff_user_id = staff.id;

                            IF FOUND AND membership.status = 'ACTIVE' THEN
                                tenant_id := staff.tenant_id;
                                staff_user_id := staff.id;
                                canonical_email := staff.canonical_email;
                                display_email := staff.display_email;
                                display_name := staff.display_name;
                                password_hash := staff.password_hash;
                                auth_version := staff.auth_version;
                                membership_id := membership.id;
                                membership_authorization_version := membership.authorization_version;
                                found_subject := true;
                            END IF;
                        END IF;
                    END IF;
                END IF;

                PERFORM pg_catalog.set_config('app.context_mode', coalesce(previous_mode, ''), true);
                PERFORM pg_catalog.set_config('app.host_resolution_hostname', coalesce(previous_host, ''), true);
                PERFORM pg_catalog.set_config('app.tenant_id', coalesce(previous_tenant, ''), true);
                PERFORM pg_catalog.set_config('app.user_id', coalesce(previous_user, ''), true);
                PERFORM pg_catalog.set_config('app.tenant_auth_hostname', coalesce(previous_auth_host, ''), true);
                PERFORM pg_catalog.set_config('app.tenant_auth_email', coalesce(previous_auth_email, ''), true);

                IF found_subject THEN
                    RETURN NEXT;
                END IF;
                RETURN;
            END
            $function$
        SQL);

        DB::statement('ALTER FUNCTION public.lookup_tenant_staff_credentials(text, text, text, text) OWNER TO daleel_tenant_auth_lookup');
        DB::statement('REVOKE CREATE ON SCHEMA public FROM daleel_tenant_auth_lookup');
        DB::statement('REVOKE ALL ON FUNCTION public.lookup_tenant_staff_credentials(text, text, text, text) FROM PUBLIC');
        DB::statement('GRANT EXECUTE ON FUNCTION public.lookup_tenant_staff_credentials(text, text, text, text) TO daleel_tenant_auth_client');

        // Authenticated requests use a different, non-owner NOBYPASSRLS role.
        DB::statement('GRANT SELECT (id, status) ON public.tenants TO daleel_tenant_runtime');
        DB::statement('GRANT SELECT (id, tenant_id, canonical_email, display_email, display_name, status, auth_version) ON public.tenant_staff_users TO daleel_tenant_runtime');
        DB::statement('GRANT SELECT (id, tenant_id, staff_user_id, status, authorization_version) ON public.tenant_staff_memberships TO daleel_tenant_runtime');
        DB::statement('GRANT SELECT (tenant_id, membership_id, role_id, revoked_at) ON public.tenant_staff_membership_roles TO daleel_tenant_runtime');
        DB::statement('GRANT SELECT (tenant_id, membership_id, permission_key, scope, revoked_at) ON public.tenant_staff_permission_grants TO daleel_tenant_runtime');
        DB::statement('GRANT SELECT (id, tenant_id, display_name, normalized_name, status, archived_at) ON public.roles TO daleel_tenant_runtime');
        DB::statement('GRANT SELECT (tenant_id, role_id, permission_key, scope) ON public.role_permissions TO daleel_tenant_runtime');
        DB::statement('GRANT SELECT (key, scopeable, allowed_scopes, delegable, status) ON public.permissions TO daleel_tenant_runtime');
    }

    public function down(): void
    {
        throw new LogicException('FND-ID-02 authentication ACLs are forward-only; use a separately reviewed forward correction.');
    }
};
