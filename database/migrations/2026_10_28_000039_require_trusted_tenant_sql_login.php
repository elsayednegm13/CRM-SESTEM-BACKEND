<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/**
 * CORE-01: a shared legacy login must never gain tenant rows by setting a GUC.
 * The deployment provisions the trusted LOGIN and its secret outside this migration.
 * The migration fails closed until both SQL identities are explicitly configured.
 */
return new class extends Migration
{
    private const TABLES = [
        'tenants', 'tenant_memberships', 'roles', 'role_permissions', 'membership_roles',
        'tenant_staff_users', 'tenant_staff_memberships', 'tenant_staff_membership_roles',
        'tenant_staff_permission_grants', 'tenant_staff_password_reset_tokens',
        'tenant_staff_security_events', 'tenant_hostnames', 'leads', 'tenant_subscriptions',
        'tenant_limit_overrides', 'security_audit_events', 'outbox_messages',
        'provider_provision_revisions',
    ];

    public function up(): void
    {
        $trusted = (string) config('core_sql.trusted_tenant_login');
        $legacy = (string) config('core_sql.legacy_tenant_login');
        if (! preg_match('/^[a-z_][a-z0-9_]{2,62}$/D', $trusted)
            || ! preg_match('/^[a-z_][a-z0-9_]{2,62}$/D', $legacy)
            || $trusted === $legacy) {
            throw new RuntimeException('Distinct trusted and legacy tenant SQL logins must be configured.');
        }

        $roles = DB::select(<<<'SQL'
            SELECT r.rolname, r.rolcanlogin, r.rolsuper, r.rolbypassrls,
                   r.rolcreatedb, r.rolcreaterole, r.rolreplication,
                   pg_catalog.pg_has_role(r.oid, 'daleel_tenant_runtime', 'MEMBER') AS runtime_member,
                   pg_catalog.pg_has_role(r.oid, 'daleel_tenant_runtime', 'USAGE') AS runtime_usage,
                   pg_catalog.pg_has_role(r.oid, 'daleel_tenant_runtime', 'SET') AS runtime_set,
                   pg_catalog.has_schema_privilege(r.oid, 'public', 'CREATE') AS can_create_public
            FROM pg_catalog.pg_roles r WHERE r.rolname IN (?, ?)
        SQL, [$trusted, $legacy]);
        if (count($roles) !== 2) {
            throw new RuntimeException('Both tenant SQL logins must exist before migration 039.');
        }
        foreach ($roles as $role) {
            if (! $role->rolcanlogin || $role->rolsuper || $role->rolbypassrls
                || $role->rolcreatedb || $role->rolcreaterole || $role->rolreplication
                || $role->can_create_public) {
                throw new RuntimeException('Tenant SQL role has unsafe cluster/schema privileges: '.$role->rolname);
            }
            if ($role->rolname === $trusted && (! $role->runtime_member || ! $role->runtime_usage || $role->runtime_set)) {
                throw new RuntimeException('Trusted tenant login requires inherited runtime grants without SET ROLE.');
            }
        }
        $canSwitch = DB::selectOne('SELECT pg_catalog.pg_has_role(?, ?, ?) AS allowed', [$legacy, $trusted, 'SET']);
        if ($canSwitch->allowed) {
            throw new RuntimeException('Legacy tenant login can SET ROLE to trusted tenant login.');
        }

        DB::statement(<<<'SQL'
            CREATE TABLE public.core_sql_tenant_logins (
                role_name name PRIMARY KEY,
                purpose text NOT NULL CHECK (purpose = 'TRUSTED_TENANT'),
                created_at timestamptz NOT NULL DEFAULT pg_catalog.transaction_timestamp()
            )
        SQL);
        DB::statement('REVOKE ALL ON public.core_sql_tenant_logins FROM PUBLIC');
        DB::table('core_sql_tenant_logins')->insert(['role_name' => $trusted, 'purpose' => 'TRUSTED_TENANT']);
        DB::statement(<<<'SQL'
            CREATE FUNCTION public.core_sql_tenant_login_allowed() RETURNS boolean
            LANGUAGE sql STABLE SECURITY DEFINER
            SET search_path = pg_catalog, pg_temp
            AS $function$
                SELECT EXISTS (
                    SELECT 1 FROM public.core_sql_tenant_logins p
                    WHERE p.role_name = session_user AND p.purpose = 'TRUSTED_TENANT'
                )
            $function$
        SQL);
        DB::statement('REVOKE ALL ON FUNCTION public.core_sql_tenant_login_allowed() FROM PUBLIC');
        DB::statement('GRANT EXECUTE ON FUNCTION public.core_sql_tenant_login_allowed() TO daleel_tenant_runtime');

        foreach (self::TABLES as $table) {
            $metadata = DB::selectOne('SELECT c.relrowsecurity, c.relforcerowsecurity FROM pg_catalog.pg_class c WHERE c.oid = ?::regclass', ['public.'.$table]);
            if (! $metadata || ! $metadata->relrowsecurity || ! $metadata->relforcerowsecurity) {
                throw new RuntimeException('Expected FORCE RLS on tenant SQL surface: '.$table);
            }
            DB::statement("CREATE POLICY core_sql_trusted_login_boundary ON public.{$table} "
                .'AS RESTRICTIVE FOR ALL TO daleel_tenant_runtime '
                .'USING (public.core_sql_tenant_login_allowed()) '
                .'WITH CHECK (public.core_sql_tenant_login_allowed())');
        }
    }

    public function down(): void
    {
        throw new LogicException('CORE-01 SQL boundary is forward-only; a separately reviewed migration is required.');
    }
};
