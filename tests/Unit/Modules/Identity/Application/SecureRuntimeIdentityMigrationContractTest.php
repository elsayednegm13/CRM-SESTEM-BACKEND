<?php

declare(strict_types=1);

namespace Tests\Unit\Modules\Identity\Application;

use Tests\TestCase;

final class SecureRuntimeIdentityMigrationContractTest extends TestCase
{
    private const MIGRATION = '2026_11_19_000072_bind_signed_tenant_context_to_restricted_runtime_login.php';

    public function test_forward_migration_uses_exact_restricted_login_membership_as_a_necessary_gate(): void
    {
        $source = file_get_contents(database_path('migrations/'.self::MIGRATION));

        self::assertIsString($source);
        self::assertStringContainsString("login_role.rolname = session_user", $source);
        self::assertStringContainsString("login_role.rolcanlogin", $source);
        self::assertStringContainsString("NOT login_role.rolinherit", $source);
        self::assertStringContainsString("NOT login_role.rolsuper", $source);
        self::assertStringContainsString("NOT login_role.rolcreaterole", $source);
        self::assertStringContainsString("NOT login_role.rolbypassrls", $source);
        self::assertStringContainsString("runtime_role.rolname = 'dl_core_truntime'", $source);
        self::assertStringContainsString('NOT membership.admin_option', $source);
        self::assertStringContainsString('membership.inherit_option', $source);
        self::assertStringContainsString('NOT membership.set_option', $source);
        self::assertStringContainsString('public.core_sql_tenant_logins', $source);
        self::assertStringContainsString("trusted_login.role_name = session_user", $source);
        self::assertStringContainsString("trusted_login.purpose = 'TRUSTED_TENANT'", $source);
    }

    public function test_forward_migration_preserves_the_signed_session_backend_and_subject_gates(): void
    {
        $source = file_get_contents(database_path('migrations/'.self::MIGRATION));

        self::assertIsString($source);
        self::assertStringContainsString("v_parts[12]<>'v3'", $source);
        self::assertStringContainsString('v_backend<>pg_backend_pid()', $source);
        self::assertStringContainsString("encode(public.hmac(convert_to(v_message,'UTF8'),v_key,'sha256'),'hex')<>v_parts[13]", $source);
        self::assertStringContainsString('public.core01_tenant_authority_sessions', $source);
        self::assertStringContainsString('s.revoked_at IS NULL', $source);
        self::assertStringContainsString('s.expires_at>clock_timestamp()', $source);
        self::assertStringContainsString('m.authorization_version=v_authorization', $source);
    }

    public function test_forward_migration_does_not_embed_test_identity_or_expand_runtime_privilege(): void
    {
        $source = file_get_contents(database_path('migrations/'.self::MIGRATION));

        self::assertIsString($source);
        self::assertStringNotContainsString('dcrm_test_trusted_20261118', $source);
        self::assertStringNotContainsString('BYPASSRLS', $source);
        self::assertStringNotContainsString('SUPERUSER', $source);
        self::assertStringNotContainsString('CREATEROLE', $source);
        self::assertStringNotContainsString('GRANT ROLE', $source);
        self::assertStringContainsString('GRANT SELECT ON public.core_sql_tenant_logins TO daleel_core01_authority_definer', $source);
        self::assertStringContainsString('REVOKE ALL ON FUNCTION public.core01_signed_tenant_allowed(uuid) FROM PUBLIC', $source);
        self::assertStringContainsString('GRANT EXECUTE ON FUNCTION public.core01_signed_tenant_allowed(uuid) TO daleel_tenant_runtime', $source);
    }
}
