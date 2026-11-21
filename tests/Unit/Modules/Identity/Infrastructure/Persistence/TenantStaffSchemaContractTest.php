<?php

namespace Tests\Unit\Modules\Identity\Infrastructure\Persistence;

use Tests\TestCase;

final class TenantStaffSchemaContractTest extends TestCase
{
    public function test_both_tenant_staff_access_policies_emit_complete_parenthesized_sql(): void
    {
        $source = $this->migration('2026_10_11_000024_create_tenant_staff_membership_access.php');

        foreach ([
            'tenant_staff_membership_roles_actor_scope' => ['staffActor', 'tenant_staff_membership_roles'],
            'tenant_staff_permission_grants_actor_scope' => ['grantActor', 'tenant_staff_permission_grants'],
        ] as $policy => [$actorVariable, $table]) {
            self::assertSame(1, preg_match('/^\s*\$'.preg_quote($actorVariable, '/').' = "([^"\n]+)";/m', $source, $actor));
            self::assertSame(1, preg_match('/^\s*DB::statement\("(CREATE POLICY '.preg_quote($policy, '/').' [^"\n]+)"\);/m', $source, $statement));

            $emittedSql = str_replace('{$'.$actorVariable.'}', $actor[1], $statement[1]);
            self::assertStringNotContainsString('{$', $emittedSql);
            self::assertStringContainsString("CREATE POLICY {$policy} ON {$table} FOR ALL USING (", $emittedSql);
            self::assertStringContainsString(' WITH CHECK (', $emittedSql);
            self::assertStringContainsString("tenant_id = app_rls_current_tenant_id()", $emittedSql);
            self::assertStringContainsString("actor.staff_user_id = app_rls_current_user_id()", $emittedSql);
            self::assertSame(substr_count($emittedSql, '('), substr_count($emittedSql, ')'), $policy);
        }
    }

    public function test_membership_candidate_key_precedes_composite_self_foreign_key(): void
    {
        $source = $this->migration('2026_10_11_000023_create_tenant_staff_users.php');
        $membershipCreate = strpos($source, "Schema::create('tenant_staff_memberships'");
        $candidateKey = strpos($source, "\$table->unique(['tenant_id', 'id'], 'tenant_staff_membership_tenant_id_id_unique')");
        $postCreateAlter = strpos($source, "Schema::table('tenant_staff_memberships'");
        $selfForeignKey = strpos($source, "\$table->foreign(['tenant_id', 'created_by_membership_id'])");

        self::assertNotFalse($membershipCreate);
        self::assertNotFalse($candidateKey);
        self::assertNotFalse($postCreateAlter);
        self::assertNotFalse($selfForeignKey);
        self::assertGreaterThan($membershipCreate, $candidateKey);
        self::assertGreaterThan($candidateKey, $postCreateAlter);
        self::assertGreaterThan($postCreateAlter, $selfForeignKey);
        self::assertStringContainsString("->references(['tenant_id', 'id'])->on('tenant_staff_memberships')->restrictOnDelete()", $source);
    }

    public function test_new_schema_is_additive_forward_only_and_tenant_scoped(): void
    {
        $migration23 = $this->migration('2026_10_11_000023_create_tenant_staff_users.php');
        $migration24 = $this->migration('2026_10_11_000024_create_tenant_staff_membership_access.php');
        $migration25 = $this->migration('2026_10_11_000025_create_tenant_staff_recovery_audit.php');
        $all = $migration23.$migration24.$migration25;

        self::assertStringContainsString("Schema::create('tenant_staff_users'", $migration23);
        self::assertStringContainsString("tenant_staff_email_per_tenant_unique", $migration23);
        self::assertStringContainsString('canonical_email = lower(canonical_email)', $migration23);
        self::assertStringContainsString('tenant_staff_user_owner_immutable', $migration23);
        self::assertStringContainsString('tenant_staff_one_membership_per_user_unique', $migration23);
        self::assertStringContainsString('DEFERRABLE INITIALLY DEFERRED', $migration23);
        self::assertStringContainsString('REFERENCES', strtoupper($migration24));
        self::assertStringContainsString("Schema::create('tenant_staff_membership_roles'", $migration24);
        self::assertStringContainsString("Schema::create('tenant_staff_permission_grants'", $migration24);
        self::assertStringContainsString("REFERENCES", strtoupper($migration24));
        self::assertStringContainsString("Schema::create('tenant_staff_password_reset_tokens'", $migration25);
        self::assertStringContainsString("Schema::create('tenant_staff_security_events'", $migration25);
        self::assertStringContainsString('tenant_staff_security_event_append_only', $migration25);

        foreach ([$migration23, $migration24, $migration25] as $migration) {
            self::assertStringContainsString('ENABLE ROW LEVEL SECURITY', $migration);
            self::assertStringContainsString('FORCE ROW LEVEL SECURITY', $migration);
            self::assertStringContainsString('REVOKE ALL ON TABLE', $migration);
            self::assertStringContainsString('app_rls_current_tenant_id()', $migration);
            self::assertStringContainsString('app_rls_current_user_id()', $migration);
            self::assertStringContainsString("throw new LogicException('FND-ID-01 migrations are forward-only", $migration);
        }

        self::assertStringContainsString('permission_key', $migration24);
        self::assertStringContainsString('FROM permissions WHERE key = NEW.permission_key', $migration24);
        self::assertStringContainsString("permission_record.delegable IS DISTINCT FROM true", $migration24);
        self::assertStringContainsString('password_hash LIKE \'$argon2id$%\'', $migration23);
        self::assertStringContainsString('token_hash', $migration25);
        self::assertStringNotContainsString('token_value', $migration25);
        self::assertStringNotContainsString('tenant_staff_invitations', $all);
        self::assertStringNotContainsString('must_change_password', $all);
        self::assertStringNotContainsString('GRANT ALL', strtoupper($all));
    }

    public function test_migration_26_uses_narrow_definer_lookup_and_separate_runtime_acl(): void
    {
        $source = $this->migration('2026_10_12_000026_create_tenant_staff_authentication_access.php');

        self::assertStringContainsString('SECURITY DEFINER', $source);
        self::assertStringContainsString('SET search_path = pg_catalog, pg_temp', $source);
        self::assertStringContainsString('ALTER FUNCTION public.lookup_tenant_staff_credentials', $source);
        self::assertStringContainsString('REVOKE ALL ON FUNCTION public.lookup_tenant_staff_credentials', $source);
        self::assertStringContainsString('GRANT EXECUTE ON FUNCTION public.lookup_tenant_staff_credentials', $source);
        self::assertStringContainsString("p_expected_environment_scope NOT IN ('LOCAL_TEST', 'NON_LOCAL')", $source);
        self::assertStringContainsString('h.hostname = p_hostname', $source);
        self::assertStringContainsString('u.canonical_email = p_canonical_email', $source);
        self::assertStringContainsString("tenant_status = 'ACTIVE'", $source);
        self::assertStringContainsString("staff.status = 'ACTIVE'", $source);
        self::assertStringContainsString("membership.status = 'ACTIVE'", $source);
        self::assertStringContainsString("('daleel_tenant_auth_lookup')", $source);
        self::assertStringContainsString('TO daleel_tenant_auth_lookup', $source);
        self::assertStringContainsString('TO daleel_tenant_runtime', $source);
        self::assertStringNotContainsString('CREATE ROLE', strtoupper($source));
        self::assertStringNotContainsString('ALTER ROLE', strtoupper($source));
        self::assertStringNotContainsString('ALTER TABLE public.tenant_staff_users NO FORCE ROW LEVEL SECURITY', $source);
        self::assertStringNotContainsString('GRANT SELECT ON public.tenant_staff_users TO daleel_tenant_auth_client', $source);
        self::assertStringContainsString('throw new LogicException(\'FND-ID-02 authentication ACLs are forward-only', $source);
    }

    private function migration(string $file): string
    {
        $path = base_path("database/migrations/{$file}");
        self::assertFileExists($path);

        $source = file_get_contents($path);
        self::assertIsString($source);

        return $source;
    }
}
