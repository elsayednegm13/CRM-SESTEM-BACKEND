<?php

namespace Tests\Feature\Tenancy;

use App\Modules\Identity\Infrastructure\Persistence\User;
use App\Modules\Identity\Application\UserAccountStatusService;
use App\Modules\Tenancy\Application\CompanyAdminBootstrap;
use App\Modules\Tenancy\Application\TenantAuthorizationService;
use App\Modules\Tenancy\Application\TenantRoleMutationService;
use App\Modules\Tenancy\Domain\AuthorizationDeniedException;
use App\Modules\Tenancy\Domain\TenantContext;
use App\Modules\Tenancy\Infrastructure\Persistence\Role;
use App\Modules\Tenancy\Infrastructure\Persistence\TenantMembership;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Tests\TestCase;

final class TenantRbacTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        config(['tenancy.disposable_bootstrap_enabled' => true]);
    }

    private function user(string $name): User
    {
        return User::query()->create([
            'email' => $name.'@proof.invalid',
            'password' => Hash::make('correct horse battery staple'),
        ])->fresh();
    }

    private function bootstrap(string $slug = 'company-a'): array
    {
        $user = $this->user('founder-'.$slug);
        $context = app(CompanyAdminBootstrap::class)->create($user, [
            'display_name' => $slug,
            'slug' => $slug,
            'timezone' => 'UTC',
            'default_locale' => 'en',
        ], (string) Str::uuid());
        return [$user, $context];
    }

    private function member(TenantContext $company, string $name): array
    {
        $user = $this->user($name);
        $membership = TenantMembership::query()->create([
            'tenant_id' => $company->tenantId, 'user_id' => $user->id, 'joined_at' => now(),
        ]);
        $membership->forceFill(['status' => 'ACTIVE'])->save();
        return [$user, $membership->fresh(), new TenantContext($user->id, $company->tenantId,
            $membership->id, 1, 0, (string) Str::uuid())];
    }

    private function role(TenantContext $company, string $name, array $grants = []): Role
    {
        $role = Role::query()->create([
            'tenant_id' => $company->tenantId, 'display_name' => $name,
            'normalized_name' => Str::slug($name, '_'),
        ]);
        foreach ($grants as [$key, $scope]) {
            DB::table('role_permissions')->insert([
                'tenant_id' => $company->tenantId, 'role_id' => $role->id,
                'permission_key' => $key, 'scope' => $scope,
            ]);
        }
        return $role;
    }

    private function attach(TenantContext $company, string $membershipId, Role $role): void
    {
        DB::table('membership_roles')->insert([
            'tenant_id' => $company->tenantId, 'membership_id' => $membershipId,
            'role_id' => $role->id, 'assigned_at' => now(),
        ]);
    }

    private function assertPgViolation(callable $operation, string $state): void
    {
        try {
            DB::transaction($operation);
            $this->fail('PostgreSQL accepted an invalid RBAC row.');
        } catch (QueryException $exception) {
            $this->assertSame($state, $exception->errorInfo[0]);
        }
    }

    public function test_catalog_template_and_schema_constraints(): void
    {
        // Updated for migration 2026_10_23_000036 (leads.view/leads.manage added to the
        // catalog and to this template).
        $keys = DB::table('permissions')->orderBy('key')->pluck('key')->all();
        $this->assertSame(['company.administer', 'leads.manage', 'leads.view', 'member.manage',
            'member.view', 'role.manage', 'role.view'], $keys);
        $this->assertFalse((bool) DB::table('permissions')->where('key', 'company.administer')->value('delegable'));
        $template = DB::table('role_templates')->where('code', 'company_admin')->where('version', 1)->first();
        $this->assertNotNull($template);
        $this->assertSame(7, DB::table('role_template_permissions')->where('template_id', $template->id)->count());
        $this->assertSame('ALL_TENANT', DB::table('role_template_permissions')->where('template_id', $template->id)
            ->where('permission_key', 'company.administer')->value('scope'));

        $this->assertPgViolation(fn () => DB::table('permissions')->insert([
            'key' => 'provider.payments.verify', 'scopeable' => false, 'allowed_scopes' => '[]', 'delegable' => false,
            'status' => 'ACTIVE', 'version' => 1, 'description' => 'bad',
        ]), '23514');
        $this->assertPgViolation(fn () => DB::table('permissions')->insert([
            'key' => 'bad.scope', 'scopeable' => false, 'allowed_scopes' => '["SELF"]', 'delegable' => true,
            'status' => 'ACTIVE', 'version' => 1, 'description' => 'bad',
        ]), '23514');
        $this->assertPgViolation(fn () => DB::table('role_templates')->insert([
            'id' => (string) Str::uuid7(), 'code' => 'company_admin', 'version' => 1,
            'display_name' => 'Duplicate', 'status' => 'ACTIVE',
        ]), '23505');
        $this->assertPgViolation(fn () => DB::table('role_template_permissions')->insert([
            'template_id' => $template->id, 'permission_key' => 'provider.payments',
        ]), '23503');
    }

    public function test_bootstrap_is_restricted_atomic_and_copies_template(): void
    {
        [$user, $context] = $this->bootstrap();
        $this->assertSame('ACTIVE', DB::table('tenants')->where('id', $context->tenantId)->value('status'));
        $this->assertSame('ACTIVE', DB::table('tenant_memberships')->where('id', $context->membershipId)->value('status'));
        $role = DB::table('roles')->where('tenant_id', $context->tenantId)->first();
        $this->assertSame('7', substr($role->id, 14, 1));
        $this->assertNotNull($role->source_template_id);
        $this->assertSame(7, DB::table('role_permissions')->where('role_id', $role->id)->count());
        $this->assertSame(1, DB::table('membership_roles')->where('membership_id', $context->membershipId)->count());

        config(['tenancy.disposable_bootstrap_enabled' => false]);
        try {
            app(CompanyAdminBootstrap::class)->create($user, ['display_name' => 'No', 'slug' => 'disabled', 'timezone' => 'UTC', 'default_locale' => 'en'], (string) Str::uuid());
            $this->fail('Disabled bootstrap succeeded.');
        } catch (AuthorizationDeniedException) {
            $this->assertSame(1, DB::table('tenants')->count());
        }

        config(['tenancy.disposable_bootstrap_enabled' => true]);
        try {
            DB::transaction(function () use ($user): void {
                app(CompanyAdminBootstrap::class)->create($user, [
                    'display_name' => 'Rollback', 'slug' => 'rollback',
                    'timezone' => 'UTC', 'default_locale' => 'en',
                ], (string) Str::uuid());
                throw new \RuntimeException('controlled rollback');
            });
        } catch (\RuntimeException) {
            $this->assertSame(1, DB::table('tenants')->count());
            $this->assertSame(1, DB::table('roles')->count());
            $this->assertSame(1, DB::table('membership_roles')->count());
        }
    }

    /**
     * `/api/v1/company/*` now serves the tenant-staff model only (`TenantStaffCompanyRolesController`);
     * the legacy `CompanyRolesController`/`/auth/login` global-user HTTP path tested here no longer
     * has a route. `TenantAuthorizationService` is still the real gate used by `listRoles()`
     * internally, so this proof calls it directly. See TenantIsolationTest's class docblock
     * for the same note.
     */
    public function test_no_permission_by_default_and_http_role_view_gate(): void
    {
        [, $company] = $this->bootstrap();
        [, $member, $context] = $this->member($company, 'plain');
        $service = app(TenantAuthorizationService::class);
        $snapshot = $service->snapshot($context);
        $this->assertSame([], $snapshot['grants']);
        $this->assertSame($member->id, $snapshot['membership_id']);
        try {
            $service->listRoles($context);
            $this->fail('A membership with no role.view grant listed roles.');
        } catch (AuthorizationDeniedException $exception) {
            $this->assertInstanceOf(AuthorizationDeniedException::class, $exception);
        }
    }

    public function test_delegation_self_escalation_and_cross_tenant_are_denied(): void
    {
        [, $company] = $this->bootstrap();
        [$targetUser, $target, $targetContext] = $this->member($company, 'target');
        $mutations = app(TenantRoleMutationService::class);
        try { $mutations->createRole($targetContext, 'Forbidden'); $this->fail('No-capability actor created role.'); }
        catch (AuthorizationDeniedException) { $this->assertTrue(true); }

        $roleId = $mutations->createRole($company, 'Viewer');
        $mutations->updateRoleGrants($company, $roleId, [['permission' => 'role.view', 'scope' => null]]);
        $mutations->assignRole($company, $target->id, $roleId);
        $this->assertSame(2, (int) DB::table('tenant_memberships')->where('id', $target->id)->value('authorization_version'));
        $this->assertSame(2, (int) DB::table('roles')->where('id', $roleId)->value('version'));
        try { $mutations->assignRole($company, $company->membershipId, $roleId); $this->fail('Self-assignment succeeded.'); }
        catch (AuthorizationDeniedException) { $this->assertTrue(true); }
        try { $mutations->updateRoleGrants($company, $roleId, [['permission' => 'company.administer', 'scope' => 'ALL_TENANT']]); $this->fail('Admin grant succeeded.'); }
        catch (AuthorizationDeniedException) { $this->assertTrue(true); }
        try { $mutations->updateRoleGrants($company, $roleId, [['permission' => 'provider.payments', 'scope' => null]]); $this->fail('Provider grant succeeded.'); }
        catch (AuthorizationDeniedException) { $this->assertTrue(true); }
        [$bUser, $b] = $this->bootstrap('company-b');
        $bRole = DB::table('roles')->where('tenant_id', $b->tenantId)->value('id');
        try { $mutations->assignRole($company, $target->id, $bRole); $this->fail('Cross-company role assignment succeeded.'); }
        catch (AuthorizationDeniedException) { $this->assertTrue(true); }
        $this->assertSame($company->tenantId, DB::table('roles')->where('id', $roleId)->value('tenant_id'));
    }

    public function test_grant_assignment_revoke_and_role_edit_are_fresh(): void
    {
        [, $company] = $this->bootstrap();
        [$user, $member, $context] = $this->member($company, 'grantee');
        $mutations = app(TenantRoleMutationService::class);
        $auth = app(TenantAuthorizationService::class);
        $roleId = $mutations->createRole($company, 'Reader');
        $mutations->updateRoleGrants($company, $roleId, [['permission' => 'role.view', 'scope' => null]]);
        $mutations->assignRole($company, $member->id, $roleId);
        $fresh = new TenantContext($context->userId, $context->tenantId, $context->membershipId, 2, 0, $context->requestId);
        $this->assertArrayHasKey('role.view', $auth->snapshot($fresh)['grants']);
        $this->expectException(\App\Modules\Tenancy\Domain\TenantAccessException::class);
        $auth->snapshot($context);
    }

    /** Each "next request" below is simulated by rebuilding TenantContext from the current
     * membership authorization_version, exactly as the per-request middleware would. */
    public function test_http_grant_edit_and_revoke_take_effect_on_next_request(): void
    {
        [, $company] = $this->bootstrap();
        [, $member, $context] = $this->member($company, 'http-grantee');
        $mutations = app(TenantRoleMutationService::class);
        $auth = app(TenantAuthorizationService::class);
        $roleId = $mutations->createRole($company, 'Http Reader');
        $mutations->updateRoleGrants($company, $roleId, [['permission' => 'role.view', 'scope' => null]]);

        $this->expectDenied($auth, $context);
        $mutations->assignRole($company, $member->id, $roleId);
        $context = $this->refreshed($context, $member->id);
        $auth->listRoles($context);
        $this->assertSame(2, $auth->snapshot($context)['authorization_version']);

        $mutations->updateRoleGrants($company, $roleId, []);
        $this->assertSame(3, (int) DB::table('roles')->where('id', $roleId)->value('version'));
        $this->expectDenied($auth, $context);
        $mutations->updateRoleGrants($company, $roleId, [['permission' => 'role.view', 'scope' => null]]);
        $auth->listRoles($context);
        $mutations->revokeRole($company, $member->id, $roleId);
        $this->assertSame(3, (int) DB::table('tenant_memberships')->where('id', $member->id)->value('authorization_version'));
        $context = $this->refreshed($context, $member->id);
        $this->expectDenied($auth, $context);
    }

    private function expectDenied(TenantAuthorizationService $auth, TenantContext $context): void
    {
        try {
            $auth->listRoles($context);
            $this->fail('listRoles() succeeded without a current role.view grant.');
        } catch (AuthorizationDeniedException) {
            $this->assertTrue(true);
        }
    }

    private function refreshed(TenantContext $context, string $membershipId): TenantContext
    {
        $version = (int) DB::table('tenant_memberships')->where('id', $membershipId)->value('authorization_version');
        return new TenantContext($context->userId, $context->tenantId, $context->membershipId,
            $version, $context->identityAuthVersion, $context->requestId);
    }

    public function test_reactivation_checks_global_cardinality_and_delegation_ceiling(): void
    {
        [, $company] = $this->bootstrap();
        [$user, $member] = $this->member($company, 'reactivate');
        DB::table('tenant_memberships')->where('id', $member->id)->update(['status' => 'SUSPENDED']);
        $mutations = app(TenantRoleMutationService::class);
        $mutations->reactivateMembership($company, $member->id);
        $this->assertSame('ACTIVE', DB::table('tenant_memberships')->where('id', $member->id)->value('status'));
        $this->assertSame(2, (int) DB::table('tenant_memberships')->where('id', $member->id)->value('authorization_version'));

        $adminRole = Role::query()->where('tenant_id', $company->tenantId)->where('normalized_name', 'company_admin')->firstOrFail();
        $this->attach($company, $member->id, $adminRole);
        DB::table('tenant_memberships')->where('id', $member->id)->update(['status' => 'SUSPENDED']);
        try { $mutations->reactivateMembership($company, $member->id); $this->fail('Admin grant was reactivated by ordinary service.'); }
        catch (AuthorizationDeniedException) { $this->assertTrue(true); }
    }

    public function test_template_revision_does_not_mutate_instantiated_role(): void
    {
        [, $company] = $this->bootstrap();
        $role = DB::table('roles')->where('tenant_id', $company->tenantId)->first();
        $before = DB::table('role_permissions')->where('role_id', $role->id)->orderBy('permission_key')->pluck('permission_key')->all();
        $secondTemplateId = (string) Str::uuid7();
        DB::table('role_templates')->insert([
            'id' => $secondTemplateId, 'code' => 'company_admin', 'version' => 2,
            'display_name' => 'Future template', 'status' => 'ACTIVE',
        ]);
        $this->assertSame($role->source_template_id, DB::table('roles')->where('id', $role->id)->value('source_template_id'));
        $this->assertNotSame($secondTemplateId, $role->source_template_id);
        $this->assertSame($before, DB::table('role_permissions')->where('role_id', $role->id)->orderBy('permission_key')->pluck('permission_key')->all());
    }

    /**
     * "Forged markers" (`X-Tenant-ID`, query selectors) are not re-tested here: the
     * `TenantAuthorizationService`/`TenantContext` layer takes no such input at all (see
     * TenantIsolationTest's class docblock). What remains meaningful — a company's own
     * admin can only ever list its own tenant's roles — is asserted below.
     */
    public function test_roles_api_lists_only_current_company_and_forged_markers_do_not_switch(): void
    {
        [, $a] = $this->bootstrap();
        [, $b] = $this->bootstrap('company-b');
        $aRoleId = DB::table('roles')->where('tenant_id', $a->tenantId)->value('id');
        $bRoleId = DB::table('roles')->where('tenant_id', $b->tenantId)->value('id');
        $roles = app(TenantAuthorizationService::class)->listRoles($a);
        $this->assertSame([$aRoleId], array_column($roles, 'id'));
        $this->assertNotContains($bRoleId, array_column($roles, 'id'));
    }

    public function test_catalog_metadata_inconsistency_fails_closed(): void
    {
        [, $company] = $this->bootstrap();
        $roleId = DB::table('roles')->where('tenant_id', $company->tenantId)->value('id');
        DB::table('role_permissions')->where('tenant_id', $company->tenantId)
            ->where('role_id', $roleId)->where('permission_key', 'role.view')
            ->update(['scope' => 'SELF']);
        $this->expectException(AuthorizationDeniedException::class);
        app(TenantAuthorizationService::class)->snapshot($company);
    }

    public function test_last_admin_is_preserved_across_membership_role_and_grant_mutations(): void
    {
        [, $founder] = $this->bootstrap();
        [, $managerMember, $manager] = $this->member($founder, 'manager');
        $managerRole = $this->role($founder, 'manager', [
            ['role.manage', null], ['member.manage', null], ['role.view', null], ['member.view', null],
        ]);
        $this->attach($founder, $managerMember->id, $managerRole);
        $adminRoleId = DB::table('roles')->where('tenant_id', $founder->tenantId)->where('normalized_name', 'company_admin')->value('id');
        $mutations = app(TenantRoleMutationService::class);
        foreach ([
            fn () => $mutations->suspendMembership($manager, $founder->membershipId),
            fn () => $mutations->revokeRole($manager, $founder->membershipId, $adminRoleId),
            fn () => $mutations->archiveRole($manager, $adminRoleId),
            fn () => $mutations->updateRoleGrants($manager, $adminRoleId, [
                ['permission' => 'role.view', 'scope' => null], ['permission' => 'role.manage', 'scope' => null],
                ['permission' => 'member.view', 'scope' => null], ['permission' => 'member.manage', 'scope' => null],
            ]),
        ] as $operation) {
            try { $operation(); $this->fail('Last admin was removed.'); }
            catch (AuthorizationDeniedException) { $this->assertTrue(true); }
        }
        $this->assertSame('ACTIVE', DB::table('tenant_memberships')->where('id', $founder->membershipId)->value('status'));
        $this->assertSame('ACTIVE', DB::table('roles')->where('id', $adminRoleId)->value('status'));
        $this->assertSame('ALL_TENANT', DB::table('role_permissions')->where('role_id', $adminRoleId)->where('permission_key', 'company.administer')->value('scope'));
    }

    public function test_two_admins_can_reduce_to_one_but_not_zero(): void
    {
        [, $founder] = $this->bootstrap();
        [, $second, $secondContext] = $this->member($founder, 'second-admin');
        [, $managerMember, $manager] = $this->member($founder, 'manager-two');
        $adminRole = DB::table('roles')->where('tenant_id', $founder->tenantId)->where('normalized_name', 'company_admin')->first();
        $this->attach($founder, $second->id, Role::query()->findOrFail($adminRole->id));
        $managerRole = $this->role($founder, 'manager_two', [['member.manage', null]]);
        $this->attach($founder, $managerMember->id, $managerRole);
        $mutations = app(TenantRoleMutationService::class);
        $mutations->suspendMembership($manager, $second->id);
        $this->assertSame('SUSPENDED', DB::table('tenant_memberships')->where('id', $second->id)->value('status'));
        try { $mutations->suspendMembership($manager, $founder->membershipId); $this->fail('Zero-admin transition succeeded.'); }
        catch (AuthorizationDeniedException) { $this->assertSame('ACTIVE', DB::table('tenant_memberships')->where('id', $founder->membershipId)->value('status')); }
    }

    public function test_global_disable_cannot_remove_final_effective_admin(): void
    {
        [$founderUser, $company] = $this->bootstrap();
        try {
            app(UserAccountStatusService::class)->disable($founderUser);
            $this->fail('Final admin was globally disabled.');
        } catch (AuthorizationDeniedException) {
            $this->assertSame('ACTIVE', DB::table('users')->where('id', $founderUser->id)->value('status'));
        }

        [$otherUser, $otherMembership] = $this->member($company, 'other-admin');
        $adminRole = Role::query()->where('tenant_id', $company->tenantId)
            ->where('normalized_name', 'company_admin')->firstOrFail();
        $this->attach($company, $otherMembership->id, $adminRole);
        app(UserAccountStatusService::class)->disable($otherUser);
        $this->assertSame('DISABLED', DB::table('users')->where('id', $otherUser->id)->value('status'));
        $this->assertSame('ACTIVE', DB::table('users')->where('id', $founderUser->id)->value('status'));
    }

    public function test_cross_company_composite_keys_and_duplicates_are_database_enforced(): void
    {
        [, $a] = $this->bootstrap();
        [, $b] = $this->bootstrap('company-b');
        $aRole = DB::table('roles')->where('tenant_id', $a->tenantId)->value('id');
        $bRole = DB::table('roles')->where('tenant_id', $b->tenantId)->value('id');
        $this->assertPgViolation(fn () => DB::table('membership_roles')->insert([
            'tenant_id' => $a->tenantId, 'membership_id' => $a->membershipId,
            'role_id' => $bRole, 'assigned_at' => now(),
        ]), '23503');
        $this->assertPgViolation(fn () => DB::table('role_permissions')->insert([
            'tenant_id' => $a->tenantId, 'role_id' => $bRole,
            'permission_key' => 'role.view', 'scope' => null,
        ]), '23503');
        $this->assertPgViolation(fn () => DB::table('membership_roles')->insert([
            'tenant_id' => $a->tenantId, 'membership_id' => $a->membershipId,
            'role_id' => $aRole, 'assigned_at' => now(),
        ]), '23505');
        $this->assertPgViolation(fn () => DB::table('role_permissions')->insert([
            'tenant_id' => $a->tenantId, 'role_id' => $aRole,
            'permission_key' => 'role.view', 'scope' => 'INVALID',
        ]), '23514');
    }
}
