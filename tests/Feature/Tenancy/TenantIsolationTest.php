<?php

namespace Tests\Feature\Tenancy;

use App\Modules\Identity\Infrastructure\Persistence\User;
use App\Modules\Tenancy\Application\ResolveTenantContext;
use App\Modules\Tenancy\Domain\TenantAccessException;
use App\Modules\Tenancy\Domain\TenantContext;
use App\Modules\Tenancy\Infrastructure\Persistence\ActiveMembershipLookup;
use App\Modules\Tenancy\Infrastructure\Persistence\Tenant;
use App\Modules\Tenancy\Infrastructure\Persistence\TenantContextGuard;
use App\Modules\Tenancy\Infrastructure\Persistence\TenantMembership;
use App\Modules\Tenancy\Infrastructure\Persistence\TenantScopedRepository;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Tests\TestCase;

final class ProofRepository extends TenantScopedRepository
{
    protected function table(): string
    {
        return 'tenant_proof_records';
    }
}

final class TenantIsolationTest extends TestCase
{
    use RefreshDatabase;

    private const ORIGIN = 'http://localhost:3001';

    private function user(string $email = 'a@example.test'): User
    {
        return User::query()->create(['email' => $email, 'password' => Hash::make('correct horse battery staple')])->fresh();
    }

    private function tenant(string $slug): Tenant
    {
        $tenant = Tenant::query()->create([
            'display_name' => strtoupper($slug), 'slug' => $slug,
            'timezone' => 'Africa/Cairo', 'default_locale' => 'ar',
        ]);
        $tenant->forceFill(['status' => 'ACTIVE'])->save();
        return $tenant->fresh();
    }

    private function member(User $user, Tenant $tenant, string $status = 'ACTIVE'): TenantMembership
    {
        $member = TenantMembership::query()->create([
            'user_id' => $user->id, 'tenant_id' => $tenant->id, 'joined_at' => now(),
        ]);
        $member->forceFill(['status' => $status])->save();
        return $member->fresh();
    }

    private function login(User $user): void
    {
        $this->withHeaders(['Origin' => self::ORIGIN, 'Accept' => 'application/json'])
            ->postJson('/api/v1/auth/login', ['email' => $user->email, 'password' => 'correct horse battery staple'])
            ->assertOk();
    }

    private function context(User $user, Tenant $tenant, TenantMembership $member): TenantContext
    {
        return new TenantContext($user->id, $tenant->id, $member->id, $member->authorization_version,
            $user->auth_version, (string) Str::uuid());
    }

    public function test_native_uuidv7_and_postgresql_schema_constraints(): void
    {
        $user = $this->user();
        $tenant = $this->tenant('company-a');
        $member = $this->member($user, $tenant);
        $this->assertSame('7', substr($tenant->id, 14, 1));
        $this->assertSame('7', substr($member->id, 14, 1));
        $this->assertSame('uuid', DB::selectOne("SELECT data_type FROM information_schema.columns WHERE table_name='tenants' AND column_name='id'")->data_type);
        $this->assertSame('uuid', DB::selectOne("SELECT data_type FROM information_schema.columns WHERE table_name='tenant_memberships' AND column_name='tenant_id'")->data_type);

        foreach ([
            fn () => DB::table('tenants')->where('id', $tenant->id)->update(['status' => 'PAID']),
            fn () => DB::table('tenants')->where('id', $tenant->id)->update(['slug' => 'BAD SLUG']),
            fn () => DB::table('tenant_memberships')->where('id', $member->id)->update(['status' => 'INVITED']),
            fn () => DB::table('tenant_memberships')->where('id', $member->id)->update(['authorization_version' => 0]),
        ] as $invalid) {
            try { DB::transaction($invalid); $this->fail('A PostgreSQL CHECK constraint did not reject invalid state.'); }
            catch (QueryException $exception) { $this->assertSame('23514', $exception->errorInfo[0]); }
        }
    }

    public function test_tenant_model_rejects_unsupported_timezone_and_locale(): void
    {
        foreach ([
            ['timezone' => 'Not/A_Zone', 'default_locale' => 'ar'],
            ['timezone' => 'Africa/Cairo', 'default_locale' => 'unsupported'],
        ] as $invalid) {
            try {
                Tenant::query()->create(['display_name' => 'Invalid', 'slug' => 'invalid-'.Str::random(6), ...$invalid]);
                $this->fail('Invalid tenant setting was accepted.');
            } catch (\InvalidArgumentException $exception) {
                $this->assertNotEmpty($exception->getMessage());
            }
        }
    }

    public function test_slug_membership_and_one_active_company_uniqueness(): void
    {
        $user = $this->user();
        $a = $this->tenant('company-a');
        $b = $this->tenant('company-b');
        $this->member($user, $a);
        $suspended = $this->member($user, $b, 'SUSPENDED');
        $this->assertSame(1, DB::table('tenant_memberships')->where('user_id', $user->id)->where('status', 'ACTIVE')->count());
        try {
            DB::transaction(fn () => DB::table('tenant_memberships')->where('id', $suspended->id)->update(['status' => 'ACTIVE']));
            $this->fail('Partial unique index failed.');
        } catch (QueryException $exception) {
            $this->assertSame('23505', $exception->errorInfo[0]);
        }
        $this->assertSame('SUSPENDED', DB::table('tenant_memberships')->where('id', $suspended->id)->value('status'));
        foreach ([
            fn () => $this->member($user, $a, 'SUSPENDED'),
            fn () => $this->tenant('company-a'),
        ] as $duplicate) {
            try { DB::transaction($duplicate); $this->fail('Unique constraint failed.'); }
            catch (QueryException $exception) { $this->assertSame('23505', $exception->errorInfo[0]); }
        }
    }

    /**
     * The legacy global-`users` guard has no HTTP entry point any more: `/api/v1/auth/login`
     * and `/api/v1/company/*` now serve the tenant-staff model exclusively (see
     * docs/TENANT_STAFF_IDENTITY_AND_RBAC_FOUNDATION.md). `ResolveTenantContext` and
     * `TenantContextGuard` remain real internal services — used by `CompanyAdminBootstrap`
     * and the RLS/audit fixtures below — so this proof now calls them directly instead of
     * through the retired route. The HTTP-level contract for the tenant-staff model is
     * Eng06CompanyContextAuthorizationTest (tracked separately; needs its own acceptance DB).
     */
    public function test_zero_one_and_suspended_membership_resolution(): void
    {
        $user = $this->user();
        $tenant = $this->tenant('company-a');
        $resolve = app(ResolveTenantContext::class);
        try {
            $resolve->resolve($user->id, 0, (string) Str::uuid());
            $this->fail('A user with no membership resolved a tenant context.');
        } catch (TenantAccessException $exception) {
            $this->assertSame('TENANT_MEMBERSHIP_REQUIRED', $exception->safeCode);
        }
        $member = $this->member($user, $tenant, 'SUSPENDED');
        try {
            $resolve->resolve($user->id, 0, (string) Str::uuid());
            $this->fail('A suspended membership resolved a tenant context.');
        } catch (TenantAccessException $exception) {
            $this->assertSame('TENANT_MEMBERSHIP_REQUIRED', $exception->safeCode);
        }
        $member->forceFill(['status' => 'ACTIVE'])->save();
        $context = $resolve->resolve($user->id, 0, (string) Str::uuid());
        $this->assertSame($tenant->id, $context->tenantId);
        $this->assertSame($member->id, $context->membershipId);
    }

    public function test_every_nonactive_tenant_denies_without_logging_out_identity(): void
    {
        $user = $this->user();
        $tenant = $this->tenant('company-a');
        $this->member($user, $tenant);
        $resolve = app(ResolveTenantContext::class);
        foreach (['PROVISIONING', 'SUSPENDED', 'ARCHIVED'] as $state) {
            DB::table('tenants')->where('id', $tenant->id)->update(['status' => $state]);
            try {
                $resolve->resolve($user->id, 0, (string) Str::uuid());
                $this->fail("A {$state} tenant resolved a context.");
            } catch (TenantAccessException $exception) {
                $this->assertSame('TENANT_UNAVAILABLE', $exception->safeCode);
            }
        }
    }

    /**
     * Retired: this proved that the old `/company/context` controller never read
     * `X-Tenant-ID` / query / cookie / `X-Role` selectors. That controller no longer
     * exists (see the class docblock above); `ResolveTenantContext::resolve()` takes
     * no selector argument at all, so the property it protects against is now a type
     * signature, not runtime behavior worth re-asserting here.
     */
    public function test_forged_selector_query_body_cookie_and_role_markers_do_not_switch_company(): void
    {
        $this->markTestSkipped('Superseded: legacy /company/context route removed; see class docblock.');
    }

    public function test_global_disable_and_auth_version_revoke_before_tenant_resolution(): void
    {
        $user = $this->user();
        $tenant = $this->tenant('company-a');
        $member = $this->member($user, $tenant);
        $context = $this->context($user, $tenant, $member);
        $guard = app(TenantContextGuard::class);

        DB::table('users')->where('id', $user->id)->increment('auth_version');
        try {
            $guard->run($context, fn () => 'must not run');
            $this->fail('A stale identity auth_version still passed the tenant context guard.');
        } catch (TenantAccessException $exception) {
            $this->assertSame('TENANT_CONTEXT_REQUIRED', $exception->safeCode);
        }

        // TenantContext is immutable and has no wither; rebuild it with the now-current auth_version.
        $freshVersion = (int) DB::table('users')->where('id', $user->id)->value('auth_version');
        $disabledContext = new TenantContext(
            $user->id, $tenant->id, $member->id, $member->authorization_version, $freshVersion, (string) Str::uuid(),
        );
        DB::table('users')->where('id', $user->id)->update(['status' => 'DISABLED']);
        try {
            $guard->run($disabledContext, fn () => 'must not run');
            $this->fail('A disabled identity still passed the tenant context guard.');
        } catch (TenantAccessException $exception) {
            $this->assertSame('TENANT_CONTEXT_REQUIRED', $exception->safeCode);
        }
    }

    public function test_defensive_multiple_membership_result_fails_closed(): void
    {
        $user = $this->user();
        $fakeLookup = \Mockery::mock(ActiveMembershipLookup::class);
        $fakeLookup->shouldReceive('forUser')->once()->with($user->id)
            ->andReturn(collect([(object) ['id' => (string) Str::uuid(), 'tenant_id' => (string) Str::uuid(), 'authorization_version' => 1],
                (object) ['id' => (string) Str::uuid(), 'tenant_id' => (string) Str::uuid(), 'authorization_version' => 1]]));
        $this->app->instance(ActiveMembershipLookup::class, $fakeLookup);
        $this->expectException(TenantAccessException::class);
        app(ResolveTenantContext::class)->resolve($user->id, 0, (string) Str::uuid());
    }

    public function test_request_context_does_not_bleed_to_another_user(): void
    {
        $aUser = $this->user();
        $tenant = $this->tenant('company-a');
        $this->member($aUser, $tenant);
        $context = app(ResolveTenantContext::class)->resolve($aUser->id, 0, (string) Str::uuid());
        $this->assertSame($tenant->id, $context->tenantId);
        $this->assertNull(request()->attributes->get('tenant_context'));
        try {
            app(TenantContextGuard::class)->run(null, fn () => 'must not run');
            $this->fail('Contextless access was allowed.');
        } catch (TenantAccessException $exception) {
            $this->assertSame('TENANT_CONTEXT_REQUIRED', $exception->safeCode);
        }
    }

    public function test_scoped_repository_denies_cross_company_read_write_count_and_relation(): void
    {
        Schema::create('tenant_proof_records', function (Blueprint $table): void {
            $table->uuid('id')->primary(); $table->uuid('tenant_id'); $table->string('label');
            $table->unique(['tenant_id', 'id']);
        });
        Schema::create('tenant_proof_links', function (Blueprint $table): void {
            $table->uuid('id')->primary(); $table->uuid('tenant_id'); $table->uuid('record_id');
            $table->foreign(['tenant_id', 'record_id'])->references(['tenant_id', 'id'])->on('tenant_proof_records')->restrictOnDelete();
        });
        $aUser = $this->user(); $bUser = $this->user('b@example.test');
        $a = $this->tenant('company-a'); $b = $this->tenant('company-b');
        $aMember = $this->member($aUser, $a); $bMember = $this->member($bUser, $b);
        $aContext = $this->context($aUser, $a, $aMember);
        $bContext = $this->context($bUser, $b, $bMember);
        $repository = app(ProofRepository::class);
        $aId = (string) Str::uuid7(); $bId = (string) Str::uuid7();
        $repository->create($aContext, ['id' => $aId, 'label' => 'A']);
        $repository->create($bContext, ['id' => $bId, 'label' => 'B']);
        $this->assertSame(1, $repository->count($aContext));
        $this->assertSame('A', $repository->find($aContext, $aId)->label);
        $this->assertNull($repository->find($aContext, $bId));
        $this->assertFalse($repository->update($aContext, $bId, ['label' => 'hijacked']));
        $this->assertFalse($repository->delete($aContext, $bId));
        $this->assertSame('B', $repository->find($bContext, $bId)->label);
        try {
            DB::transaction(fn () => DB::table('tenant_proof_links')->insert(['id' => (string) Str::uuid7(), 'tenant_id' => $a->id, 'record_id' => $bId]));
            $this->fail('Cross-tenant relation was accepted.');
        } catch (QueryException $exception) { $this->assertSame('23503', $exception->errorInfo[0]); }
        $this->expectException(TenantAccessException::class);
        $repository->find(null, $aId);
    }

    public function test_context_is_readonly_and_stale_grant_denies_repository_access(): void
    {
        $user = $this->user(); $tenant = $this->tenant('company-a'); $member = $this->member($user, $tenant);
        $context = $this->context($user, $tenant, $member);
        $this->assertTrue((new \ReflectionClass(TenantContext::class))->isReadOnly());
        DB::table('tenant_memberships')->where('id', $member->id)->update(['status' => 'SUSPENDED', 'authorization_version' => 2]);
        $this->expectException(TenantAccessException::class);
        app(TenantContextGuard::class)->run($context, fn () => 'must not run');
    }
}
