<?php

namespace Tests\Feature\Audit;

use App\Modules\Identity\Application\UserAccountStatusService;
use App\Modules\Identity\Infrastructure\Persistence\User;
use App\Modules\Shared\Audit\AuditEventType;
use App\Modules\Shared\Audit\SecurityAuditWriter;
use App\Modules\Tenancy\Application\CompanyAdminBootstrap;
use App\Modules\Tenancy\Application\TenantRoleMutationService;
use App\Modules\Tenancy\Domain\TenantContext;
use App\Modules\Tenancy\Infrastructure\Persistence\TenantMembership;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use LogicException;
use Tests\TestCase;

final class SecurityAuditTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        config(['tenancy.disposable_bootstrap_enabled' => true]);
    }

    private function bootstrap(): array
    {
        $user = User::query()->create([
            'email' => 'audit-founder-'.Str::random(12).'@proof.invalid',
            'password' => 'disposable proof only',
        ]);
        $context = app(CompanyAdminBootstrap::class)->create($user, [
            'display_name' => 'Audit proof', 'slug' => 'audit-'.Str::lower(Str::random(12)),
            'timezone' => 'UTC', 'default_locale' => 'en',
        ], (string) Str::uuid());

        return [$user, $context];
    }

    private function member(TenantContext $tenant): array
    {
        $user = User::query()->create([
            'email' => 'audit-member-'.Str::random(12).'@proof.invalid',
            'password' => 'disposable proof only',
        ]);
        $membership = TenantMembership::query()->create([
            'tenant_id' => $tenant->tenantId, 'user_id' => $user->id, 'joined_at' => now(),
        ]);
        $membership->forceFill(['status' => 'ACTIVE'])->save();

        return [$user, $membership->fresh()];
    }

    private function rawEvent(array $overrides = []): array
    {
        $actorId = (string) Str::uuid7();
        return array_replace([
            'id' => (string) Str::uuid7(), 'category' => 'PROVIDER_SECURITY',
            'event_type' => 'provider.mfa.enrolled', 'outcome' => 'SUCCESS',
            'actor_type' => 'PROVIDER_USER', 'actor_id' => $actorId,
            'tenant_id' => null, 'target_type' => 'provider_user',
            'target_id' => $actorId, 'source_channel' => 'PROVIDER',
            'metadata' => '{}',
        ], $overrides);
    }

    private function assertCheckFails(array $row): void
    {
        try {
            DB::transaction(fn () => DB::table('security_audit_events')->insert($row));
            $this->fail('Invalid audit row was accepted.');
        } catch (QueryException $exception) {
            $this->assertSame('23514', $exception->errorInfo[0]);
        }
    }

    public function test_schema_vocabulary_provider_actor_and_metadata_are_constrained(): void
    {
        $this->assertCheckFails($this->rawEvent(['actor_type' => 'UNKNOWN']));
        $this->assertCheckFails($this->rawEvent(['category' => 'UNBOUNDED']));
        $this->assertCheckFails($this->rawEvent(['outcome' => 'MAYBE']));
        $this->assertCheckFails($this->rawEvent(['source_channel' => 'UNTRUSTED']));
        $this->assertCheckFails($this->rawEvent(['actor_type' => 'SYSTEM']));
        $this->assertCheckFails($this->rawEvent(['metadata' => '[]']));
        $this->assertCheckFails($this->rawEvent(['metadata' => '{"password":"AUDIT_SECRET_CANARY_10A"}']));
        $this->assertCheckFails($this->rawEvent(['event_type' => 'role.created', 'category' => 'AUTHORIZATION', 'target_type' => 'user']));
        $this->assertCheckFails($this->rawEvent(['event_type' => 'role.created', 'category' => 'AUTHORIZATION', 'target_type' => 'role', 'target_id' => 'not-a-uuid']));

        $provider = $this->rawEvent();
        DB::table('security_audit_events')->insert($provider);
        $this->assertSame($provider['actor_id'], DB::table('security_audit_events')->where('id', $provider['id'])->value('actor_id'));
        $this->assertNull(DB::table('security_audit_events')->where('id', $provider['id'])->value('tenant_id'));
    }

    public function test_bootstrap_writes_one_uuid7_fact_with_db_time_and_archive_preserves_it(): void
    {
        [, $context] = $this->bootstrap();
        $rows = DB::table('security_audit_events')->where('event_type', AuditEventType::COMPANY_ADMIN_BOOTSTRAPPED->value)->get();
        $this->assertCount(1, $rows);
        $this->assertSame('7', $rows[0]->id[14]);
        $this->assertSame('SYSTEM', $rows[0]->actor_type);
        $this->assertNull($rows[0]->actor_id);
        $this->assertSame($context->tenantId, $rows[0]->tenant_id);
        $this->assertSame($context->requestId, $rows[0]->request_id);
        $this->assertNotNull($rows[0]->occurred_at);
        $this->assertStringContainsString('with time zone', DB::selectOne("SELECT format_type(atttypid,atttypmod) AS t FROM pg_attribute WHERE attrelid='security_audit_events'::regclass AND attname='occurred_at'")->t);
        DB::table('tenants')->where('id', $context->tenantId)->update(['status' => 'ARCHIVED', 'archived_at' => now()]);
        $this->assertSame(1, DB::table('security_audit_events')->where('tenant_id', $context->tenantId)->count());
    }

    public function test_role_and_membership_mutations_write_exactly_one_fact_each(): void
    {
        [, $context] = $this->bootstrap();
        [, $member] = $this->member($context);
        $service = app(TenantRoleMutationService::class);
        $roleId = $service->createRole($context, 'Audit Reader');
        $service->updateRoleGrants($context, $roleId, [['permission' => 'role.view', 'scope' => null]]);
        $service->assignRole($context, $member->id, $roleId);
        $service->revokeRole($context, $member->id, $roleId);
        $service->suspendMembership($context, $member->id);
        $service->reactivateMembership($context, $member->id);

        foreach (['role.created', 'role.grants_changed', 'role.assigned', 'role.revoked',
            'membership.suspended', 'membership.reactivated'] as $event) {
            $this->assertSame(1, DB::table('security_audit_events')->where('tenant_id', $context->tenantId)
                ->where('event_type', $event)->count(), $event);
        }
        $grant = DB::table('security_audit_events')->where('event_type', 'role.grants_changed')->first();
        $this->assertSame(['changed_fields' => ['grants']], json_decode($grant->metadata, true, 512, JSON_THROW_ON_ERROR));
        $this->assertSame($context->userId, $grant->actor_id);
        $this->assertSame($context->tenantId, $grant->tenant_id);
        $this->assertSame($roleId, $grant->target_id);
        $this->assertSame('ACTIVE', DB::table('tenant_memberships')->where('id', $member->id)->value('status'));
    }

    public function test_real_postgres_audit_failure_rolls_back_role_assignment_and_version(): void
    {
        [, $context] = $this->bootstrap();
        [, $member] = $this->member($context);
        $service = app(TenantRoleMutationService::class);
        $roleId = $service->createRole($context, 'Fault Reader');
        DB::statement("ALTER TABLE security_audit_events ADD CONSTRAINT audit_test_reject_role_assign CHECK (event_type <> 'role.assigned')");

        try {
            $service->assignRole($context, $member->id, $roleId);
            $this->fail('Assignment committed after audit failure.');
        } catch (QueryException $exception) {
            $this->assertSame('23514', $exception->errorInfo[0]);
        }
        $this->assertSame(0, DB::table('membership_roles')->where('membership_id', $member->id)->where('role_id', $roleId)->count());
        $this->assertSame(1, (int) DB::table('tenant_memberships')->where('id', $member->id)->value('authorization_version'));
        $this->assertSame(0, DB::table('security_audit_events')->where('event_type', 'role.assigned')->count());
        $this->assertContains(DB::selectOne("SELECT current_setting('app.context_mode', true) AS mode")->mode, [null, '']);
    }

    public function test_real_postgres_audit_failure_rolls_back_membership_suspension(): void
    {
        [, $context] = $this->bootstrap();
        [, $member] = $this->member($context);
        DB::statement("ALTER TABLE security_audit_events ADD CONSTRAINT audit_test_reject_suspend CHECK (event_type <> 'membership.suspended')");

        try {
            app(TenantRoleMutationService::class)->suspendMembership($context, $member->id);
            $this->fail('Suspension committed after audit failure.');
        } catch (QueryException $exception) {
            $this->assertSame('23514', $exception->errorInfo[0]);
        }
        $this->assertSame('ACTIVE', DB::table('tenant_memberships')->where('id', $member->id)->value('status'));
        $this->assertSame(1, (int) DB::table('tenant_memberships')->where('id', $member->id)->value('authorization_version'));
        $this->assertSame(0, DB::table('security_audit_events')->where('event_type', 'membership.suspended')->count());
        $this->assertContains(DB::selectOne("SELECT current_setting('app.context_mode', true) AS mode")->mode, [null, '']);
    }

    public function test_global_disable_uses_system_actor_without_impersonating_target(): void
    {
        [, $context] = $this->bootstrap();
        [$otherUser, $member] = $this->member($context);
        $adminRoleId = DB::table('roles')->where('tenant_id', $context->tenantId)
            ->where('normalized_name', 'company_admin')->value('id');
        DB::table('membership_roles')->insert([
            'tenant_id' => $context->tenantId, 'membership_id' => $member->id,
            'role_id' => $adminRoleId, 'assigned_at' => now(),
        ]);
        app(UserAccountStatusService::class)->disable($otherUser);
        $row = DB::table('security_audit_events')->where('event_type', 'user.disabled')->first();
        $this->assertNotNull($row);
        $this->assertSame('SYSTEM', $row->actor_type);
        $this->assertNull($row->actor_id);
        $this->assertSame($otherUser->id, $row->target_id);
        $this->assertSame($context->tenantId, $row->tenant_id);
        $this->assertSame('DISABLED', DB::table('users')->where('id', $otherUser->id)->value('status'));
    }

    public function test_writer_rejects_wrong_event_class_and_has_no_raw_metadata_argument(): void
    {
        [, $context] = $this->bootstrap();
        $writer = app(SecurityAuditWriter::class);
        $this->expectException(LogicException::class);
        $writer->appendTenantMutation($context, AuditEventType::COMPANY_ADMIN_BOOTSTRAPPED, $context->tenantId);
    }
}
