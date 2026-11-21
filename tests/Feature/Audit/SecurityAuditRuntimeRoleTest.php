<?php

namespace Tests\Feature\Audit;

use App\Modules\Identity\Infrastructure\Persistence\User;
use App\Modules\Identity\Application\UserAccountStatusService;
use App\Modules\Shared\Audit\AuditEventType;
use App\Modules\Shared\Audit\SecurityAuditWriter;
use App\Modules\Tenancy\Application\CompanyAdminBootstrap;
use App\Modules\Tenancy\Application\TenantRoleMutationService;
use App\Modules\Tenancy\Domain\TenantContext;
use App\Modules\Tenancy\Infrastructure\Persistence\TenantMembership;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use LogicException;
use PDO;
use PDOException;
use RuntimeException;
use Tests\TestCase;

/** Disposable PostgreSQL owner fixtures plus real non-owner runtime proof. */
final class SecurityAuditRuntimeRoleTest extends TestCase
{
    private array $tenantIds = [];
    private array $userIds = [];
    private TenantContext $actorA;
    private TenantContext $actorB;
    private string $targetMembershipId;
    private string $targetUserId;

    protected function setUp(): void
    {
        parent::setUp();
        if (! getenv('AUDIT_TEST_RUNTIME_USER') || ! getenv('AUDIT_TEST_RUNTIME_PASSWORD')) {
            $this->markTestSkipped('Control 10A non-owner runtime role is not configured.');
        }
        $db = DB::selectOne('SELECT current_database() AS db')->db;
        $allowed = ($db === 'daleel_crm_b10a_disposable' && config('database.connections.pgsql.port') == 55436)
            || ($db === 'daleel_crm_b10b_disposable' && config('database.connections.pgsql.port') == 55437)
            || ($db === 'daleel_crm_b10c_closeout_disposable' && config('database.connections.pgsql.port') == 55439)
            || ($db === 'daleel_crm_b10c04_disposable' && config('database.connections.pgsql.port') == 55440);
        if (! $allowed) {
            throw new RuntimeException('Refusing audit fixtures outside the exact 10A disposable PostgreSQL.');
        }
        config(['tenancy.disposable_bootstrap_enabled' => true]);
        $suffix = Str::lower(Str::random(10));
        foreach (['a', 'b'] as $letter) {
            $user = User::query()->create([
                'email' => "audit-runtime-{$letter}-{$suffix}@proof.invalid",
                'password' => 'disposable proof only',
            ]);
            $this->userIds[] = $user->id;
            $context = app(CompanyAdminBootstrap::class)->create($user, [
                'display_name' => "Audit runtime {$letter}", 'slug' => "audit-runtime-{$letter}-{$suffix}",
                'timezone' => 'UTC', 'default_locale' => 'en',
            ], (string) Str::uuid());
            $this->tenantIds[] = $context->tenantId;
            if ($letter === 'a') {
                $this->actorA = $context;
            } else {
                $this->actorB = $context;
            }
        }
        $target = User::query()->create([
            'email' => "audit-target-{$suffix}@proof.invalid", 'password' => 'disposable proof only',
        ]);
        $this->userIds[] = $target->id;
        $this->targetUserId = $target->id;
        $membership = TenantMembership::query()->create([
            'tenant_id' => $this->actorA->tenantId, 'user_id' => $target->id, 'joined_at' => now(),
        ]);
        $membership->forceFill(['status' => 'ACTIVE'])->save();
        $this->targetMembershipId = $membership->id;
    }

    protected function tearDown(): void
    {
        DB::setDefaultConnection('pgsql');
        DB::purge('audit_runtime');
        if ($this->tenantIds !== []) {
            // Fixture owner cleanup only; ordinary runtime has no audit DELETE.
            DB::table('security_audit_events')->whereIn('tenant_id', $this->tenantIds)->delete();
            foreach (['membership_roles', 'role_permissions', 'roles', 'tenant_memberships'] as $table) {
                DB::table($table)->whereIn('tenant_id', $this->tenantIds)->delete();
            }
            DB::table('tenants')->whereIn('id', $this->tenantIds)->delete();
            DB::table('users')->whereIn('id', $this->userIds)->delete();
        }
        parent::tearDown();
    }

    private function runtime(): PDO
    {
        $cfg = config('database.connections.pgsql');
        return new PDO("pgsql:host={$cfg['host']};port={$cfg['port']};dbname={$cfg['database']}",
            getenv('AUDIT_TEST_RUNTIME_USER'), getenv('AUDIT_TEST_RUNTIME_PASSWORD'),
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_EMULATE_PREPARES => false]);
    }

    private function runtimeDefault(callable $operation): mixed
    {
        config(['database.connections.audit_runtime' => [
            ...config('database.connections.pgsql'),
            'username' => getenv('AUDIT_TEST_RUNTIME_USER'),
            'password' => getenv('AUDIT_TEST_RUNTIME_PASSWORD'),
        ]]);
        DB::purge('audit_runtime');
        DB::setDefaultConnection('audit_runtime');
        try {
            return $operation();
        } finally {
            DB::setDefaultConnection('pgsql');
            DB::purge('audit_runtime');
        }
    }

    private function expectSqlState(callable $operation, string $state): void
    {
        try {
            $operation();
            $this->fail("PostgreSQL accepted forbidden audit operation {$state}.");
        } catch (PDOException $exception) {
            $this->assertSame($state, $exception->getCode());
        }
    }

    private function setLocal(PDO $pdo, TenantContext $context): void
    {
        foreach (['app.user_id' => $context->userId, 'app.tenant_id' => $context->tenantId,
            'app.context_mode' => 'TENANT'] as $key => $value) {
            $pdo->prepare('SELECT set_config(?, ?, true)')->execute([$key, $value]);
        }
    }

    private function rawRow(TenantContext $actor, array $overrides = []): array
    {
        return array_replace([
            'id' => (string) Str::uuid7(), 'category' => 'AUTHORIZATION',
            'event_type' => 'role.created', 'outcome' => 'SUCCESS',
            'actor_type' => 'TENANT_USER', 'actor_id' => $actor->userId,
            'tenant_id' => $actor->tenantId, 'target_type' => 'role',
            'target_id' => (string) Str::uuid7(), 'source_channel' => 'INTERNAL',
            'metadata' => '{}',
        ], $overrides);
    }

    private function rawInsert(PDO $pdo, array $row): void
    {
        $columns = array_keys($row);
        $sql = 'INSERT INTO security_audit_events ('.implode(',', $columns).') VALUES ('
            .implode(',', array_fill(0, count($columns), '?')).')';
        $pdo->prepare($sql)->execute(array_values($row));
    }

    public function test_role_flags_rls_grants_and_no_generic_read_or_mutation(): void
    {
        $pdo = $this->runtime();
        $role = $pdo->query("SELECT current_user, session_user, current_database() AS db,
            rolsuper, rolbypassrls, rolcreaterole, rolcreatedb FROM pg_roles WHERE rolname=current_user")
            ->fetch(PDO::FETCH_ASSOC);
        $is10c04 = $role['db'] === 'daleel_crm_b10c04_disposable';
        $is10b = in_array($role['db'], ['daleel_crm_b10b_disposable', 'daleel_crm_b10c_closeout_disposable'], true);
        $this->assertSame($is10c04 ? 'daleel_b10c04_tenant_runtime'
            : ($is10b ? 'daleel_b10b_tenant_runtime' : 'daleel_b10a_runtime'), $role['current_user']);
        $this->assertSame($role['current_user'], $role['session_user']);
        $this->assertContains($role['db'], ['daleel_crm_b10a_disposable', 'daleel_crm_b10b_disposable', 'daleel_crm_b10c_closeout_disposable', 'daleel_crm_b10c04_disposable']);
        foreach (['rolsuper', 'rolbypassrls', 'rolcreaterole', 'rolcreatedb'] as $flag) {
            $this->assertFalse((bool) $role[$flag]);
        }
        $catalog = $pdo->query("SELECT c.relrowsecurity,c.relforcerowsecurity,pg_get_userbyid(c.relowner) AS owner
            FROM pg_class c WHERE c.oid='security_audit_events'::regclass")->fetch(PDO::FETCH_ASSOC);
        $this->assertTrue((bool) $catalog['relrowsecurity']);
        $this->assertTrue((bool) $catalog['relforcerowsecurity']);
        $this->assertSame($is10c04 ? 'daleel_b10c04_owner'
            : ($is10b ? 'daleel_b10b_owner' : 'daleel_b10a_owner'), $catalog['owner']);
        $priv = $pdo->query("SELECT has_schema_privilege(current_user,'public','CREATE') AS schema_create,
            has_table_privilege(current_user,'security_audit_events','INSERT') AS ins,
            has_table_privilege(current_user,'security_audit_events','SELECT') AS sel,
            has_table_privilege(current_user,'security_audit_events','UPDATE') AS upd,
            has_table_privilege(current_user,'security_audit_events','DELETE') AS del")->fetch(PDO::FETCH_ASSOC);
        $this->assertFalse((bool) $priv['schema_create']);
        $this->assertTrue((bool) $priv['ins']);
        foreach (['sel', 'upd', 'del'] as $key) {
            $this->assertFalse((bool) $priv[$key]);
        }
        $this->expectSqlState(fn () => $pdo->query('SELECT count(*) FROM security_audit_events'), '42501');
        $this->expectSqlState(fn () => $pdo->exec("UPDATE security_audit_events SET outcome='FAILED' WHERE id='".(string) Str::uuid7()."'"), '42501');
        $this->expectSqlState(fn () => $pdo->exec("DELETE FROM security_audit_events WHERE id='".(string) Str::uuid7()."'"), '42501');
    }

    public function test_no_context_cross_tenant_provider_actor_and_secret_metadata_are_denied(): void
    {
        $pdo = $this->runtime();
        $this->expectSqlState(fn () => $this->rawInsert($pdo, $this->rawRow($this->actorA)), '42501');
        foreach ([
            [$this->rawRow($this->actorA, ['tenant_id' => $this->actorB->tenantId]), '42501'],
            [$this->rawRow($this->actorA, ['actor_id' => $this->actorB->userId]), '42501'],
            [$this->rawRow($this->actorA, ['actor_type' => 'PROVIDER_USER', 'source_channel' => 'PROVIDER']), '42501'],
            [$this->rawRow($this->actorA, ['metadata' => '{"password":"AUDIT_SECRET_CANARY_10A"}']), '23514'],
        ] as [$row, $state]) {
            $pdo->beginTransaction();
            $this->setLocal($pdo, $this->actorA);
            $this->expectSqlState(fn () => $this->rawInsert($pdo, $row), $state);
            $pdo->rollBack();
        }
        $this->assertSame(0, DB::table('security_audit_events')->where('event_type', 'role.created')->count());
    }

    public function test_runtime_service_commits_one_fact_per_effect_and_writer_requires_transaction(): void
    {
        $writer = app(SecurityAuditWriter::class);
        try {
            $writer->appendTenantMutation($this->actorA, AuditEventType::ROLE_CREATED, (string) Str::uuid7());
            $this->fail('Audit writer accepted an autocommit mutation.');
        } catch (LogicException) {
            $this->assertTrue(true);
        }

        $roleId = $this->runtimeDefault(function (): string {
            return app(TenantRoleMutationService::class)->createRole($this->actorA, 'Runtime Audit Reader');
        });
        $this->runtimeDefault(function () use ($roleId): void {
            $service = app(TenantRoleMutationService::class);
            $service->updateRoleGrants($this->actorA, $roleId, [['permission' => 'role.view', 'scope' => null]]);
            $service->assignRole($this->actorA, $this->targetMembershipId, $roleId);
            $service->revokeRole($this->actorA, $this->targetMembershipId, $roleId);
            $service->suspendMembership($this->actorA, $this->targetMembershipId);
            $service->reactivateMembership($this->actorA, $this->targetMembershipId);
        });
        $target = User::query()->findOrFail($this->targetUserId);
        $this->runtimeDefault(function () use ($target): void {
            app(UserAccountStatusService::class)->disable($target);
        });
        foreach (['role.created', 'role.grants_changed', 'role.assigned', 'role.revoked',
            'membership.suspended', 'membership.reactivated'] as $event) {
            $this->assertSame(1, DB::table('security_audit_events')->where('tenant_id', $this->actorA->tenantId)
                ->where('event_type', $event)->count(), $event);
        }
        $row = DB::table('security_audit_events')->where('event_type', 'role.assigned')->first();
        $this->assertSame($this->actorA->userId, $row->actor_id);
        $this->assertSame($this->actorA->tenantId, $row->tenant_id);
        $this->assertSame($this->targetMembershipId, $row->target_id);
        $this->assertSame(5, (int) DB::table('tenant_memberships')->where('id', $this->targetMembershipId)->value('authorization_version'));
        $disabled = DB::table('security_audit_events')->where('event_type', 'user.disabled')
            ->where('tenant_id', $this->actorA->tenantId)->first();
        $this->assertNotNull($disabled);
        $this->assertSame('SYSTEM', $disabled->actor_type);
        $this->assertNull($disabled->actor_id);
        $this->assertSame($this->targetUserId, $disabled->target_id);
        $this->assertSame('DISABLED', DB::table('users')->where('id', $this->targetUserId)->value('status'));
    }
}
