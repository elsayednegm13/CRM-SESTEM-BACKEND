<?php

namespace Tests\Feature\Provider;

use App\Modules\Provider\Application\ProviderApprovalService;
use App\Modules\Provider\Domain\ProviderContext;
use App\Modules\Provider\Infrastructure\Persistence\ProviderUser;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use PDO;
use PDOException;
use RuntimeException;
use Tests\TestCase;

final class ProviderRuntimeRoleTest extends TestCase
{
    private array $ids = [];
    private array $ownerProviderConfig;

    protected function setUp(): void
    {
        parent::setUp();
        if (! getenv('PROVIDER_TEST_RUNTIME_USER') || ! getenv('PROVIDER_TEST_RUNTIME_PASSWORD')
            || ! getenv('RLS_TEST_RUNTIME_USER') || ! getenv('RLS_TEST_RUNTIME_PASSWORD')) {
            $this->markTestSkipped('Exact Control 10B runtime credentials are required.');
        }
        $db = DB::selectOne('SELECT current_database() AS db')->db;
        $port = config('database.connections.pgsql.port');
        if (!(($db === 'daleel_crm_b10b_disposable' && $port == 55437)
            || ($db === 'daleel_crm_b10c_closeout_disposable' && $port == 55439))) {
            throw new RuntimeException('Refusing provider runtime fixtures outside an exact approved disposable target.');
        }
        $this->ownerProviderConfig = config('database.connections.pgsql_provider');
    }

    protected function tearDown(): void
    {
        if (isset($this->ownerProviderConfig)) {
            config(['database.connections.pgsql_provider' => $this->ownerProviderConfig]);
            DB::purge('pgsql_provider');
        }
        if ($this->ids !== []) {
            DB::table('security_audit_events')->whereIn('actor_id', $this->ids)->delete();
            $requests = DB::table('provider_approval_requests')
                ->whereIn('requester_provider_user_id', $this->ids)->pluck('id')->all();
            DB::table('provider_approval_decisions')->whereIn('approval_request_id', $requests)->delete();
            DB::table('provider_approval_requests')->whereIn('id', $requests)->delete();
            DB::table('provider_user_capabilities')->whereIn('provider_user_id', $this->ids)->delete();
            DB::table('provider_mfa_recovery_codes')->whereIn('provider_user_id', $this->ids)->delete();
            DB::table('provider_mfa_totp')->whereIn('provider_user_id', $this->ids)->delete();
            DB::table('provider_users')->whereIn('id', $this->ids)->delete();
        }
        parent::tearDown();
    }

    private function runtime(string $kind): PDO
    {
        $cfg = config('database.connections.pgsql');
        $prefix = $kind === 'provider' ? 'PROVIDER_TEST_RUNTIME' : 'RLS_TEST_RUNTIME';
        return new PDO("pgsql:host={$cfg['host']};port={$cfg['port']};dbname={$cfg['database']}",
            getenv($prefix.'_USER'), getenv($prefix.'_PASSWORD'),
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_EMULATE_PREPARES => false]);
    }

    private function fixture(string $label): ProviderUser
    {
        $user = ProviderUser::query()->create([
            'email' => 'runtime-'.Str::lower(Str::random(10)).'-'.$label.'@proof.invalid',
            'password' => Hash::make(Str::random(32)),
        ]);
        $this->ids[] = $user->id;
        $user->forceFill(['email_verified_at' => now('UTC'), 'mfa_enrolled_at' => now('UTC')])->save();
        return $user->fresh();
    }

    private function expectDenied(callable $query): void
    {
        try {
            $query();
            $this->fail('Cross-plane or audit operation was accepted.');
        } catch (PDOException $exception) {
            $this->assertSame('42501', $exception->getCode());
        }
    }

    private function insertAudit(PDO $pdo, string $actorId, string $type,
        string $category = 'PROVIDER_SECURITY', string $actorType = 'PROVIDER_USER',
        ?string $tenantId = null): void
    {
        $targetType = $type === 'role.created' ? 'role' : 'provider_user';
        $pdo->prepare('INSERT INTO security_audit_events
            (id,category,event_type,outcome,actor_type,actor_id,tenant_id,target_type,target_id,source_channel,metadata)
            VALUES (?,?,?,?,?,?,?,?,?,?,?::jsonb)')->execute([
                (string) Str::uuid7(), $category, $type, 'SUCCESS', $actorType, $actorId,
                $tenantId, $targetType, $actorId,
                $actorType === 'PROVIDER_USER' ? 'PROVIDER' : 'INTERNAL', '{}',
            ]);
    }

    public function test_two_runtime_roles_have_cross_plane_denial_and_no_owner_flags(): void
    {
        $provider = $this->runtime('provider');
        $tenant = $this->runtime('tenant');
        foreach ([$provider, $tenant] as $pdo) {
            $flags = $pdo->query("SELECT current_user,session_user,rolsuper,rolbypassrls,rolcreaterole,rolcreatedb,
                has_schema_privilege(current_user,'public','CREATE') AS schema_create
                FROM pg_roles WHERE rolname=current_user")->fetch(PDO::FETCH_ASSOC);
            $this->assertSame($flags['current_user'], $flags['session_user']);
            foreach (['rolsuper', 'rolbypassrls', 'rolcreaterole', 'rolcreatedb', 'schema_create'] as $flag) {
                $this->assertFalse((bool) $flags[$flag]);
            }
        }
        $this->assertSame('daleel_b10b_provider_runtime', $provider->query('SELECT current_user')->fetchColumn());
        $this->assertSame('daleel_b10b_tenant_runtime', $tenant->query('SELECT current_user')->fetchColumn());
        foreach (['users', 'tenants', 'tenant_memberships', 'roles', 'role_permissions', 'membership_roles'] as $table) {
            foreach (['SELECT', 'INSERT', 'UPDATE', 'DELETE'] as $operation) {
                $has = $provider->query("SELECT has_table_privilege(current_user,'{$table}','{$operation}')")
                    ->fetchColumn();
                $this->assertFalse((bool) $has, "Provider {$operation} {$table}");
            }
            $this->expectDenied(fn () => $provider->query("SELECT count(*) FROM {$table}"));
        }
        foreach (['provider_users', 'provider_mfa_totp', 'provider_mfa_recovery_codes',
            'provider_capabilities', 'provider_user_capabilities', 'provider_approval_requests',
            'provider_approval_decisions'] as $table) {
            foreach (['SELECT', 'INSERT', 'UPDATE', 'DELETE'] as $operation) {
                $has = $tenant->query("SELECT has_table_privilege(current_user,'{$table}','{$operation}')")
                    ->fetchColumn();
                $this->assertFalse((bool) $has, "Tenant {$operation} {$table}");
            }
            $this->expectDenied(fn () => $tenant->query("SELECT count(*) FROM {$table}"));
        }
        $owner = DB::selectOne("SELECT pg_get_userbyid(relowner) AS name FROM pg_class WHERE oid='provider_users'::regclass");
        $this->assertSame('daleel_b10b_owner', $owner->name);
    }

    public function test_provider_audit_policy_accepts_real_actor_and_rejects_forgery_and_reads(): void
    {
        $actor = $this->fixture('audit');
        $pdo = $this->runtime('provider');
        $grant = $pdo->query("SELECT has_table_privilege(current_user,'security_audit_events','INSERT') AS ins,
            has_table_privilege(current_user,'security_audit_events','SELECT') AS sel,
            has_table_privilege(current_user,'security_audit_events','UPDATE') AS upd,
            has_table_privilege(current_user,'security_audit_events','DELETE') AS del")->fetch(PDO::FETCH_ASSOC);
        $this->assertTrue((bool) $grant['ins']);
        foreach (['sel', 'upd', 'del'] as $key) {
            $this->assertFalse((bool) $grant[$key]);
        }
        $this->expectDenied(fn () => $pdo->query('SELECT count(*) FROM security_audit_events'));
        $this->expectDenied(fn () => $pdo->exec("UPDATE security_audit_events SET outcome='FAILED'"));
        $this->expectDenied(fn () => $pdo->exec('DELETE FROM security_audit_events'));
        $this->expectDenied(fn () => $this->insertAudit($pdo, $actor->id, 'provider.mfa.enrolled'));
        $pdo->beginTransaction();
        $pdo->prepare('SELECT set_config(?, ?, true)')->execute(['app.context_mode', 'PROVIDER']);
        $pdo->prepare('SELECT set_config(?, ?, true)')->execute(['app.provider_user_id', $actor->id]);
        $this->insertAudit($pdo, $actor->id, 'provider.mfa.enrolled');
        $pdo->commit();
        $this->assertSame(1, DB::table('security_audit_events')
            ->where('actor_id', $actor->id)->where('event_type', 'provider.mfa.enrolled')->count());
        foreach ([
            [$actor->id, 'role.created', 'AUTHORIZATION', 'TENANT_USER', (string) Str::uuid7()],
            [(string) Str::uuid7(), 'provider.mfa.enrolled', 'PROVIDER_SECURITY', 'PROVIDER_USER', null],
        ] as $args) {
            $pdo->beginTransaction();
            $pdo->prepare('SELECT set_config(?, ?, true)')->execute(['app.context_mode', 'PROVIDER']);
            $pdo->prepare('SELECT set_config(?, ?, true)')->execute(['app.provider_user_id', $actor->id]);
            $this->expectDenied(fn () => $this->insertAudit($pdo, ...$args));
            $pdo->rollBack();
        }
        $tenant = $this->runtime('tenant');
        $this->expectDenied(fn () => $this->insertAudit($tenant, $actor->id, 'provider.mfa.enrolled'));
    }

    public function test_real_provider_runtime_service_couples_approval_and_audit(): void
    {
        $requester = $this->fixture('requester');
        $reviewer = $this->fixture('reviewer');
        DB::table('provider_user_capabilities')->insert([
            ['provider_user_id' => $requester->id, 'capability_key' => 'company.recover', 'granted_at' => now('UTC')],
            ['provider_user_id' => $reviewer->id, 'capability_key' => 'provider.approval.review', 'granted_at' => now('UTC')],
        ]);
        config(['database.connections.pgsql_provider' => [
            ...$this->ownerProviderConfig,
            'username' => getenv('PROVIDER_TEST_RUNTIME_USER'),
            'password' => getenv('PROVIDER_TEST_RUNTIME_PASSWORD'),
        ]]);
        DB::purge('pgsql_provider');
        $service = app(ProviderApprovalService::class);
        $requesterCtx = new ProviderContext($requester->id, $requester->auth_version, 1,
            (string) Str::uuid(), now('UTC')->timestamp, now('UTC')->timestamp);
        $reviewerCtx = new ProviderContext($reviewer->id, $reviewer->auth_version, 1,
            (string) Str::uuid(), now('UTC')->timestamp, now('UTC')->timestamp);
        $id = $service->request($requesterCtx, 'company.recover', (string) Str::uuid7(),
            'Runtime role proof', 'TICKET-RUNTIME-10B');
        $this->assertSame('APPROVED', $service->decide($reviewerCtx, $id, 'APPROVE'));
        config(['database.connections.pgsql_provider' => $this->ownerProviderConfig]);
        DB::purge('pgsql_provider');
        $rows = DB::table('security_audit_events')->where('target_id', $id)
            ->whereIn('event_type', ['provider.approval.requested', 'provider.approval.approved'])
            ->orderBy('event_type')->get();
        $this->assertCount(2, $rows);
        $this->assertSame($requester->id, $rows[1]->actor_id);
        $this->assertSame($reviewer->id, $rows[0]->actor_id);
        $this->assertSame('APPROVED', DB::table('provider_approval_requests')->where('id', $id)->value('status'));
    }
}
