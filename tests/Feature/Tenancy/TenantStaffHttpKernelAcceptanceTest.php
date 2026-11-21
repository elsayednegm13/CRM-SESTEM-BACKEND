<?php

namespace Tests\Feature\Tenancy;

use Illuminate\Database\Connection;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use RuntimeException;
use Tests\TestCase;

/**
 * HTTP kernel acceptance for the tenant-staff realm on the locked RM02 target
 * (DEV-FOUNDATION-01 / REMEDIATION-04, G4). Requests go through the real route stack:
 * ResolveTenantHost -> RejectCompanyContextSelectors -> RequireAllowedSpaOrigin ->
 * TenantStaffRequestContext -> auth:tenant_staff -> ValidateTenantStaffSession, with the real
 * session guard resolving the principal through TenantStaffUserProvider on
 * pgsql_tenant_runtime. No middleware is disabled, no actor is injected with actingAs(), no
 * test-only route exists, and the default connection is never used inside a request path.
 *
 * Write endpoints are exercised inside an outer transaction on pgsql_tenant_runtime so the
 * request's own commit becomes a savepoint release and the rows are discarded; read-only
 * requests run with no outer transaction, so they prove the real top-level
 * transaction/commit/context-clearing lifecycle.
 */
final class TenantStaffHttpKernelAcceptanceTest extends TestCase
{
    private const TARGET_DATABASE = 'daleel_crm_rm02_isolated';
    private const TARGET_PORT = 55437;
    private const TARGET_SYSTEM_IDENTIFIER = '7699972247235194919';
    private const BASE_DOMAIN = 'acceptance.localhost';
    private const ORIGIN = 'http://localhost:3001';

    private array $tenant = [];
    private array $admin = [];
    private array $reader = [];
    private array $suspended = [];

    protected function setUp(): void
    {
        parent::setUp();
        if (! getenv('RLS_TEST_RUNTIME_USER') || ! getenv('RLS_TEST_RUNTIME_PASSWORD')) {
            $this->markTestSkipped('Non-owner tenant runtime role is not configured.');
        }
        $identity = DB::selectOne("SELECT current_database() AS name,
            (SELECT oid::text FROM pg_catalog.pg_database WHERE datname = current_database()) AS oid,
            (SELECT system_identifier::text FROM pg_catalog.pg_control_system()) AS system_id,
            inet_server_port() AS server_port");
        $lockedOid = getenv('ACCEPTANCE_RM02_DB_OID');
        if ($identity->name !== self::TARGET_DATABASE
            || (int) config('database.connections.pgsql.port') !== self::TARGET_PORT
            || $identity->system_id !== self::TARGET_SYSTEM_IDENTIFIER
            || (int) $identity->server_port !== 5432
            || ! is_string($lockedOid) || $lockedOid === '' || $lockedOid !== $identity->oid) {
            throw new RuntimeException('Refusing HTTP kernel acceptance outside the locked RM02 target.');
        }
        if (config('identity.tenant_auth_client_enabled') !== true) {
            $this->markTestSkipped('The tenant-staff realm is disabled (TENANT_STAFF_AUTH_ENABLED).');
        }
        if (! in_array(self::ORIGIN, (array) config('cors.allowed_origins'), true)) {
            throw new RuntimeException('The company SPA origin is not configured.');
        }

        foreach (['a', 'b'] as $letter) {
            $tenantId = DB::table('tenants')->where('slug', "rm02-{$letter}")->where('status', 'ACTIVE')->value('id');
            if (! is_string($tenantId)) {
                throw new RuntimeException('RM02 fixtures are missing.');
            }
            $this->tenant[$letter] = $tenantId;
            $this->admin[$letter] = $this->staff($tenantId, "rm02-admin-{$letter}@proof.invalid");
        }
        $this->reader = $this->staff($this->tenant['a'], 'rm02-reader-a@proof.invalid');
        $this->suspended = $this->staff($this->tenant['a'], 'rm02-suspended-a@proof.invalid');
    }

    protected function tearDown(): void
    {
        if (array_key_exists('pgsql_tenant_runtime', DB::getConnections())) {
            $runtime = DB::connection('pgsql_tenant_runtime');
            while ($runtime->transactionLevel() > 0) {
                $runtime->rollBack();
            }
        }
        parent::tearDown();
    }

    private function staff(string $tenantId, string $email): array
    {
        $row = DB::table('tenant_staff_users as u')
            ->join('tenant_staff_memberships as m', 'm.staff_user_id', '=', 'u.id')
            ->where('u.tenant_id', $tenantId)->where('u.canonical_email', $email)
            ->first(['u.id as user', 'm.id as membership', 'u.auth_version', 'm.authorization_version']);
        if (! $row) {
            throw new RuntimeException('RM02 staff fixture is missing.');
        }

        return ['user' => $row->user, 'membership' => $row->membership,
            'auth_version' => (int) $row->auth_version, 'authorization_version' => (int) $row->authorization_version];
    }

    private function url(string $letter, string $path): string
    {
        return "http://rm02-{$letter}.".self::BASE_DOMAIN.'/api/v1'.$path;
    }

    /** The exact session state a successful login leaves behind, including the real guard key. */
    private function sessionFor(string $hostLetter, array $member, array $overrides = []): array
    {
        return [
            Auth::guard('tenant_staff')->getName() => $member['user'],
            'identity.tenant_staff' => array_merge([
                'tenant_id' => $this->tenant[$hostLetter],
                'hostname' => "rm02-{$hostLetter}.".self::BASE_DOMAIN,
                'user_id' => $member['user'],
                'membership_id' => $member['membership'],
                'auth_version' => $member['auth_version'],
                'authorization_version' => $member['authorization_version'],
                'authenticated_at' => now()->timestamp,
            ], $overrides),
        ];
    }

    private function headers(?string $origin = self::ORIGIN, array $extra = []): array
    {
        return array_merge($origin === null ? [] : ['Origin' => $origin], ['Accept' => 'application/json'], $extra);
    }

    private function assertSafeErrorEnvelope(\Illuminate\Testing\TestResponse $response, int $status, string $code, string $label = ''): void
    {
        $this->assertSame($status, $response->status(), $label.' '.$response->getContent());
        $this->assertSame($code, $response->json('error.code'), $label.' '.$response->getContent());
        $this->assertIsString($response->json('meta.request_id'));
        $body = $response->getContent();
        foreach (['SQLSTATE', 'pg_', 'Exception', 'vendor\\', '/vendor/', 'password_hash', 'permission denied', 'row-level security'] as $leak) {
            $this->assertStringNotContainsString($leak, (string) $body, 'the error envelope must not leak internals');
        }
    }

    public function test_company_reads_succeed_for_the_resolved_host_and_session(): void
    {
        $session = $this->sessionFor('a', $this->admin['a']);

        $context = $this->withSession($session)->getJson($this->url('a', '/company/context'), $this->headers());
        $context->assertOk();
        $context->assertJsonPath('data.company.id', $this->tenant['a']);
        $context->assertJsonPath('data.company.slug', 'rm02-a');
        $context->assertJsonPath('data.staff.id', $this->admin['a']['user']);

        $authorization = $this->withSession($session)->getJson($this->url('a', '/company/authorization'), $this->headers());
        $authorization->assertOk();
        $grants = $authorization->json('data');
        $this->assertNotEmpty($grants, 'the company admin must carry grants');
        $this->assertStringNotContainsString('password_hash', (string) $authorization->getContent());

        $roles = $this->withSession($session)->getJson($this->url('a', '/company/roles'), $this->headers());
        $roles->assertOk();
        $this->assertNotEmpty($roles->json('data'));

        $staff = $this->withSession($session)->getJson($this->url('a', '/company/staff'), $this->headers());
        $staff->assertOk();
        $emails = array_column((array) $staff->json('data'), 'email');
        $this->assertContains('rm02-admin-a@proof.invalid', $emails);
        $this->assertNotContains('rm02-admin-b@proof.invalid', $emails, 'tenant B staff must never appear');
        $this->assertStringNotContainsString('password_hash', (string) $staff->getContent());

        $leads = $this->withSession($session)->getJson($this->url('a', '/company/leads'), $this->headers());
        $leads->assertOk();
        $this->assertSame([], $leads->json('data'));
    }

    public function test_tenant_runtime_context_is_cleared_after_each_request(): void
    {
        /** @var Connection $runtime */
        $runtime = DB::connection('pgsql_tenant_runtime');
        $this->withSession($this->sessionFor('a', $this->admin['a']))
            ->getJson($this->url('a', '/company/context'), $this->headers())->assertOk();

        $this->assertSame(0, $runtime->transactionLevel(), 'the request transaction must be closed');
        $this->assertSame(0, (int) $runtime->selectOne('SELECT count(id) AS n FROM tenants')->n,
            'no tenant row may stay visible once the request transaction committed');
        foreach (['app.context_mode', 'app.tenant_id', 'app.user_id'] as $guc) {
            $this->assertSame('', (string) $runtime->selectOne('SELECT coalesce(current_setting(?, true), ?) AS v', [$guc, ''])->v,
                "{$guc} must not survive the request");
        }
    }

    /**
     * One request per method for allowed paths: a denied request makes the in-process
     * SessionGuard call logout(), which would poison any later request in the same method.
     */
    public function test_forwarded_host_headers_cannot_move_a_request_to_another_tenant(): void
    {
        $spoofed = $this->withSession($this->sessionFor('a', $this->admin['a']))->getJson(
            $this->url('a', '/company/context'),
            $this->headers(self::ORIGIN, [
                'X-Forwarded-Host' => 'rm02-b.'.self::BASE_DOMAIN,
                'X-Forwarded-Server' => 'rm02-b.'.self::BASE_DOMAIN,
                'Forwarded' => 'host=rm02-b.'.self::BASE_DOMAIN,
            ]));
        $this->assertSame(200, $spoofed->status(), 'forwarded host headers must be ignored: '.$spoofed->getContent());
        $spoofed->assertJsonPath('data.company.id', $this->tenant['a']);
        $spoofed->assertJsonPath('data.company.slug', 'rm02-a');
        $this->assertSame([], Request::getTrustedProxies(), 'no proxy may be trusted by default');
    }

    public function test_host_binding_rejects_foreign_sessions_and_unknown_hosts(): void
    {
        // A valid tenant A session presented on tenant B's host.
        $this->assertSafeErrorEnvelope(
            $this->withSession($this->sessionFor('a', $this->admin['a']))
                ->getJson($this->url('b', '/company/context'), $this->headers()),
            401, 'AUTH_UNAUTHENTICATED');

        // A session whose stored tenant/hostname was tampered with to point at tenant B.
        $forged = $this->sessionFor('b', $this->admin['a'], ['tenant_id' => $this->tenant['b']]);
        $this->assertSafeErrorEnvelope(
            $this->withSession($forged)->getJson($this->url('b', '/company/context'), $this->headers()),
            401, 'AUTH_UNAUTHENTICATED');

        // An unmapped host never reveals whether the company exists.
        $this->assertSafeErrorEnvelope(
            $this->withSession($this->sessionFor('a', $this->admin['a']))
                ->getJson('http://rm02-unmapped.'.self::BASE_DOMAIN.'/api/v1/company/context', $this->headers()),
            404, 'RESOURCE_NOT_FOUND');
    }

    public function test_session_integrity_versions_and_membership_state_are_revalidated(): void
    {
        foreach ([
            'no session' => [],
            'stale authorization version' => $this->sessionFor('a', $this->reader, ['authorization_version' => $this->reader['authorization_version'] + 1]),
            'stale auth version' => $this->sessionFor('a', $this->reader, ['auth_version' => $this->reader['auth_version'] + 1]),
            'suspended membership' => $this->sessionFor('a', $this->suspended),
            'membership of another member' => $this->sessionFor('a', $this->reader, ['membership_id' => $this->admin['a']['membership']]),
            'expired absolute lifetime' => $this->sessionFor('a', $this->admin['a'], ['authenticated_at' => now()->timestamp - 100000]),
        ] as $label => $session) {
            $response = $this->withSession($session)->getJson($this->url('a', '/company/context'), $this->headers());
            $this->assertContains($response->status(), [401], $label.' must not be authenticated');
            $this->assertIsString($response->json('error.code'), $label);
            $this->assertStringNotContainsString('SQLSTATE', (string) $response->getContent(), $label);
        }
    }

    public function test_origin_allowlist_and_company_selectors_are_enforced_at_the_edge(): void
    {
        $session = $this->sessionFor('a', $this->admin['a']);
        $this->withSession($session)->getJson($this->url('a', '/company/context'), $this->headers(null))->assertStatus(403);
        $this->withSession($session)->getJson($this->url('a', '/company/context'), $this->headers('http://evil.example'))->assertStatus(403);

        $this->assertSafeErrorEnvelope(
            $this->withSession($session)->getJson($this->url('a', '/company/context'),
                $this->headers(self::ORIGIN, ['X-Tenant-ID' => $this->tenant['b']])),
            400, 'TENANT_SELECTOR_NOT_ALLOWED');
        // A selector passed as a field is rejected by validation instead of the header guard.
        $this->assertSafeErrorEnvelope(
            $this->withSession($session)->getJson($this->url('a', '/company/context?tenant_id='.$this->tenant['b']), $this->headers()),
            422, 'VALIDATION_FAILED');
    }

    /** A direct member.view grant is honoured over HTTP, and the list stays tenant-scoped. */
    public function test_direct_grant_allows_the_staff_list_for_a_member_without_roles(): void
    {
        $staff = $this->withSession($this->sessionFor('a', $this->reader))
            ->getJson($this->url('a', '/company/staff'), $this->headers());
        $this->assertSame(200, $staff->status(), (string) $staff->getContent());
        $emails = array_column((array) $staff->json('data'), 'email');
        $this->assertContains('rm02-reader-a@proof.invalid', $emails);
        $this->assertNotContains('rm02-admin-b@proof.invalid', $emails);
    }

    public function test_rbac_denials_are_enforced_per_endpoint_over_http(): void
    {
        $reader = $this->sessionFor('a', $this->reader);
        // The reader holds neither role.view, role.manage, leads.view nor member.manage.
        foreach ([
            ['GET', '/company/roles', []],
            ['GET', '/company/leads', []],
            ['POST', '/company/roles', ['name' => 'RM04 HTTP Denied']],
            ['POST', '/company/staff', ['email' => 'rm04-http-denied@proof.invalid',
                'display_name' => 'RM04 Denied', 'initial_password' => 'rm04-synthetic-initial-pass']],
            ['POST', '/company/leads', ['name' => 'RM04 HTTP Denied Lead']],
        ] as [$method, $path, $payload]) {
            $response = $this->withSession($reader)->json($method, $this->url('a', $path), $payload, $this->headers());
            $this->assertSafeErrorEnvelope($response, 403, 'AUTHORIZATION_DENIED', $method.' '.$path);
        }
        $this->assertSame(4, DB::table('tenant_staff_users')->count());
        $this->assertSame(0, DB::table('leads')->count());
        $this->assertSame(0, DB::table('tenant_staff_security_events')->count());
    }

    /** All requests here are tenant A's and all succeed, so the session guard is never logged out. */
    public function test_http_write_endpoints_create_rows_for_the_resolved_tenant_only(): void
    {
        /** @var Connection $runtime */
        $runtime = DB::connection('pgsql_tenant_runtime');
        $adminA = $this->sessionFor('a', $this->admin['a']);
        // The request's own commit degrades to a savepoint release inside this transaction,
        // so these real HTTP writes leave nothing behind.
        $runtime->beginTransaction();
        try {
            $created = $this->withSession($adminA)->postJson($this->url('a', '/company/leads'),
                ['name' => 'RM04 HTTP Lead'], $this->headers());
            $this->assertSame(201, $created->status(), 'lead creation over HTTP: '.$created->getContent());
            $leadId = $created->json('data.id');
            $this->assertIsString($leadId);

            $role = $this->withSession($adminA)->postJson($this->url('a', '/company/roles'),
                ['name' => 'RM04 HTTP Role'], $this->headers());
            $this->assertSame(201, $role->status(), (string) $role->getContent());

            $staff = $this->withSession($adminA)->postJson($this->url('a', '/company/staff'), [
                'email' => 'rm04-http-new@proof.invalid',
                'display_name' => 'RM04 HTTP Staff',
                'initial_password' => 'rm04-synthetic-initial-pass',
                'role_id' => $role->json('data.id'),
            ], $this->headers());
            $this->assertSame(201, $staff->status(), (string) $staff->getContent());
            $this->assertStringNotContainsString('password', strtolower((string) $staff->getContent()));

            $own = $this->withSession($adminA)->getJson($this->url('a', '/company/leads/'.$leadId), $this->headers());
            $this->assertSame(200, $own->status(), (string) $own->getContent());
            $own->assertJsonPath('data.name', 'RM04 HTTP Lead');

            // Every row landed in tenant A and the audit trail recorded the staff creation.
            $this->assertSame($this->tenant['a'], $runtime->table('leads')->where('id', $leadId)->value('tenant_id'));
            $this->assertSame($this->tenant['a'], $runtime->table('roles')->where('id', $role->json('data.id'))->value('tenant_id'));
            $this->assertSame($this->tenant['a'], $runtime->table('tenant_staff_memberships')
                ->where('id', $staff->json('data.membership_id'))->value('tenant_id'));
            // role_created + tenant_staff.created + role_assigned, one per authorized operation.
            $this->assertSame(3, (int) $runtime->selectOne("SELECT coalesce(sum(n_tup_ins), 0) AS n
                FROM pg_stat_xact_user_tables WHERE relname = 'tenant_staff_security_events'")->n);
        } finally {
            $runtime->rollBack();
        }
        $this->assertSame(0, DB::table('leads')->count(), 'every HTTP write was discarded');
        $this->assertSame(3, DB::table('roles')->count());
        $this->assertSame(4, DB::table('tenant_staff_users')->count());
        $this->assertSame(0, DB::table('tenant_staff_security_events')->count());
    }

    /** Tenant B gets AUTHORIZATION_DENIED (not a logout), so several B requests can share one method. */
    public function test_cross_tenant_object_access_over_http_is_denied_for_every_lead_verb(): void
    {
        /** @var Connection $runtime */
        $runtime = DB::connection('pgsql_tenant_runtime');
        $adminB = $this->sessionFor('b', $this->admin['b']);
        $runtime->beginTransaction();
        try {
            // Seed tenant A's lead on the same connection the HTTP request will use.
            foreach (['app.context_mode' => 'TENANT', 'app.tenant_id' => $this->tenant['a'],
                'app.user_id' => $this->admin['a']['user']] as $key => $value) {
                $runtime->selectOne('SELECT set_config(?, ?, true)', [$key, $value]);
            }
            $leadId = (string) \Illuminate\Support\Str::uuid();
            $runtime->table('leads')->insert(['id' => $leadId, 'tenant_id' => $this->tenant['a'],
                'name' => 'RM04 Cross Tenant Lead', 'created_by_membership_id' => $this->admin['a']['membership']]);

            foreach ([
                ['GET', '/company/leads/'.$leadId, []],
                ['PATCH', '/company/leads/'.$leadId, ['name' => 'taken']],
                ['PATCH', '/company/leads/'.$leadId.'/stage', ['stage' => 'won']],
                ['PATCH', '/company/leads/'.$leadId.'/assign', ['assigned_membership_id' => $this->admin['b']['membership']]],
                ['DELETE', '/company/leads/'.$leadId, []],
            ] as [$method, $path, $payload]) {
                $response = $this->withSession($adminB)->json($method, $this->url('b', $path), $payload, $this->headers());
                $this->assertSafeErrorEnvelope($response, 403, 'AUTHORIZATION_DENIED', $method.' '.$path);
            }
            $list = $this->withSession($adminB)->getJson($this->url('b', '/company/leads'), $this->headers());
            $this->assertSame(200, $list->status(), (string) $list->getContent());
            $this->assertSame([], $list->json('data'), 'tenant B must see none of tenant A rows');

            foreach (['app.context_mode' => 'TENANT', 'app.tenant_id' => $this->tenant['a'],
                'app.user_id' => $this->admin['a']['user']] as $key => $value) {
                $runtime->selectOne('SELECT set_config(?, ?, true)', [$key, $value]);
            }
            $row = $runtime->table('leads')->where('id', $leadId)->first(['name', 'pipeline_stage', 'status', 'assigned_membership_id']);
            $this->assertSame('RM04 Cross Tenant Lead', $row->name, 'no cross-tenant attempt may mutate the row');
            $this->assertSame('new', $row->pipeline_stage);
            $this->assertSame('ACTIVE', $row->status);
            $this->assertNull($row->assigned_membership_id);
        } finally {
            $runtime->rollBack();
        }
        $this->assertSame(0, DB::table('leads')->count());
    }

    public function test_validation_and_not_found_use_the_safe_error_contract(): void
    {
        $session = $this->sessionFor('a', $this->admin['a']);
        $invalid = $this->withSession($session)->postJson($this->url('a', '/company/leads'), ['name' => ''], $this->headers());
        $this->assertSafeErrorEnvelope($invalid, 422, 'VALIDATION_FAILED');

        $missing = $this->withSession($session)->getJson($this->url('a', '/company/leads/'.\Illuminate\Support\Str::uuid()), $this->headers());
        $this->assertContains($missing->status(), [403, 404], 'an unknown lead id must not disclose existence');
        $this->assertIsString($missing->json('error.code'));

        $this->assertSame(0, DB::table('leads')->count());
    }
}
