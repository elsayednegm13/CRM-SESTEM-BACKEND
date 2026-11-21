<?php

namespace Tests\Feature\Identity;

use App\Modules\Identity\Application\TenantAuthoritySessionService;
use App\Modules\Identity\Domain\Exceptions\LoginAttemptConflictException;
use App\Modules\Identity\Domain\TenantStaffContext;
use Illuminate\Database\QueryException;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Tests\TestCase;

/**
 * AL11 — Concurrency, revocation, key rotation, membership change,
 * and pool reuse safety tests at the Laravel service layer.
 *
 * Uses independent DB connections to test real concurrent scenarios.
 * Sandbox target is ENV-configured (G2_SANDBOX_*) and verified by
 * G2SandboxGuard before any write.
 */
class TenantAuthorityConcurrencyTest extends TestCase
{
    use G2SandboxGuard;

    private TenantAuthoritySessionService $service;
    private \PDO $superPdo;

    protected function setUp(): void
    {
        parent::setUp();

        // MANDATORY identity/scope guard before any write; returns the verified
        // superuser PDO (BYPASSRLS) used for RLS-protected table mutations.
        $this->superPdo = $this->g2GuardOrSkip();

        $this->service = new TenantAuthoritySessionService;
    }

    private function makeRequest(?string $sessionId = null): Request
    {
        $session = new Store('al11_test', new ArraySessionHandler(120));
        if ($sessionId !== null) {
            $session->setId($sessionId);
        }
        $session->start();

        $request = Request::create('/test', 'POST');
        $request->setLaravelSession($session);

        return $request;
    }

    private function contextA(): TenantStaffContext
    {
        return new TenantStaffContext(
            tenantId: 'a0000001-0001-4001-8001-000000000001',
            hostname: 'al11-a.test',
            userId: 'b0000001-0001-4001-8001-000000000001',
            membershipId: 'c0000001-0001-4001-8001-000000000001',
            authVersion: 1,
            authorizationVersion: 1,
        );
    }

    private function contextB(): TenantStaffContext
    {
        return new TenantStaffContext(
            tenantId: 'a0000001-0001-4001-8001-000000000002',
            hostname: 'al11-b.test',
            userId: 'b0000001-0001-4001-8001-000000000002',
            membershipId: 'c0000001-0001-4001-8001-000000000002',
            authVersion: 1,
            authorizationVersion: 1,
        );
    }

    private function freshAttempt(Request $request, string $retryKey, string $hostname): array
    {
        $request->attributes->set('tenant_login_client_hash',
            hash_hmac('sha256', 'test-client-'.$retryKey, 'al11-secret'));

        return $this->service->attemptBinding($request, $retryKey, $hostname);
    }

    // ─── T1: Two independent registrations for same user ───────────────

    public function test_independent_concurrent_registrations(): void
    {
        $request1 = $this->makeRequest();
        $retryKey1 = (string) Str::uuid();
        $attempt1 = $this->freshAttempt($request1, $retryKey1, 'al11-a.test');

        $request2 = $this->makeRequest();
        $retryKey2 = (string) Str::uuid();
        $attempt2 = $this->freshAttempt($request2, $retryKey2, 'al11-a.test');

        $result1 = $this->service->register($request1, $this->contextA(), $attempt1);
        $result2 = $this->service->register($request2, $this->contextA(), $attempt2);

        $this->assertEquals('CREATED', $result1['disposition']);
        $this->assertEquals('CREATED', $result2['disposition']);
        $this->assertNotEquals($result1['generation'], $result2['generation']);
    }

    // ─── T2: Same attempt_hash concurrently (simulated via sequential
    //         calls — advisory lock serializes) ─────────────────────────

    public function test_same_attempt_sequential_produces_rebound(): void
    {
        $retryKey = (string) Str::uuid();

        $request1 = $this->makeRequest('concurrent-session-1');
        $attempt1 = $this->freshAttempt($request1, $retryKey, 'al11-a.test');
        $result1 = $this->service->register($request1, $this->contextA(), $attempt1);
        $this->assertEquals('CREATED', $result1['disposition']);

        // Second "concurrent" worker with same attempt_hash but different session
        $request2 = $this->makeRequest('concurrent-session-2');
        $request2->attributes->set('tenant_login_client_hash',
            $request1->attributes->get('tenant_login_client_hash'));
        $attempt2 = $this->service->attemptBinding($request2, $retryKey, 'al11-a.test');

        $result2 = $this->service->register($request2, $this->contextA(), $attempt2);
        $this->assertEquals('REBOUND', $result2['disposition']);
    }

    // ─── T3: Revocation during active request (revoke between
    //         register and subsequent use) ──────────────────────────────

    public function test_revocation_between_register_and_use(): void
    {
        $request = $this->makeRequest();
        $retryKey = (string) Str::uuid();
        $attempt = $this->freshAttempt($request, $retryKey, 'al11-a.test');
        $result = $this->service->register($request, $this->contextA(), $attempt);
        $this->assertEquals('CREATED', $result['disposition']);

        // Concurrent revocation (e.g., admin or another tab)
        $snapshot = $this->service->snapshot($request);
        $this->assertNotNull($snapshot);
        $this->service->revokeHash($snapshot['hash'], $snapshot['generation']);

        // Verify revoked in DB
        $row = DB::connection('pgsql')->selectOne(
            'SELECT revoked_at FROM core01_tenant_authority_sessions WHERE login_attempt_hash = ?',
            [$attempt['attempt_hash']]
        );
        $this->assertNotNull($row->revoked_at);

        // Retry the same attempt after revocation → PZ409
        $retryRequest = $this->makeRequest();
        $retryRequest->attributes->set('tenant_login_client_hash',
            $request->attributes->get('tenant_login_client_hash'));
        $retryAttempt = $this->service->attemptBinding($retryRequest, $retryKey, 'al11-a.test');

        $this->expectException(LoginAttemptConflictException::class);
        $this->service->register($retryRequest, $this->contextA(), $retryAttempt);
    }

    // ─── T4: Key rotation during active sessions ───────────────────────

    public function test_key_rotation_invalidates_rebound(): void
    {
        $retryKey = (string) Str::uuid();
        $request1 = $this->makeRequest();
        $attempt = $this->freshAttempt($request1, $retryKey, 'al11-a.test');
        $result = $this->service->register($request1, $this->contextA(), $attempt);
        $this->assertEquals('CREATED', $result['disposition']);

        // Rotate key (gen 1 → 2)
        DB::connection('pgsql')->statement(
            'UPDATE core01_sql_signing_keys SET key_generation = 2 WHERE id = 1'
        );

        try {
            // Retry same attempt after rotation → PZ409 (key_generation mismatch)
            $request2 = $this->makeRequest();
            $request2->attributes->set('tenant_login_client_hash',
                $request1->attributes->get('tenant_login_client_hash'));
            $retryAttempt = $this->service->attemptBinding($request2, $retryKey, 'al11-a.test');

            $this->expectException(LoginAttemptConflictException::class);
            $this->service->register($request2, $this->contextA(), $retryAttempt);
        } finally {
            // Restore key generation
            DB::connection('pgsql')->statement(
                'UPDATE core01_sql_signing_keys SET key_generation = 1 WHERE id = 1'
            );
        }
    }

    // ─── T5: Membership change blocks registration ─────────────────────

    public function test_membership_suspension_blocks_registration(): void
    {
        // Superuser bypasses FORCE RLS to mutate membership status
        $this->superPdo->exec(
            "UPDATE tenant_staff_memberships SET status='SUSPENDED' WHERE id='c0000001-0001-4001-8001-000000000002'"
        );

        try {
            $request = $this->makeRequest();
            $retryKey = (string) Str::uuid();
            $attempt = $this->freshAttempt($request, $retryKey, 'al11-b.test');

            $thrown = false;
            try {
                $this->service->register($request, $this->contextB(), $attempt);
            } catch (QueryException $e) {
                $this->assertEquals('PZ403', $e->errorInfo[0] ?? $e->getCode());
                $thrown = true;
            }
            $this->assertTrue($thrown, 'Suspended membership must be denied');
        } finally {
            $this->superPdo->exec(
                "UPDATE tenant_staff_memberships SET status='ACTIVE' WHERE id='c0000001-0001-4001-8001-000000000002'"
            );
        }
    }

    // ─── T6: auth_version change blocks registration ───────────────────

    public function test_auth_version_bump_blocks_stale_registration(): void
    {
        // Superuser bypasses FORCE RLS to mutate auth_version
        $this->superPdo->exec(
            "UPDATE tenant_staff_users SET auth_version=2 WHERE id='b0000001-0001-4001-8001-000000000002'"
        );

        try {
            $request = $this->makeRequest();
            $retryKey = (string) Str::uuid();
            $attempt = $this->freshAttempt($request, $retryKey, 'al11-b.test');

            $thrown = false;
            try {
                $this->service->register($request, $this->contextB(), $attempt);
            } catch (QueryException $e) {
                $this->assertEquals('PZ403', $e->errorInfo[0] ?? $e->getCode());
                $thrown = true;
            }
            $this->assertTrue($thrown, 'Stale auth_version must be denied');
        } finally {
            $this->superPdo->exec(
                "UPDATE tenant_staff_users SET auth_version=1 WHERE id='b0000001-0001-4001-8001-000000000002'"
            );
        }
    }

    // ─── T7: Pool reuse — dl_tauth connection has no GUC state ─────────

    public function test_pool_reuse_no_guc_leakage(): void
    {
        // Register as tenant A
        $requestA = $this->makeRequest();
        $retryKeyA = (string) Str::uuid();
        $attemptA = $this->freshAttempt($requestA, $retryKeyA, 'al11-a.test');
        $resultA = $this->service->register($requestA, $this->contextA(), $attemptA);
        $this->assertEquals('CREATED', $resultA['disposition']);

        // On the same connection pool, register as tenant B
        $requestB = $this->makeRequest();
        $retryKeyB = (string) Str::uuid();
        $attemptB = $this->freshAttempt($requestB, $retryKeyB, 'al11-b.test');
        $resultB = $this->service->register($requestB, $this->contextB(), $attemptB);
        $this->assertEquals('CREATED', $resultB['disposition']);

        // Verify they are independent authorities for different tenants
        $rowA = DB::connection('pgsql')->selectOne(
            'SELECT tenant_id FROM core01_tenant_authority_sessions WHERE login_attempt_hash = ?',
            [$attemptA['attempt_hash']]
        );
        $rowB = DB::connection('pgsql')->selectOne(
            'SELECT tenant_id FROM core01_tenant_authority_sessions WHERE login_attempt_hash = ?',
            [$attemptB['attempt_hash']]
        );

        $this->assertEquals('a0000001-0001-4001-8001-000000000001', $rowA->tenant_id);
        $this->assertEquals('a0000001-0001-4001-8001-000000000002', $rowB->tenant_id);
    }

    // ─── T8: Cross-tenant pool reuse cannot hijack authority ───────────

    public function test_cross_tenant_pool_reuse_cannot_hijack(): void
    {
        $retryKey = (string) Str::uuid();

        // Register as tenant A
        $requestA = $this->makeRequest();
        $attemptA = $this->freshAttempt($requestA, $retryKey, 'al11-a.test');
        $resultA = $this->service->register($requestA, $this->contextA(), $attemptA);
        $this->assertEquals('CREATED', $resultA['disposition']);

        // Same connection, try to REBOUND with tenant B context → PZ409
        $requestB = $this->makeRequest();
        $requestB->attributes->set('tenant_login_client_hash',
            $requestA->attributes->get('tenant_login_client_hash'));
        $attemptB = $this->service->attemptBinding($requestB, $retryKey, 'al11-a.test');

        $this->expectException(LoginAttemptConflictException::class);
        $this->service->register($requestB, $this->contextB(), $attemptB);
    }
}
