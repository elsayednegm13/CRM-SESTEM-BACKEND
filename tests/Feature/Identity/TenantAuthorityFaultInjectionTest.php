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
 * AL09 — Fault-injection tests at the Laravel service layer.
 *
 * Exercises TenantAuthoritySessionService::register() and revoke()
 * against a real PostgreSQL sandbox (ENV-configured via G2_SANDBOX_*),
 * with the dl_tauth connection, covering session-save failures, retry
 * idempotency, cross-tenant denial, revocation finality and key
 * unavailability.
 *
 * The sandbox target is resolved and verified by G2SandboxGuard before any
 * write: unconfigured => BLOCKED (skipped), and a forbidden port / protected
 * database / wrong system_identifier => REFUSED (hard fail). No ENV value can
 * widen the guard.
 */
class TenantAuthorityFaultInjectionTest extends TestCase
{
    use G2SandboxGuard;

    private TenantAuthoritySessionService $service;

    protected function setUp(): void
    {
        parent::setUp();

        // MANDATORY identity/scope guard before any write (skips or refuses).
        $this->g2GuardOrSkip();

        $this->service = new TenantAuthoritySessionService;
    }

    private function makeRequest(?string $sessionId = null): Request
    {
        $session = new Store('al09_test', new ArraySessionHandler(120));
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
            hostname: 'al09-a.test',
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
            hostname: 'al09-b.test',
            userId: 'b0000001-0001-4001-8001-000000000002',
            membershipId: 'c0000001-0001-4001-8001-000000000002',
            authVersion: 1,
            authorizationVersion: 1,
        );
    }

    private function freshAttempt(Request $request, string $retryKey, string $hostname): array
    {
        $request->attributes->set('tenant_login_client_hash',
            hash_hmac('sha256', 'test-client-'.$retryKey, 'test-secret'));

        return $this->service->attemptBinding($request, $retryKey, $hostname);
    }

    // ─── T1: Register new session via service layer → CREATED ──────────

    public function test_register_new_session_returns_created(): void
    {
        $request = $this->makeRequest();
        $retryKey = (string) Str::uuid();
        $attempt = $this->freshAttempt($request, $retryKey, 'al09-a.test');

        $result = $this->service->register($request, $this->contextA(), $attempt);

        $this->assertEquals('CREATED', $result['disposition']);
        $this->assertIsString($result['generation']);
        $this->assertTrue(Str::isUuid($result['generation']));
        $this->assertIsInt($result['authenticated_at']);

        // Verify authority exists in DB (via owner connection — dl_tauth has no table privileges)
        $row = DB::connection('pgsql')->selectOne(
            'SELECT id, session_generation, revoked_at FROM core01_tenant_authority_sessions WHERE login_attempt_hash = ?',
            [$attempt['attempt_hash']]
        );
        $this->assertNotNull($row);
        $this->assertNull($row->revoked_at);
    }

    // ─── T2: Simulated session-save failure + retry → REBOUND ──────────

    public function test_session_save_failure_retry_returns_rebound(): void
    {
        // Phase 1: register succeeds, but we "lose" the session
        $request1 = $this->makeRequest('session-fault-01');
        $retryKey = (string) Str::uuid();
        $attempt = $this->freshAttempt($request1, $retryKey, 'al09-a.test');
        $result1 = $this->service->register($request1, $this->contextA(), $attempt);
        $this->assertEquals('CREATED', $result1['disposition']);

        // Phase 2: simulate session loss — new request with different session ID
        // (client retries because it never got the response / session cookie was lost)
        $request2 = $this->makeRequest('session-fault-02');
        $request2->attributes->set('tenant_login_client_hash',
            $request1->attributes->get('tenant_login_client_hash'));

        // Same attempt binding (same retryKey + same hostname = same attempt_hash)
        $attempt2 = $this->service->attemptBinding($request2, $retryKey, 'al09-a.test');
        $this->assertEquals($attempt['attempt_hash'], $attempt2['attempt_hash'],
            'Same retryKey+hostname must produce identical attempt_hash');

        $result2 = $this->service->register($request2, $this->contextA(), $attempt2);
        $this->assertEquals('REBOUND', $result2['disposition'],
            'Retry after session-save failure must REBOUND, not create duplicate authority');
        $this->assertEquals($result1['authenticated_at'], $result2['authenticated_at'],
            'REBOUND must preserve original authenticated_at');

        // Verify only one authority row exists (via owner connection)
        $count = DB::connection('pgsql')->selectOne(
            'SELECT count(*) AS n FROM core01_tenant_authority_sessions WHERE login_attempt_hash = ?',
            [$attempt['attempt_hash']]
        );
        $this->assertEquals(1, $count->n, 'No duplicate authority must exist');
    }

    // ─── T3: Revoke then retry → LoginAttemptConflictException ─────────

    public function test_revoked_authority_rejects_retry(): void
    {
        // Register
        $request = $this->makeRequest();
        $retryKey = (string) Str::uuid();
        $attempt = $this->freshAttempt($request, $retryKey, 'al09-a.test');
        $result = $this->service->register($request, $this->contextA(), $attempt);
        $this->assertEquals('CREATED', $result['disposition']);

        // Revoke via service
        $this->service->revoke($request);

        // Retry with same attempt — new request (session lost)
        $request2 = $this->makeRequest();
        $request2->attributes->set('tenant_login_client_hash',
            $request->attributes->get('tenant_login_client_hash'));
        $attempt2 = $this->service->attemptBinding($request2, $retryKey, 'al09-a.test');

        $this->expectException(LoginAttemptConflictException::class);
        $this->service->register($request2, $this->contextA(), $attempt2);
    }

    // ─── T4: Cross-tenant attempt → PZ403 ──────────────────────────────

    public function test_cross_tenant_attempt_denied(): void
    {
        $request = $this->makeRequest();
        $retryKey = (string) Str::uuid();
        $attempt = $this->freshAttempt($request, $retryKey, 'al09-b.test');

        // Register as tenant B (valid)
        $result = $this->service->register($request, $this->contextB(), $attempt);
        $this->assertEquals('CREATED', $result['disposition']);

        // Replay same attempt_hash but claim tenant A context
        $request2 = $this->makeRequest();
        $request2->attributes->set('tenant_login_client_hash',
            $request->attributes->get('tenant_login_client_hash'));
        $attempt2 = $this->service->attemptBinding($request2, $retryKey, 'al09-b.test');

        $this->expectException(LoginAttemptConflictException::class);
        $this->service->register($request2, $this->contextA(), $attempt2);
    }

    // ─── T5: Expired signing key → RuntimeException (PZ503) ────────────

    public function test_expired_signing_key_denies_registration(): void
    {
        // Expire the key (as superuser via owner connection)
        DB::connection('pgsql')->statement(
            "UPDATE core01_sql_signing_keys SET status='REVOKED', revoked_at=now() WHERE id=1"
        );

        try {
            $request = $this->makeRequest();
            $retryKey = (string) Str::uuid();
            $attempt = $this->freshAttempt($request, $retryKey, 'al09-a.test');

            $this->expectException(QueryException::class);
            $this->service->register($request, $this->contextA(), $attempt);
        } finally {
            // Restore the key
            DB::connection('pgsql')->statement(
                "UPDATE core01_sql_signing_keys SET status='ACTIVE', revoked_at=NULL WHERE id=1"
            );
        }
    }

    // ─── T6: Full login cycle: register → session rotation → re-register
    //         simulates the full authenticate() pattern ──────────────────

    public function test_full_login_cycle_with_session_rotation(): void
    {
        // Phase 1: Pre-auth binding (before session rotation)
        $preAuthRequest = $this->makeRequest('pre-auth-session-id');
        $retryKey = (string) Str::uuid();
        $attempt = $this->freshAttempt($preAuthRequest, $retryKey, 'al09-a.test');

        // Phase 2: Session rotation (mimics Auth::guard()->login())
        // After rotation, session ID changes but attempt binding is preserved
        $postAuthRequest = $this->makeRequest('post-auth-session-id');
        $postAuthRequest->attributes->set('tenant_login_client_hash',
            $preAuthRequest->attributes->get('tenant_login_client_hash'));

        // Phase 3: Register with post-rotation session
        $result = $this->service->register($postAuthRequest, $this->contextA(), $attempt);
        $this->assertEquals('CREATED', $result['disposition']);

        // Verify the session_hash is bound to post-auth session ID (via owner connection)
        $expectedHash = $this->service->sessionHash($postAuthRequest, $result['generation']);
        $row = DB::connection('pgsql')->selectOne(
            'SELECT session_hash FROM core01_tenant_authority_sessions WHERE login_attempt_hash = ?',
            [$attempt['attempt_hash']]
        );
        $this->assertEquals($expectedHash, $row->session_hash);

        // Phase 4: Simulate lost response — retry with another session ID
        $retryRequest = $this->makeRequest('retry-after-lost-response');
        $retryRequest->attributes->set('tenant_login_client_hash',
            $preAuthRequest->attributes->get('tenant_login_client_hash'));
        $retryAttempt = $this->service->attemptBinding($retryRequest, $retryKey, 'al09-a.test');

        $result2 = $this->service->register($retryRequest, $this->contextA(), $retryAttempt);
        $this->assertEquals('REBOUND', $result2['disposition']);

        // After REBOUND, session_hash should be updated to retry session (via owner connection)
        $retryHash = $this->service->sessionHash($retryRequest, $result2['generation']);
        $row2 = DB::connection('pgsql')->selectOne(
            'SELECT session_hash FROM core01_tenant_authority_sessions WHERE login_attempt_hash = ?',
            [$attempt['attempt_hash']]
        );
        $this->assertEquals($retryHash, $row2->session_hash,
            'REBOUND must update session_hash to the retry session');
    }

    // ─── T7: Revocation via snapshot (mimics middleware cleanup) ────────

    public function test_revocation_via_snapshot_after_exception(): void
    {
        $request = $this->makeRequest();
        $retryKey = (string) Str::uuid();
        $attempt = $this->freshAttempt($request, $retryKey, 'al09-a.test');
        $result = $this->service->register($request, $this->contextA(), $attempt);
        $this->assertEquals('CREATED', $result['disposition']);

        // Snapshot captures hash+generation from session
        $snapshot = $this->service->snapshot($request);
        $this->assertNotNull($snapshot);
        $this->assertArrayHasKey('hash', $snapshot);
        $this->assertArrayHasKey('generation', $snapshot);

        // Revoke via snapshot (mimics middleware cleanup after exception)
        $this->service->revokeHash($snapshot['hash'], $snapshot['generation']);

        // Verify revoked in DB (via owner connection)
        $row = DB::connection('pgsql')->selectOne(
            'SELECT revoked_at FROM core01_tenant_authority_sessions WHERE login_attempt_hash = ?',
            [$attempt['attempt_hash']]
        );
        $this->assertNotNull($row->revoked_at, 'Authority must be revoked after revokeHash()');
    }
}
