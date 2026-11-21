<?php

namespace Tests\Feature\Identity;

use App\Modules\Identity\Application\TenantAuthoritySessionService;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

/**
 * G2-A / AL09 HTTP-level fault injection.
 *
 * Sends real HTTP requests through the full Laravel kernel:
 *   ResolveTenantHost → EnsureTenantLoginClientProof → RequireAllowedSpaOrigin
 *   → TenantStaffRequestContext → TenantStaffAuthController::login
 *
 * Faultpoints tested:
 *   FP1: DB authority COMMIT succeeded, session store write interrupted
 *   FP2: Session saved, but HTTP response never reached client (connection drop)
 *   FP3: Revocation mid-flight — authority created then revoked before retry
 *   FP4: Key rotation between first request and retry
 *   FP5: Cross-tenant replay — same idempotency key, different tenant host
 */
final class TenantAuthorityHttpFaultInjectionTest extends TestCase
{
    use G2AcceptClusterGuard;

    private const TENANT_A_HOST = 'al09-a.daleel.localhost';
    private const TENANT_B_HOST = 'al09-b.daleel.localhost';
    private const BASE_DOMAIN = 'daleel.localhost';
    private const STAFF_EMAIL = 'al09-admin@proof.invalid';
    private const STAFF_PASSWORD = 'Secfix06TestPass!';

    private \PDO $superPdo;

    /**
     * Per-host client cookie jar. Models a real browser: the host-bound
     * daleel_login_client proof is a 15-minute cookie that deliberately survives
     * server-side session rotation / loss. Keyed by host so cross-tenant calls
     * don't share a proof.
     *
     * @var array<string, array<string, string>>
     */
    private array $clientJars = [];

    protected function setUp(): void
    {
        parent::setUp();

        // MANDATORY identity/scope guard before any write; returns the verified
        // superuser PDO and sets $this->g2Host/g2Port/g2Db used to rebuild the
        // connection config in configureTestEnvironment().
        $this->superPdo = $this->g2GuardOrSkip();
    }

    private function configureTestEnvironment(string $host = self::TENANT_A_HOST): void
    {
        $connBase = [
            'driver' => 'pgsql',
            'host' => $this->g2Host,
            'port' => (string) $this->g2Port,
            'database' => $this->g2Db,
            'charset' => 'utf8',
            'prefix' => '',
            'prefix_indexes' => true,
            'search_path' => 'public',
            'sslmode' => 'prefer',
        ];
        $pw = config('database.connections.pgsql.password');

        config([
            // APP_KEY must be a valid 32-byte key for AES-256-CBC encryption (CSRF cookies).
            // phpunit.xml provides one but shell env may override with an invalid length.
            'app.key' => 'base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
            // CoreRuntimeBoundary reads HTTP_HOST which Request::create() derives from the URL.
            // prepareUrlForRequest() prepends app.url to relative paths, so it must be the tenant host.
            'app.url' => 'http://'.$host,
            'identity.tenant_auth_client_enabled' => true,
            'tenancy.base_domain' => self::BASE_DOMAIN,
            'tenancy.allow_localhost_base_domain' => true,
            'tenancy.local_test_base_domain' => self::BASE_DOMAIN,
            'cors.allowed_origins' => ['http://'.self::TENANT_A_HOST.':3001', 'http://'.self::TENANT_B_HOST.':3001'],
            'sanctum.stateful' => array_values(array_unique(array_merge(
                config('sanctum.stateful', []),
                [self::TENANT_A_HOST.':3001', self::TENANT_B_HOST.':3001'],
            ))),

            'core_runtime.mode' => 'trusted',
            'core_runtime.owner_login' => 'daleel_b10b_owner',
            'core_runtime.base_host' => self::BASE_DOMAIN,
            'core_runtime.legacy_host' => 'legacy.daleel.localhost',
            'database.default' => 'pgsql_provider',

            'database.connections.pgsql' => array_merge($connBase, [
                'username' => 'dl_truntime',
                'password' => $pw,
            ]),
            'database.connections.pgsql_provider' => array_merge($connBase, [
                'username' => 'dl_provider',
                'password' => $pw,
            ]),
            'database.connections.pgsql_hostname_resolver' => array_merge($connBase, [
                // Instruction 4: the host-resolution identity is dl_host (IN daleel_hostname_resolver),
                // NOT dl_tauth (IN daleel_tenant_auth_client). Using dl_tauth caused "permission denied
                // for table tenant_hostnames" because dl_tauth is not a member of daleel_hostname_resolver.
                'username' => 'dl_host',
                'password' => $pw,
            ]),
            'database.connections.pgsql_tenant_auth' => array_merge($connBase, [
                'username' => 'dl_tauth',
                'password' => $pw,
            ]),
            'database.connections.pgsql_tenant_runtime' => array_merge($connBase, [
                'username' => 'dl_core_truntime',
                'password' => $pw,
            ]),
            'core_sql.trusted_tenant_login' => 'dl_core_truntime',
            'core_sql.legacy_tenant_login' => 'daleel_b10b_tenant_runtime',

            'database.connections.pgsql_provider_control' => array_merge($connBase, [
                'username' => 'dl_provider_ctl',
                'password' => $pw,
            ]),
            'database.connections.pgsql_provider_issuer' => array_merge($connBase, [
                'username' => 'dl_provider_issuer',
                'password' => $pw,
            ]),
            'database.connections.pgsql_onboarding' => array_merge($connBase, [
                'username' => 'dl_onboarding',
                'password' => $pw,
            ]),
            'database.connections.pgsql_f06_bootstrap.username' => null,
            'database.connections.pgsql_f06_bootstrap.password' => null,
        ]);

        // Force Encrypter to rebuild with the corrected key
        $this->app->forgetInstance('encrypter');
    }

    private function loginHeaders(string $host): array
    {
        return [
            'Accept' => 'application/json',
            'Origin' => 'http://'.$host.':3001',
        ];
    }

    private function tenantUrl(string $host, string $path): string
    {
        return 'http://'.$host.'/'.ltrim($path, '/');
    }

    private function obtainCsrfAndClientProof(string $host, bool $freshClient = false): array
    {
        $this->configureTestEnvironment($host);

        // Model a browser's cookie jar: carry whatever this host already holds
        // (most importantly the daleel_login_client proof) INTO the csrf request,
        // exactly as a real client would after a session loss. The server may
        // rotate XSRF-TOKEN and the Laravel session, but it validates the still
        // present proof and does not re-issue it — so it is retained, not wiped.
        // $freshClient models a DIFFERENT client (e.g. an attacker holding only
        // the idempotency key): it starts with an empty jar and is issued its own
        // proof, so its client_hash differs from the legitimate attempt.
        $jar = $freshClient ? [] : ($this->clientJars[$host] ?? []);
        // Reset the framework's own persistent request-cookie state, then seed it
        // with only this host's jar, so a prior performLogin on another host does
        // not leak cookies into this request.
        $this->defaultCookies = [];
        $this->unencryptedCookies = [];

        $response = $this->withServerVariables(['HTTP_HOST' => $host])
            ->withHeaders(['Accept' => 'application/json', 'Origin' => 'http://'.$host.':3001'])
            ->withUnencryptedCookies($jar)
            ->withCredentials()
            ->get($this->tenantUrl($host, '/sanctum/csrf-cookie'));

        $response->assertStatus(204);

        // Merge Set-Cookie from the response into the host jar (new/rotated
        // cookies overwrite; cookies not re-sent are retained).
        foreach ($response->headers->getCookies() as $cookie) {
            $jar[$cookie->getName()] = $cookie->getValue();
        }
        // A fresh (foreign) client must not overwrite the legitimate host jar.
        if (! $freshClient) {
            $this->clientJars[$host] = $jar;
        }

        $csrfToken = isset($jar['XSRF-TOKEN']) ? rawurldecode($jar['XSRF-TOKEN']) : null;
        $clientProof = $jar['daleel_login_client'] ?? null;

        self::assertNotNull($csrfToken, 'CSRF token cookie must be set');
        self::assertNotNull($clientProof, 'Login client proof cookie must be set');

        return ['csrf' => $csrfToken, 'client_proof' => $clientProof, 'all_cookies' => $jar];
    }

    private function performLogin(string $host, string $idempotencyKey, array $tokens): \Illuminate\Testing\TestResponse
    {
        $this->configureTestEnvironment($host);

        return $this->withServerVariables(['HTTP_HOST' => $host])
            ->withHeaders(array_merge($this->loginHeaders($host), [
                'Idempotency-Key' => $idempotencyKey,
                'X-XSRF-TOKEN' => $tokens['csrf'],
            ]))
            ->withUnencryptedCookies($tokens['all_cookies'])
            ->withCredentials()
            ->postJson($this->tenantUrl($host, '/api/v1/auth/login'), [
                'email' => self::STAFF_EMAIL,
                'password' => self::STAFF_PASSWORD,
            ]);
    }

    private function countActiveAuthorities(string $tenantId): int
    {
        $stmt = $this->superPdo->prepare(
            "SELECT count(*) FROM core01_tenant_authority_sessions WHERE tenant_id = ? AND revoked_at IS NULL AND expires_at > now()"
        );
        $stmt->execute([$tenantId]);

        return (int) $stmt->fetchColumn();
    }

    private function revokeAllAuthorities(string $tenantId): void
    {
        $this->superPdo->exec(
            "UPDATE core01_tenant_authority_sessions SET revoked_at = now() WHERE tenant_id = '{$tenantId}' AND revoked_at IS NULL"
        );
    }

    // --- Test Cases ---

    public function test_http_login_succeeds_through_full_kernel(): void
    {
        $tenantA = 'a0000001-0001-4001-8001-000000000001';
        $this->revokeAllAuthorities($tenantA);
        $beforeCount = $this->countActiveAuthorities($tenantA);

        $tokens = $this->obtainCsrfAndClientProof(self::TENANT_A_HOST);
        $idempotencyKey = \Illuminate\Support\Str::uuid()->toString();

        $response = $this->performLogin(self::TENANT_A_HOST, $idempotencyKey, $tokens);

        $response->assertStatus(200);
        $response->assertJsonStructure(['data' => ['id', 'email', 'name']]);
        $response->assertJsonPath('data.email', self::STAFF_EMAIL);

        $afterCount = $this->countActiveAuthorities($tenantA);
        self::assertSame($beforeCount + 1, $afterCount, 'Exactly one new authority created');
    }

    public function test_fp1_retry_after_session_loss_produces_rebound_not_duplicate(): void
    {
        $tenantA = 'a0000001-0001-4001-8001-000000000001';
        $this->revokeAllAuthorities($tenantA);

        $tokens = $this->obtainCsrfAndClientProof(self::TENANT_A_HOST);
        $idempotencyKey = \Illuminate\Support\Str::uuid()->toString();

        $first = $this->performLogin(self::TENANT_A_HOST, $idempotencyKey, $tokens);
        $first->assertStatus(200);
        $countAfterFirst = $this->countActiveAuthorities($tenantA);

        $this->clearTestSession();
        DB::purge('pgsql_tenant_auth');
        DB::purge('pgsql_hostname_resolver');
        DB::purge('pgsql_tenant_runtime');

        $tokens2 = $this->obtainCsrfAndClientProof(self::TENANT_A_HOST);
        $retry = $this->performLogin(self::TENANT_A_HOST, $idempotencyKey, $tokens2);

        $retry->assertStatus(200);
        $retry->assertJsonPath('data.email', self::STAFF_EMAIL);

        $countAfterRetry = $this->countActiveAuthorities($tenantA);
        self::assertSame($countAfterFirst, $countAfterRetry, 'No duplicate authority — REBOUND reused the existing one');
    }

    public function test_fp2_connection_drop_after_session_save_retry_also_rebounds(): void
    {
        $tenantA = 'a0000001-0001-4001-8001-000000000001';
        $this->revokeAllAuthorities($tenantA);

        $tokens = $this->obtainCsrfAndClientProof(self::TENANT_A_HOST);
        $idempotencyKey = \Illuminate\Support\Str::uuid()->toString();

        $first = $this->performLogin(self::TENANT_A_HOST, $idempotencyKey, $tokens);
        $first->assertStatus(200);
        $countAfterFirst = $this->countActiveAuthorities($tenantA);

        $this->refreshApplication();
        DB::purge('pgsql_tenant_auth');
        DB::purge('pgsql_hostname_resolver');
        DB::purge('pgsql_tenant_runtime');

        $tokens2 = $this->obtainCsrfAndClientProof(self::TENANT_A_HOST);
        $retry = $this->performLogin(self::TENANT_A_HOST, $idempotencyKey, $tokens2);

        $retry->assertStatus(200);
        $countAfterRetry = $this->countActiveAuthorities($tenantA);
        self::assertSame($countAfterFirst, $countAfterRetry, 'FP2: no duplicate authority after connection drop');
    }

    public function test_fp3_revocation_before_retry_blocks_rebound(): void
    {
        $tenantA = 'a0000001-0001-4001-8001-000000000001';
        $this->revokeAllAuthorities($tenantA);

        $tokens = $this->obtainCsrfAndClientProof(self::TENANT_A_HOST);
        $idempotencyKey = \Illuminate\Support\Str::uuid()->toString();

        $first = $this->performLogin(self::TENANT_A_HOST, $idempotencyKey, $tokens);
        $first->assertStatus(200);

        $this->revokeAllAuthorities($tenantA);
        self::assertSame(0, $this->countActiveAuthorities($tenantA));

        $this->refreshApplication();
        DB::purge('pgsql_tenant_auth');
        DB::purge('pgsql_hostname_resolver');
        DB::purge('pgsql_tenant_runtime');

        $tokens2 = $this->obtainCsrfAndClientProof(self::TENANT_A_HOST);
        $retry = $this->performLogin(self::TENANT_A_HOST, $idempotencyKey, $tokens2);

        self::assertTrue(
            in_array($retry->getStatusCode(), [401, 409, 500], true),
            'Revoked authority must block retry (got '.$retry->getStatusCode().')'
        );
        self::assertSame(0, $this->countActiveAuthorities($tenantA), 'No resurrection after revocation');
    }

    public function test_fp4_key_rotation_blocks_retry(): void
    {
        $tenantA = 'a0000001-0001-4001-8001-000000000001';
        $this->revokeAllAuthorities($tenantA);

        $tokens = $this->obtainCsrfAndClientProof(self::TENANT_A_HOST);
        $idempotencyKey = \Illuminate\Support\Str::uuid()->toString();

        $first = $this->performLogin(self::TENANT_A_HOST, $idempotencyKey, $tokens);
        $first->assertStatus(200);

        $original = $this->superPdo->query(
            "SELECT key_generation, encode(secret, 'hex') AS secret_hex FROM core01_sql_signing_keys WHERE id = 1"
        )->fetch(\PDO::FETCH_ASSOC);
        $newSecret = bin2hex(random_bytes(32));

        try {
            $this->superPdo->exec(
                "UPDATE core01_sql_signing_keys SET key_generation = key_generation + 1, secret = decode('{$newSecret}', 'hex') WHERE id = 1"
            );

            $this->refreshApplication();
            DB::purge('pgsql_tenant_auth');
            DB::purge('pgsql_hostname_resolver');
            DB::purge('pgsql_tenant_runtime');

            $tokens2 = $this->obtainCsrfAndClientProof(self::TENANT_A_HOST);

            $retry = $this->performLogin(self::TENANT_A_HOST, $idempotencyKey, $tokens2);
            self::assertTrue(
                in_array($retry->getStatusCode(), [401, 409, 500], true),
                'Key rotation must block retry (got '.$retry->getStatusCode().')'
            );
        } finally {
            $gen = (int) $original['key_generation'];
            $hex = $original['secret_hex'];
            $this->superPdo->exec("UPDATE core01_sql_signing_keys SET key_generation = {$gen}, secret = decode('{$hex}', 'hex') WHERE id = 1");
        }
    }

    public function test_fp5_cross_tenant_replay_denied(): void
    {
        $tenantA = 'a0000001-0001-4001-8001-000000000001';
        $this->revokeAllAuthorities($tenantA);

        $tokensA = $this->obtainCsrfAndClientProof(self::TENANT_A_HOST);
        $idempotencyKey = \Illuminate\Support\Str::uuid()->toString();

        $first = $this->performLogin(self::TENANT_A_HOST, $idempotencyKey, $tokensA);
        $first->assertStatus(200);

        $this->refreshApplication();
        DB::purge('pgsql_tenant_auth');
        DB::purge('pgsql_hostname_resolver');
        DB::purge('pgsql_tenant_runtime');

        $tokensB = $this->obtainCsrfAndClientProof(self::TENANT_B_HOST);

        $replayResponse = $this->withServerVariables(['HTTP_HOST' => self::TENANT_B_HOST])
            ->withHeaders(array_merge($this->loginHeaders(self::TENANT_B_HOST), [
                'Idempotency-Key' => $idempotencyKey,
                'X-XSRF-TOKEN' => $tokensB['csrf'],
            ]))
            ->withUnencryptedCookies($tokensB['all_cookies'])
            ->withCredentials()
            ->postJson($this->tenantUrl(self::TENANT_B_HOST, '/api/v1/auth/login'), [
                'email' => 'al09-other@proof.invalid',
                'password' => self::STAFF_PASSWORD,
            ]);

        if ($replayResponse->getStatusCode() === 200) {
            $replayResponse->assertJsonPath('data.email', 'al09-other@proof.invalid');
            self::assertNotEquals(
                'al09-admin@proof.invalid',
                $replayResponse->json('data.email'),
                'Cross-tenant replay must not leak tenant A user data'
            );
        } else {
            self::assertTrue(
                in_array($replayResponse->getStatusCode(), [401, 403, 409, 419, 422, 500], true),
                'Cross-tenant replay must fail safely'
            );
        }
    }

    public function test_no_session_recovery_by_attempt_key_alone(): void
    {
        $tenantA = 'a0000001-0001-4001-8001-000000000001';
        $this->revokeAllAuthorities($tenantA);

        $tokens = $this->obtainCsrfAndClientProof(self::TENANT_A_HOST);
        $idempotencyKey = \Illuminate\Support\Str::uuid()->toString();

        $first = $this->performLogin(self::TENANT_A_HOST, $idempotencyKey, $tokens);
        $first->assertStatus(200);

        $this->refreshApplication();
        DB::purge('pgsql_tenant_auth');
        DB::purge('pgsql_hostname_resolver');
        DB::purge('pgsql_tenant_runtime');

        $this->configureTestEnvironment();

        // The attacker holds only the idempotency key — NOT the original
        // host-bound client proof. A fresh client proof yields a different
        // client_hash, so the register_attempt lookup hits the same attempt row
        // but refuses to rebind it (PZ409): no hijack of the original authority.
        $attackerTokens = $this->obtainCsrfAndClientProof(self::TENANT_A_HOST, freshClient: true);

        $attack = $this->performLogin(self::TENANT_A_HOST, $idempotencyKey, $attackerTokens);

        self::assertNotSame(200, $attack->getStatusCode(),
            'Attempt key alone must not recover or rebind the original authority');
        self::assertSame(1, $this->countActiveAuthorities($tenantA),
            'No duplicate or resurrected authority from attempt key alone');
    }

    private function clearTestSession(): void
    {
        if (session()->isStarted()) {
            session()->flush();
            session()->regenerate(true);
        }
    }
}
