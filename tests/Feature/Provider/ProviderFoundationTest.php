<?php

namespace Tests\Feature\Provider;

use App\Modules\Identity\Infrastructure\Persistence\User;
use App\Modules\Provider\Application\ProviderApprovalService;
use App\Modules\Provider\Application\ProviderMfaService;
use App\Modules\Provider\Domain\ProviderAccessException;
use App\Modules\Provider\Domain\ProviderContext;
use App\Modules\Provider\Infrastructure\Persistence\ProviderDatabaseContext;
use App\Modules\Provider\Infrastructure\Persistence\ProviderUser;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use OTPHP\TOTP;
use Tests\TestCase;

/** Exact disposable owner fixtures; the separate runtime-role test proves grants. */
final class ProviderFoundationTest extends TestCase
{
    private array $providerIds = [];
    private array $tenantUserIds = [];
    private array $externalFixture = [];
    private string $password;

    public function getJson($uri, array $headers = [], $options = 0)
    {
        return $this->json('GET', $this->providerTestUrl($uri), [], $headers, $options);
    }

    public function postJson($uri, array $data = [], array $headers = [], $options = 0)
    {
        return $this->json('POST', $this->providerTestUrl($uri), $data, $headers, $options);
    }

    private function providerTestUrl(mixed $uri): mixed
    {
        return is_string($uri) && str_starts_with($uri, '/')
            ? 'http://platform.acceptance.localhost'.$uri
            : $uri;
    }

    protected function setUp(): void
    {
        parent::setUp();
        $fixtureDatabase = (string) getenv('PROVIDER_FOUNDATION_FIXTURE_DATABASE');
        $fixturePath = (string) getenv('PROVIDER_FOUNDATION_FIXTURE_MANIFEST');
        $runtimeRole = (string) getenv('PROVIDER_FOUNDATION_RUNTIME_ROLE');
        if (getenv('PROVIDER_FOUNDATION_FIXTURE_CONTRACT') !== 'DCRM_PROVIDER_FOUNDATION_ISOLATED_V1'
            || preg_match('/^dcrm_provider_foundation_[a-z0-9_]+$/D', $fixtureDatabase) !== 1
            || preg_match('/^dcrm_pf_provider_[a-z0-9_]+$/D', $runtimeRole) !== 1
            || $fixturePath === '' || ! is_file($fixturePath)
            || config('database.default') !== 'pgsql_provider'
            || config('database.connections.pgsql_provider.database') !== $fixtureDatabase
            || config('database.connections.pgsql_provider.username') !== $runtimeRole) {
            throw new \RuntimeException('PROVIDER_FOUNDATION_ISOLATED_CONTRACT_REQUIRED');
        }
        foreach ((array) config('database.connections', []) as $connection) {
            if (is_array($connection) && ($connection['driver'] ?? null) === 'pgsql'
                && ($connection['username'] ?? null) === config('core_runtime.owner_login')) {
                throw new \RuntimeException('PROVIDER_FOUNDATION_OWNER_IN_APP_CONFIG');
            }
        }
        $identity = DB::connection('pgsql_provider')->selectOne(<<<'SQL'
            SELECT current_database() AS db, session_user, current_user,
                   rolsuper, rolbypassrls, rolcreaterole, rolcreatedb,
                   current_setting('row_security') AS row_security
            FROM pg_roles WHERE rolname = session_user
        SQL);
        if ($identity === null || $identity->db !== $fixtureDatabase
            || $identity->session_user !== $runtimeRole || $identity->current_user !== $runtimeRole
            || $identity->rolsuper || $identity->rolbypassrls || $identity->rolcreaterole
            || $identity->rolcreatedb || $identity->row_security !== 'on') {
            throw new \RuntimeException('PROVIDER_FOUNDATION_RUNTIME_IDENTITY_REFUSED');
        }
        $decoded = json_decode((string) file_get_contents($fixturePath), true, flags: JSON_THROW_ON_ERROR);
        if (! is_array($decoded) || ($decoded['database'] ?? null) !== $fixtureDatabase
            || ($decoded['runtime_role'] ?? null) !== $runtimeRole || ! is_array($decoded['providers'] ?? null)) {
            throw new \RuntimeException('PROVIDER_FOUNDATION_FIXTURE_MANIFEST_INVALID');
        }
        $this->externalFixture = $decoded;
        config([
            'app.url' => 'http://platform.acceptance.localhost',
            'provider.allowed_origins' => ['http://localhost:3002'],
        ]);
        $this->withHeader('Host', 'platform.acceptance.localhost');
        $passwordPath = (string) getenv('PROVIDER_FOUNDATION_FIXTURE_PASSWORD_FILE');
        if ($passwordPath === '' || ! is_file($passwordPath)) {
            throw new \RuntimeException('PROVIDER_FOUNDATION_FIXTURE_PASSWORD_MISSING');
        }
        $this->password = trim((string) file_get_contents($passwordPath));
        if (strlen($this->password) < 32) {
            throw new \RuntimeException('PROVIDER_FOUNDATION_FIXTURE_PASSWORD_INVALID');
        }
    }

    protected function tearDown(): void
    {
        if ($this->externalFixture !== []) {
            parent::tearDown();
            return;
        }
        if ($this->providerIds !== []) {
            $connection = DB::connection('pgsql_provider');
            $connection->table('security_audit_events')->whereIn('actor_id', $this->providerIds)->delete();
            $requests = $connection->table('provider_approval_requests')
                ->whereIn('requester_provider_user_id', $this->providerIds)->pluck('id')->all();
            $connection->table('provider_approval_decisions')->whereIn('approval_request_id', $requests)->delete();
            $connection->table('provider_approval_requests')->whereIn('id', $requests)->delete();
            $connection->table('provider_user_capabilities')->whereIn('provider_user_id', $this->providerIds)->delete();
            $connection->table('provider_mfa_recovery_codes')->whereIn('provider_user_id', $this->providerIds)->delete();
            $connection->table('provider_mfa_totp')->whereIn('provider_user_id', $this->providerIds)->delete();
            $connection->table('provider_users')->whereIn('id', $this->providerIds)->delete();
        }
        if ($this->tenantUserIds !== []) {
            DB::table('users')->whereIn('id', $this->tenantUserIds)->delete();
        }
        parent::tearDown();
    }

    private function provider(string $suffix, bool $verified = true, bool $enrolled = false): array
    {
        if ($this->externalFixture !== []) {
            $fixture = $this->externalFixture['providers'][$suffix] ?? null;
            if (! is_array($fixture) || ! is_string($fixture['id'] ?? null)) {
                throw new \RuntimeException("PROVIDER_FOUNDATION_FIXTURE_MISSING:$suffix");
            }
            $user = ProviderUser::query()->select([
                'id', 'email', 'password', 'status', 'email_verified_at', 'mfa_enrolled_at',
                'auth_version', 'authorization_version',
            ])->findOrFail($fixture['id']);
            $this->providerIds[] = $user->id;
            return [$user, $fixture['secret'] ?? null];
        }
        $user = ProviderUser::query()->create([
            'email' => 'provider-'.Str::lower(Str::random(8)).'-'.$suffix.'@proof.invalid',
            'password' => $this->password,
        ]);
        $this->providerIds[] = $user->id;
        $user->forceFill(['email_verified_at' => $verified ? now('UTC') : null,
            'mfa_enrolled_at' => $enrolled ? now('UTC') : null])->save();
        $secret = null;
        if ($enrolled) {
            $secret = TOTP::generate(null, 32)->getSecret();
            DB::connection('pgsql_provider')->table('provider_mfa_totp')->insert([
                'provider_user_id' => $user->id, 'secret_ciphertext' => Crypt::encryptString($secret),
                'confirmed_at' => now('UTC'), 'created_at' => now('UTC'), 'updated_at' => now('UTC'),
            ]);
        }
        return [$user->fresh(), $secret];
    }

    private function grant(ProviderUser $user, string $key): void
    {
        DB::connection('pgsql_provider')->table('provider_user_capabilities')->insert([
            'provider_user_id' => $user->id, 'capability_key' => $key, 'granted_at' => now('UTC'),
        ]);
        DB::connection('pgsql_provider')->table('provider_users')->where('id', $user->id)
            ->increment('authorization_version');
    }

    private function context(ProviderUser $user, bool $stepUp = true): ProviderContext
    {
        $user = $user->fresh();
        return new ProviderContext($user->id, $user->auth_version, $user->authorization_version,
            (string) Str::uuid(), now('UTC')->timestamp, $stepUp ? now('UTC')->timestamp : null);
    }

    private function login(ProviderUser $user): void
    {
        $this->withHeader('Origin', 'http://localhost:3002')
            ->postJson('http://platform.acceptance.localhost/api/v1/super/auth/login', ['email' => $user->email, 'password' => $this->password])
            ->assertOk();
    }

    /** @return array<string,string> */
    private function loginTenantStaff(string $email): array
    {
        $host = 'foundation.acceptance.localhost';
        $origin = 'http://localhost:3001';
        $this->defaultCookies = [];
        $this->unencryptedCookies = [];
        $csrf = $this->withServerVariables(['HTTP_HOST' => $host])
            ->withHeaders(['Accept' => 'application/json', 'Origin' => $origin])
            ->withCredentials()
            ->get("http://{$host}/sanctum/csrf-cookie")
            ->assertNoContent();
        $cookies = [];
        foreach ($csrf->headers->getCookies() as $cookie) {
            $cookies[$cookie->getName()] = $cookie->getValue();
        }
        $token = isset($cookies['XSRF-TOKEN']) ? rawurldecode($cookies['XSRF-TOKEN']) : null;
        $this->assertIsString($token);
        $this->assertArrayHasKey('daleel_login_client', $cookies);
        $login = $this->withServerVariables(['HTTP_HOST' => $host])
            ->withHeaders(['Accept' => 'application/json', 'Origin' => $origin,
                'Idempotency-Key' => (string) Str::uuid(), 'X-XSRF-TOKEN' => $token])
            ->withUnencryptedCookies($cookies)
            ->withCredentials()
            ->postJson("http://{$host}/api/v1/auth/login", ['email' => $email, 'password' => $this->password])
            ->assertOk();
        foreach ($login->headers->getCookies() as $cookie) {
            $cookies[$cookie->getName()] = $cookie->getValue();
        }
        return $cookies;
    }

    private function enrollViaHttp(ProviderUser $user): array
    {
        $this->login($user);
        $start = $this->postJson('/api/v1/super/auth/mfa/enroll/start')->assertOk();
        $secret = $start->json('data.secret');
        $code = TOTP::createFromSecret($secret)->at(now('UTC')->timestamp);
        $confirmed = $this->postJson('/api/v1/super/auth/mfa/enroll/confirm', ['code' => $code])->assertOk();
        return [$secret, $confirmed->json('data.recovery_codes')];
    }

    public function test_provider_schema_password_and_same_email_remain_independent(): void
    {
        [$provider] = $this->provider('same-email');
        $tenant = $this->tenantFixture('same-email');
        $this->tenantUserIds[] = $tenant->id;
        $this->assertNotSame($provider->id, $tenant->id);
        $this->assertSame('argon2id', password_get_info($provider->password)['algoName']);
        $this->assertFalse(DB::getSchemaBuilder()->hasColumn('provider_users', 'tenant_id'));
        $this->assertFalse(DB::getSchemaBuilder()->hasColumn('provider_users', 'tenant_membership_id'));
        $this->assertSame(8, DB::connection('pgsql_provider')->table('provider_capabilities')->count());
        $this->assertEqualsCanonicalizing(['company.provision', 'company.recover',
            'company.lifecycle.manage', 'provider.approval.review', 'provider.team.manage', 'provider.root',
            'plans.manage', 'company.subscription.manage'],
            DB::connection('pgsql_provider')->table('provider_capabilities')->pluck('key')->all());
        try {
            ProviderUser::query()->create(['email' => $provider->email, 'password' => $this->password]);
            $this->fail('Duplicate provider email accepted.');
        } catch (QueryException $exception) {
            $this->assertSame('23505', $exception->errorInfo[0]);
        }
    }

    public function test_password_pending_enrollment_encryption_recovery_hashes_and_full_guard(): void
    {
        [$provider] = $this->provider('enroll');
        $initialSessionId = session()->getId();
        $this->login($provider);
        $pendingSessionId = session()->getId();
        $this->assertNotSame($initialSessionId, $pendingSessionId);
        $this->withHeader('Origin', 'http://localhost:3002')
            ->getJson('/api/v1/super/auth/me')->assertStatus(401);
        $this->assertFalse(DB::connection('pgsql_provider')->table('provider_mfa_totp')
            ->where('provider_user_id', $provider->id)->exists());
        $start = $this->postJson('/api/v1/super/auth/mfa/enroll/start')->assertOk();
        $secret = $start->json('data.secret');
        $this->assertStringStartsWith('otpauth://totp/', $start->json('data.otpauth_uri'));
        $this->assertStringContainsString('no-store', $start->headers->get('Cache-Control'));
        $pending = session('provider.pending');
        $this->assertStringNotContainsString($secret, json_encode($pending));
        $this->postJson('/api/v1/super/auth/mfa/enroll/confirm', ['code' => 'invalid'])
            ->assertStatus(401)->assertJsonPath('error.code', 'PROVIDER_MFA_INVALID');
        $code = TOTP::createFromSecret($secret)->at(now('UTC')->timestamp);
        $confirm = $this->postJson('/api/v1/super/auth/mfa/enroll/confirm', ['code' => $code])->assertOk();
        $this->assertNotSame($pendingSessionId, session()->getId());
        $codes = $confirm->json('data.recovery_codes');
        $this->assertCount(10, $codes);
        $this->assertCount(10, array_unique($codes));
        $this->assertStringContainsString('no-store', $confirm->headers->get('Cache-Control'));
        $row = DB::connection('pgsql_provider')->table('provider_mfa_totp')
            ->where('provider_user_id', $provider->id)->first();
        $this->assertNotSame($secret, $row->secret_ciphertext);
        $this->assertSame($secret, Crypt::decryptString($row->secret_ciphertext));
        $this->assertExternalCollectorContract();
        $hashes = DB::connection('pgsql_provider')->table('provider_mfa_recovery_codes')
            ->where('provider_user_id', $provider->id)->pluck('code_hash')->all();
        foreach ($codes as $code) {
            $this->assertNotContains($code, $hashes);
        }
        $this->getJson('/api/v1/super/auth/me')->assertOk();
        $this->getJson('http://foundation.acceptance.localhost/api/v1/company/context')->assertStatus(401);
        $this->assertExternalCollectorContract();
    }

    public function test_disabled_unverified_pending_logout_and_enrollment_restart_fail_closed(): void
    {
        [$disabled] = $this->provider('disabled');
        $disabled->forceFill(['status' => 'DISABLED'])->save();
        $this->withHeader('Origin', 'http://localhost:3002')
            ->postJson('http://platform.acceptance.localhost/api/v1/super/auth/login', ['email' => $disabled->email, 'password' => $this->password])
            ->assertStatus(401)->assertJsonPath('error.code', 'PROVIDER_INVALID_CREDENTIALS');
        [$unverified] = $this->provider('unverified', verified: false);
        $this->postJson('http://platform.acceptance.localhost/api/v1/super/auth/login', ['email' => $unverified->email, 'password' => $this->password])
            ->assertStatus(401)->assertJsonPath('error.code', 'PROVIDER_INVALID_CREDENTIALS');
        [$provider] = $this->provider('restart');
        $this->login($provider);
        $first = $this->postJson('http://platform.acceptance.localhost/api/v1/super/auth/mfa/enroll/start')->assertOk()->json('data.secret');
        $second = $this->postJson('http://platform.acceptance.localhost/api/v1/super/auth/mfa/enroll/start')->assertOk()->json('data.secret');
        $this->assertNotSame($first, $second);
        $this->postJson('http://platform.acceptance.localhost/api/v1/super/auth/mfa/enroll/confirm',
            ['code' => TOTP::createFromSecret($first)->at(now('UTC')->timestamp)])
            ->assertStatus(401)->assertJsonPath('error.code', 'PROVIDER_MFA_INVALID');
        $this->postJson('http://platform.acceptance.localhost/api/v1/super/auth/logout')->assertOk();
        $this->assertNull(session('provider.pending'));
        $this->postJson('http://platform.acceptance.localhost/api/v1/super/auth/mfa/enroll/confirm',
            ['code' => TOTP::createFromSecret($second)->at(now('UTC')->timestamp)])
            ->assertStatus(401)->assertJsonPath('error.code', 'PROVIDER_MFA_REQUIRED');
        $this->getJson('http://platform.acceptance.localhost/api/v1/super/auth/register')->assertStatus(404);
    }

    public function test_totp_window_replay_and_recovery_one_time(): void
    {
        [$provider, $secret] = $this->provider('factor', enrolled: true);
        $mfa = app(ProviderMfaService::class);
        $valid = TOTP::createFromSecret($secret)->at(now('UTC')->timestamp);
        $this->assertNotNull($mfa->matchingCounter($secret, $valid));
        $this->assertNull($mfa->matchingCounter($secret, 'not-six'));
        $old = TOTP::createFromSecret($secret)->at(now('UTC')->subSeconds(120)->timestamp);
        $this->assertNull($mfa->matchingCounter($secret, $old));
        $this->login($provider);
        $this->postJson('/api/v1/super/auth/mfa/verify', ['code' => 'not-six'])
            ->assertStatus(401)->assertJsonPath('error.code', 'PROVIDER_MFA_INVALID');
        $this->postJson('/api/v1/super/auth/mfa/verify', ['code' => $valid])->assertOk();
        $this->postJson('/api/v1/super/auth/logout')->assertOk();
        $this->login($provider);
        $this->postJson('/api/v1/super/auth/mfa/verify', ['code' => $valid])
            ->assertStatus(401)->assertJsonPath('error.code', 'PROVIDER_MFA_REPLAYED');
        $code = strtoupper(bin2hex(random_bytes(16)));
        DB::connection('pgsql_provider')->table('provider_mfa_recovery_codes')->insert([
            'id' => (string) Str::uuid7(), 'provider_user_id' => $provider->id,
            'code_hash' => hash_hmac('sha256', $code, (string) config('app.key')),
            'created_at' => now('UTC'), 'updated_at' => now('UTC'),
        ]);
        $this->postJson('/api/v1/super/auth/mfa/verify', ['code' => $code])->assertOk();
        $this->postJson('/api/v1/super/auth/logout')->assertOk();
        $this->login($provider);
        $this->postJson('/api/v1/super/auth/mfa/verify', ['code' => $code])
            ->assertStatus(401)->assertJsonPath('error.code', 'PROVIDER_MFA_INVALID');
        $this->assertExternalCollectorContract();
    }

    public function test_pending_expiry_absolute_session_and_auth_version_revocation(): void
    {
        [$provider, $secret] = $this->provider('expiry', enrolled: true);
        $this->login($provider);
        $this->withSession(['provider.pending' => [
            'provider_id' => $provider->id, 'auth_version' => $provider->auth_version,
            'challenge_id' => (string) Str::uuid(), 'expires_at' => now('UTC')->timestamp - 1, 'attempts' => 0,
        ]]);
        $this->postJson('/api/v1/super/auth/mfa/verify', ['code' => '000000'])
            ->assertStatus(401)->assertJsonPath('error.code', 'PROVIDER_MFA_REQUIRED');
        $this->login($provider);
        $this->postJson('/api/v1/super/auth/mfa/verify',
            ['code' => TOTP::createFromSecret($secret)->at(now('UTC')->timestamp)])->assertOk();
        $this->withSession(['provider.authenticated_at' => now('UTC')->timestamp - 14401]);
        $this->getJson('/api/v1/super/auth/me')->assertStatus(401);
        $this->login($provider);
        $this->travel(31)->seconds();
        $this->postJson('/api/v1/super/auth/mfa/verify',
            ['code' => TOTP::createFromSecret($secret)->at(now('UTC')->timestamp)])->assertOk();
        DB::connection('pgsql_provider')->table('provider_users')->where('id', $provider->id)->increment('auth_version');
        $this->getJson('/api/v1/super/auth/me')->assertStatus(401);
    }

    public function test_capability_freshness_guard_separation_and_logout(): void
    {
        [$provider, $secret] = $this->provider('capability', enrolled: true);
        $this->withHeader('Origin', 'http://localhost:3002')
            ->getJson('/api/v1/super/auth/me')->assertStatus(401);
        $tenant = $this->tenantFixture('capability');
        $this->tenantUserIds[] = $tenant->id;
        $tenantCookies = $this->loginTenantStaff($tenant->email);
        $this->withServerVariables(['HTTP_HOST' => 'foundation.acceptance.localhost'])
            ->withHeaders(['Accept' => 'application/json', 'Origin' => 'http://localhost:3001'])
            ->withUnencryptedCookies($tenantCookies)->withCredentials()
            ->getJson('http://foundation.acceptance.localhost/api/v1/company/context')->assertOk();
        $this->withHeader('Origin', 'http://localhost:3002')->getJson('/api/v1/super/auth/me')->assertStatus(401);
        $this->login($provider);
        $this->postJson('/api/v1/super/auth/mfa/verify',
            ['code' => TOTP::createFromSecret($secret)->at(now('UTC')->timestamp)])->assertOk();
        $this->withHeader('X-Capability', 'provider.approval.review')
            ->getJson('/api/v1/super/approvals')->assertStatus(403);
        $this->grant($provider, 'provider.approval.review');
        $this->getJson('/api/v1/super/approvals')->assertOk();
        DB::connection('pgsql_provider')->table('provider_user_capabilities')
            ->where('provider_user_id', $provider->id)->where('capability_key', 'provider.approval.review')->delete();
        DB::connection('pgsql_provider')->table('provider_users')->where('id', $provider->id)
            ->increment('authorization_version');
        $this->getJson('/api/v1/super/approvals')->assertStatus(403);
        $this->postJson('/api/v1/super/auth/logout')->assertOk();
        $this->getJson('/api/v1/super/auth/me')->assertStatus(401);
    }

    public function test_approval_dual_control_expiry_revoke_action_target_and_audit(): void
    {
        [$requester] = $this->provider('requester', enrolled: true);
        [$reviewer] = $this->provider('reviewer', enrolled: true);
        [$second] = $this->provider('second', enrolled: true);
        $this->grant($requester, 'company.recover');
        $this->grant($reviewer, 'provider.approval.review');
        $this->grant($second, 'provider.approval.review');
        $service = app(ProviderApprovalService::class);
        $target = (string) Str::uuid7();
        $requesterCtx = $this->context($requester);
        $reviewerCtx = $this->context($reviewer);
        $secondCtx = $this->context($second);
        $requestId = $service->request($requesterCtx, 'company.recover', $target,
            'Controlled proof recovery request', 'TICKET-10B-01');
        $this->assertSame('PENDING', DB::connection('pgsql_provider')->table('provider_approval_requests')
            ->where('id', $requestId)->value('status'));
        $this->expectProviderDenial(fn () => $service->decide($requesterCtx, $requestId, 'APPROVE'));
        $this->expectProviderDenial(fn () => $service->decide($this->context($reviewer, false), $requestId, 'APPROVE'));
        $this->assertSame('APPROVED', $service->decide($reviewerCtx, $requestId, 'APPROVE'));
        $this->expectProviderDenial(fn () => $service->decide($reviewerCtx, $requestId, 'APPROVE'));
        $this->usable($service, $requestId, $requester->id, 'company.recover', $target);
        $this->expectProviderDenial(fn () => $this->usable($service, $requestId,
            $requester->id, 'company.provision', $target));
        $this->expectProviderDenial(fn () => $this->usable($service, $requestId,
            $requester->id, 'company.recover', (string) Str::uuid7()));
        $service->revoke($requesterCtx, $requestId);
        $this->expectProviderDenial(fn () => $this->usable($service, $requestId,
            $requester->id, 'company.recover', $target));
        $this->assertExternalCollectorContract();

        config(['provider.approval_required' => array_replace(config('provider.approval_required'),
            ['company.recover' => 2])]);
        $two = $service->request($requesterCtx, 'company.recover', (string) Str::uuid7(),
            'Two reviewers required', 'TICKET-10B-02');
        $this->assertSame('PENDING', $service->decide($reviewerCtx, $two, 'APPROVE'));
        $this->assertSame('APPROVED', $service->decide($secondCtx, $two, 'APPROVE'));
        $this->travel(901)->seconds();
        $this->expectProviderDenial(fn () => $this->usable($service, $two,
            $requester->id, 'company.recover', DB::connection('pgsql_provider')
                ->table('provider_approval_requests')->where('id', $two)->value('target_id')));
    }

    public function test_approval_request_validation_capability_and_audit_failure_rollback(): void
    {
        [$requester] = $this->provider('fault', enrolled: true);
        $service = app(ProviderApprovalService::class);
        $context = $this->context($requester);
        $target = (string) Str::uuid7();
        $this->expectProviderDenial(fn () => $service->request($context, 'company.recover', $target, 'Reason', 'TICKET-1'));
        $this->grant($requester, 'company.recover');
        $context = $this->context($requester);
        $staleStepUp = new ProviderContext($requester->id, $requester->auth_version,
            $requester->fresh()->authorization_version, (string) Str::uuid(),
            now('UTC')->timestamp - 601, now('UTC')->timestamp - 601);
        $this->expectProviderDenial(fn () => $service->request($staleStepUp,
            'company.recover', $target, 'Expired step-up', 'TICKET-EXPIRED'));
        $this->expectProviderDenial(fn () => $service->request($context, 'company.recover', $target, '', 'TICKET-1'));
        $this->expectProviderDenial(fn () => $service->request($context, 'company.recover', $target, 'Reason', ''));
        $before = DB::connection('pgsql_provider')->table('provider_approval_requests')->count();
        if (getenv('PROVIDER_FOUNDATION_AUDIT_FAULT_ARMED') !== '1') {
            throw new \RuntimeException('PROVIDER_FOUNDATION_AUDIT_FAULT_NOT_ARMED');
        }
        try {
            $service->request($context, 'company.recover', $target, 'Fault proof', 'TICKET-FAULT');
            $this->fail('Audit failure did not roll back approval.');
        } catch (QueryException $exception) {
            $this->assertSame('23514', $exception->errorInfo[0]);
        }
        $this->assertSame($before, DB::connection('pgsql_provider')->table('provider_approval_requests')->count());
        $this->assertExternalCollectorContract();
    }

    public function test_approval_reviewer_capability_rejection_and_requester_revocation_at_use(): void
    {
        [$requester] = $this->provider('requester-revoke', enrolled: true);
        [$reviewer] = $this->provider('reviewer-reject', enrolled: true);
        $this->grant($requester, 'company.recover');
        $service = app(ProviderApprovalService::class);
        $requesterContext = $this->context($requester);
        $target = (string) Str::uuid7();
        $approvalId = $service->request($requesterContext, 'company.recover', $target,
            'Controlled requester capability test', 'TICKET-10B-CAP');
        $this->expectProviderDenial(fn () => $service->decide($this->context($reviewer), $approvalId, 'APPROVE'));
        $this->grant($reviewer, 'provider.approval.review');
        $this->assertSame('APPROVED', $service->decide($this->context($reviewer), $approvalId, 'APPROVE'));
        DB::connection('pgsql_provider')->table('provider_user_capabilities')
            ->where('provider_user_id', $requester->id)->where('capability_key', 'company.recover')->delete();
        DB::connection('pgsql_provider')->table('provider_users')->where('id', $requester->id)
            ->increment('authorization_version');
        $this->expectProviderDenial(fn () => $this->usable($service, $approvalId,
            $requester->id, 'company.recover', $target));

        $this->grant($requester, 'company.recover');
        $rejected = $service->request($this->context($requester), 'company.recover', (string) Str::uuid7(),
            'Controlled rejection proof', 'TICKET-10B-REJ');
        $this->assertSame('REJECTED', $service->decide($this->context($reviewer), $rejected, 'REJECT'));
        $this->expectProviderDenial(fn () => $service->decide($this->context($reviewer), $rejected, 'APPROVE'));
        $this->expectProviderDenial(fn () => $this->usable($service, $rejected,
            $requester->id, 'company.recover', DB::connection('pgsql_provider')
                ->table('provider_approval_requests')->where('id', $rejected)->value('target_id')));
    }

    private function usable(ProviderApprovalService $service, string $requestId, string $requesterId,
        string $action, string $target): void
    {
        app(ProviderDatabaseContext::class)->run($requesterId, fn ($connection) =>
            $service->assertApprovalUsable($connection, $requestId, $requesterId, $action, $target));
    }

    private function tenantFixture(string $key): User
    {
        $fixture = $this->externalFixture['tenants'][$key] ?? null;
        if (! is_array($fixture) || ! is_string($fixture['id'] ?? null) || ! is_string($fixture['email'] ?? null)) {
            throw new \RuntimeException("PROVIDER_FOUNDATION_TENANT_FIXTURE_MISSING:$key");
        }
        $user = new User;
        $user->forceFill(['id' => $fixture['id'], 'email' => $fixture['email']]);
        $user->exists = true;
        return $user;
    }

    private function expectProviderDenial(callable $operation): void
    {
        try {
            $operation();
            $this->fail('Provider operation unexpectedly accepted.');
        } catch (ProviderAccessException $exception) {
            $this->assertContains($exception->status, [401, 403, 429]);
        }
    }

    private function assertExternalCollectorContract(): void
    {
        $this->assertSame('DCRM_PROVIDER_FOUNDATION_READ_ONLY_COLLECTOR_V1',
            getenv('PROVIDER_FOUNDATION_COLLECTOR_CONTRACT'));
    }
}
