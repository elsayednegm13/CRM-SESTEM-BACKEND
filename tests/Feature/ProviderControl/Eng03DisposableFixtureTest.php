<?php

namespace Tests\Feature\ProviderControl;

use OTPHP\TOTP;
use PDO;
use PHPUnit\Framework\TestCase;
use Tests\Support\Eng03ProviderFixture;

/** Focused external-HTTP acceptance against one pinned, freshly migrated ENG-03A DB per run. */
final class Eng03DisposableFixtureTest extends TestCase
{
    private string $tag;
    private string $runId;
    private string $serverIp;
    private array $actors;

    protected function setUp(): void
    {
        parent::setUp();
        $this->tag = (string) getenv('ENG03A_DB_TAG');
        self::assertContains($this->tag, ['a', 'b'], 'Refusing an unpinned test database.');
        $this->runId = bin2hex(random_bytes(4));
        $this->serverIp = gethostbyname("eng03a_acaaa49820_http_{$this->tag}");
        self::assertNotSame("eng03a_acaaa49820_http_{$this->tag}", $this->serverIp);
        $this->actors = json_decode($this->secret("{$this->tag}_actor_ids.json"), true, flags: JSON_THROW_ON_ERROR);
    }

    public function testGenuineProviderApprovalDirectAdminsAndHostFirstTenantIsolation(): void
    {
        $unauthed = $this->client('api.crm.localhost', 'http://localhost:3002');
        self::assertSame(204, $unauthed->request('GET', '/sanctum/csrf-cookie')['status']);
        self::assertSame(401, $unauthed->request('POST', '/api/v1/super/provisioning-operations',
            $this->intent('unauthorized'), ['Idempotency-Key' => "eng03a-{$this->tag}-unauthorized-001"])['status']);

        $wrongOrigin = $this->client('api.crm.localhost', 'http://evil.invalid');
        $wrongOrigin->request('GET', '/sanctum/csrf-cookie');
        self::assertSame(403, $wrongOrigin->request('POST', '/api/v1/super/auth/login',
            ['email' => "requester.{$this->tag}.eng03a@example.invalid", 'password' => $this->secret('requester_password')])['status']);
        $wrongHost = $this->client('wrong.crm.localhost', 'http://localhost:3002');
        $wrongHost->request('GET', '/sanctum/csrf-cookie');
        self::assertSame(403, $wrongHost->request('POST', '/api/v1/super/auth/login',
            ['email' => "requester.{$this->tag}.eng03a@example.invalid", 'password' => $this->secret('requester_password')])['status']);

        $requester = $this->loginProvider('requester');
        $reviewer = $this->loginProvider('reviewer');
        $denied = $this->loginProvider('denied');
        self::assertNotSame($this->actors['requester'], $this->actors['reviewer']);
        $deniedResult = $denied->request('POST', '/api/v1/super/provisioning-operations',
            $this->intent('denied'), ['Idempotency-Key' => "eng03a-{$this->tag}-denied-001"]);
        self::assertSame(403, $deniedResult['status']);
        self::assertSame(0, $this->operationCount($this->actors['denied']));

        $first = $this->provision($requester, $reviewer, 'test-one', 'admin_a_password', true);
        $second = $this->provision($requester, $reviewer, 'test-two', 'admin_b_password', false);
        self::assertNotSame($first['tenant_id'], $second['tenant_id']);
        self::assertNotSame($first['hostname'], $second['hostname']);

        $email = "accepted.shared.{$this->tag}.{$this->runId}@example.invalid";
        $tenantA = $this->client($first['hostname'], 'http://localhost:3001');
        $tenantB = $this->client($second['hostname'], 'http://localhost:3001');
        self::assertSame(204, $tenantA->request('GET', '/sanctum/csrf-cookie')['status']);
        self::assertSame(204, $tenantB->request('GET', '/sanctum/csrf-cookie')['status']);
        $loginA = $tenantA->request('POST', '/api/v1/auth/login', ['email' => $email,
            'password' => $this->secret('admin_a_password')]);
        $loginB = $tenantB->request('POST', '/api/v1/auth/login', ['email' => $email,
            'password' => $this->secret('admin_b_password')]);
        self::assertSame(200, $loginA['status'], 'Tenant A real host-first login must succeed.');
        self::assertSame(200, $loginB['status'], 'Tenant B real host-first login must succeed.');
        self::assertNotSame($loginA['data']['id'] ?? null, $loginB['data']['id'] ?? null);
        self::assertSame($loginA['data']['id'], $tenantA->request('GET', '/api/v1/auth/me')['data']['id'] ?? null);
        self::assertSame($loginB['data']['id'], $tenantB->request('GET', '/api/v1/auth/me')['data']['id'] ?? null);

        $crossA = $this->client($first['hostname'], 'http://localhost:3001');
        $crossB = $this->client($second['hostname'], 'http://localhost:3001');
        $crossA->request('GET', '/sanctum/csrf-cookie');
        $crossB->request('GET', '/sanctum/csrf-cookie');
        self::assertSame(401, $crossA->request('POST', '/api/v1/auth/login', ['email' => $email,
            'password' => $this->secret('admin_b_password')])['status']);
        self::assertSame(401, $crossB->request('POST', '/api/v1/auth/login', ['email' => $email,
            'password' => $this->secret('admin_a_password')])['status']);

        $seed = $this->database('seed', 'seed_db_password');
        self::assertSame(0, (int) $seed->query('SELECT count(*) FROM tenant_founder_invitations')->fetchColumn());
        self::assertSame(0, (int) $seed->query('SELECT count(*) FROM outbox_messages')->fetchColumn());
        fwrite(STDOUT, json_encode(['db_tag' => $this->tag, 'run_id' => $this->runId, 'company_a' => $first,
            'company_b' => $second, 'staff_a' => $loginA['data']['id'], 'staff_b' => $loginB['data']['id']],
            JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES).PHP_EOL);
    }

    private function provision(Eng03ProviderFixture $requester, Eng03ProviderFixture $reviewer,
        string $suffix, string $passwordFile, bool $probeUnapproved): array
    {
        $key = "eng03a-{$this->tag}-{$this->runId}-{$suffix}-0001";
        $create = $requester->request('POST', '/api/v1/super/provisioning-operations', $this->intent($suffix),
            ['Idempotency-Key' => $key]);
        self::assertSame(202, $create['status'], 'Authentic Provider request must create a pending operation.');
        $operationId = $create['data']['id'];
        $approvalId = $create['data']['approval_request_id'];
        if ($probeUnapproved) {
            $before = $requester->request('POST', "/api/v1/super/provisioning-operations/{$operationId}/execute",
                ['initial_password' => $this->secret($passwordFile)]);
            self::assertSame(403, $before['status']);
            self::assertSame('PROVIDER_APPROVAL_NOT_USABLE', $before['error_code']);
        }
        $approved = $reviewer->request('POST', "/api/v1/super/approvals/{$approvalId}/approve",
            ['reason' => 'Independent fixture review', 'ticket_reference' => 'ENG03A-REVIEW-002',
                'expected_revision' => 1]);
        self::assertSame(200, $approved['status'], 'Distinct authenticated reviewer must approve.');
        $executed = $requester->request('POST', "/api/v1/super/provisioning-operations/{$operationId}/execute",
            ['initial_password' => $this->secret($passwordFile)]);
        self::assertSame(200, $executed['status'], 'Approved direct first-admin creation must execute.');
        self::assertSame('SUCCEEDED', $executed['data']['status'] ?? null);
        return ['operation_id' => $operationId, 'approval_id' => $approvalId,
            'tenant_id' => $executed['data']['tenant_id'], 'hostname' => $executed['data']['hostname']];
    }

    private function loginProvider(string $name): Eng03ProviderFixture
    {
        $client = $this->client('api.crm.localhost', 'http://localhost:3002');
        self::assertSame(204, $client->request('GET', '/sanctum/csrf-cookie')['status']);
        $login = $client->request('POST', '/api/v1/super/auth/login', [
            'email' => "{$name}.{$this->tag}.eng03a@example.invalid", 'password' => $this->secret("{$name}_password")]);
        self::assertSame(200, $login['status']);
        self::assertSame('MFA_REQUIRED', $login['data']['state'] ?? null);
        $totp = TOTP::createFromSecret($this->secret("{$this->tag}_{$name}_totp_secret"));
        $mfa = $client->request('POST', '/api/v1/super/auth/mfa/verify',
            ['code' => $totp->at((intdiv(time(), 30) + 1) * 30)]);
        self::assertSame(200, $mfa['status'], "Real {$name} MFA must succeed.");
        $me = $client->request('GET', '/api/v1/super/auth/me');
        self::assertSame(200, $me['status']);
        self::assertSame($this->actors[$name], $me['data']['id'] ?? null);
        self::assertTrue($me['data']['step_up_valid'] ?? false);
        return $client;
    }

    private function intent(string $suffix): array
    {
        return ['display_name' => "ENG03A {$suffix}", 'slug' => "eng03a-{$this->tag}-{$this->runId}-{$suffix}",
            'timezone' => 'UTC', 'first_admin_email' => "accepted.shared.{$this->tag}.{$this->runId}@example.invalid",
            'first_admin_display_name' => 'Fixture Administrator', 'reason' => 'ENG03A isolated acceptance',
            'ticket_reference' => 'ENG03A-ACCEPT-002'];
    }

    private function operationCount(string $providerId): int
    {
        $stmt = $this->database('control', 'control_password')->prepare(
            'SELECT count(*) FROM provider_control_operations WHERE requester_provider_user_id = ?');
        $stmt->execute([$providerId]);
        return (int) $stmt->fetchColumn();
    }

    private function database(string $role, string $passwordFile): PDO
    {
        $path = $role === 'seed' ? '/fixture/' : '/runtime/';
        return new PDO("pgsql:host=eng03a_acaaa49820_postgres;port=5432;dbname=eng03a_acaaa49820_{$this->tag}",
            "eng03a_acaaa49820_{$role}", trim(file_get_contents($path.$passwordFile) ?: ''),
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    }

    private function client(string $host, string $origin): Eng03ProviderFixture
    {
        return new Eng03ProviderFixture($host, $origin, $this->serverIp);
    }

    private function secret(string $name): string
    {
        return trim(file_get_contents("/fixture/{$name}") ?: '');
    }
}
