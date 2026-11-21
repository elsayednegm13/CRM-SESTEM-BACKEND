<?php

namespace Tests\Feature\Provider;

use App\Modules\Provider\Application\ProviderApprovalService;
use App\Modules\Provider\Domain\ProviderContext;
use App\Modules\Provider\Infrastructure\Persistence\ProviderUser;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use OTPHP\TOTP;
use RuntimeException;
use Symfony\Component\Process\Process;
use Tests\TestCase;

/** Two independent PHP/PostgreSQL sessions launched behind one barrier. */
final class ProviderConcurrencyTest extends TestCase
{
    private array $ids = [];

    protected function setUp(): void
    {
        parent::setUp();
        if (! getenv('PROVIDER_TEST_RUNTIME_PASSWORD') || ! getenv('RLS_TEST_RUNTIME_PASSWORD')) {
            $this->markTestSkipped('Control 10B concurrent runtime credentials are required.');
        }
        if (DB::selectOne('SELECT current_database() AS db')->db !== 'daleel_crm_b10b_disposable'
            || config('database.connections.pgsql.port') != 55437) {
            throw new RuntimeException('Refusing concurrency fixtures outside the exact 10B target.');
        }
    }

    protected function tearDown(): void
    {
        if ($this->ids !== []) {
            DB::table('security_audit_events')->whereIn('actor_id', $this->ids)->delete();
            $requests = DB::table('provider_approval_requests')->whereIn('requester_provider_user_id', $this->ids)
                ->pluck('id')->all();
            DB::table('provider_approval_decisions')->whereIn('approval_request_id', $requests)->delete();
            DB::table('provider_approval_requests')->whereIn('id', $requests)->delete();
            DB::table('provider_user_capabilities')->whereIn('provider_user_id', $this->ids)->delete();
            DB::table('provider_mfa_recovery_codes')->whereIn('provider_user_id', $this->ids)->delete();
            DB::table('provider_mfa_totp')->whereIn('provider_user_id', $this->ids)->delete();
            DB::table('provider_users')->whereIn('id', $this->ids)->delete();
        }
        parent::tearDown();
    }

    private function provider(bool $mfa = false): array
    {
        $user = ProviderUser::query()->create([
            'email' => 'concurrent-'.Str::lower(Str::random(12)).'@proof.invalid',
            'password' => Hash::make(Str::random(32)),
        ]);
        $this->ids[] = $user->id;
        $user->forceFill(['email_verified_at' => now('UTC'),
            'mfa_enrolled_at' => $mfa ? now('UTC') : null])->save();
        $secret = null;
        if ($mfa) {
            $secret = TOTP::generate(null, 32)->getSecret();
            DB::table('provider_mfa_totp')->insert([
                'provider_user_id' => $user->id, 'secret_ciphertext' => Crypt::encryptString($secret),
                'confirmed_at' => now('UTC'), 'created_at' => now('UTC'), 'updated_at' => now('UTC'),
            ]);
        }
        return [$user->fresh(), $secret];
    }

    private function grant(ProviderUser $user, string $key): void
    {
        DB::table('provider_user_capabilities')->insert([
            'provider_user_id' => $user->id, 'capability_key' => $key, 'granted_at' => now('UTC'),
        ]);
    }

    private function context(ProviderUser $user): ProviderContext
    {
        return new ProviderContext($user->id, $user->auth_version, $user->authorization_version,
            (string) Str::uuid(), now('UTC')->timestamp, now('UTC')->timestamp);
    }

    /** @return list<string> */
    private function race(array $a, array $b): array
    {
        $prefix = sys_get_temp_dir().DIRECTORY_SEPARATOR.'daleel-b10b-concurrency-'.Str::uuid();
        $barrier = $prefix.'.barrier';
        $readyA = $prefix.'.a.ready';
        $readyB = $prefix.'.b.ready';
        foreach ([$barrier, $readyA, $readyB] as $path) {
            if (file_exists($path)) {
                throw new RuntimeException('Control concurrency path unexpectedly exists.');
            }
        }
        $env = [
            'DB_USERNAME' => getenv('RLS_TEST_RUNTIME_USER'),
            'DB_PASSWORD' => getenv('RLS_TEST_RUNTIME_PASSWORD'),
            'PROVIDER_DB_USERNAME' => getenv('PROVIDER_TEST_RUNTIME_USER'),
            'PROVIDER_DB_PASSWORD' => getenv('PROVIDER_TEST_RUNTIME_PASSWORD'),
        ];
        $script = base_path('tests/Support/ProviderConcurrentAttempt.php');
        $one = new Process([PHP_BINARY, $script, $barrier, $readyA], base_path(), $env);
        $two = new Process([PHP_BINARY, $script, $barrier, $readyB], base_path(), $env);
        $one->setInput(json_encode($a, JSON_THROW_ON_ERROR));
        $two->setInput(json_encode($b, JSON_THROW_ON_ERROR));
        try {
            $one->start();
            $two->start();
            $deadline = microtime(true) + 15;
            while ((! is_file($readyA) || ! is_file($readyB)) && microtime(true) < $deadline) {
                usleep(10000);
            }
            $this->assertFileExists($readyA);
            $this->assertFileExists($readyB);
            file_put_contents($barrier, 'go');
            $one->wait();
            $two->wait();
            $this->assertSame('', $one->getErrorOutput());
            $this->assertSame('', $two->getErrorOutput());
            return [trim($one->getOutput()), trim($two->getOutput())];
        } finally {
            if ($one->isRunning()) { $one->stop(); }
            if ($two->isRunning()) { $two->stop(); }
            foreach ([$barrier, $readyA, $readyB] as $path) {
                if (is_file($path)) { unlink($path); }
            }
        }
    }

    public function test_concurrent_same_totp_counter_and_recovery_code_have_one_winner(): void
    {
        [$user, $secret] = $this->provider(mfa: true);
        $factor = ['operation' => 'factor', 'actor' => $user->id,
            'code' => TOTP::createFromSecret($secret)->at(now('UTC')->timestamp)];
        $outputs = $this->race($factor, $factor);
        sort($outputs);
        $this->assertSame(['ACCEPTED', 'DENIED'], $outputs);
        $this->assertNotNull(DB::table('provider_mfa_totp')->where('provider_user_id', $user->id)
            ->value('last_used_counter'));

        $code = strtoupper(bin2hex(random_bytes(16)));
        DB::table('provider_mfa_recovery_codes')->insert([
            'id' => (string) Str::uuid7(), 'provider_user_id' => $user->id,
            'code_hash' => hash_hmac('sha256', $code, (string) config('app.key')),
            'created_at' => now('UTC'), 'updated_at' => now('UTC'),
        ]);
        $recovery = ['operation' => 'factor', 'actor' => $user->id, 'code' => $code];
        $outputs = $this->race($recovery, $recovery);
        sort($outputs);
        $this->assertSame(['ACCEPTED', 'DENIED'], $outputs);
        $this->assertSame(1, DB::table('provider_mfa_recovery_codes')->where('provider_user_id', $user->id)
            ->whereNotNull('used_at')->count());
        $this->assertSame(1, DB::table('security_audit_events')->where('actor_id', $user->id)
            ->where('event_type', 'provider.mfa.recovery_code_used')->count());
    }

    public function test_concurrent_approval_duplicate_distinct_reviewers_and_revoke_race(): void
    {
        [$requester] = $this->provider();
        [$reviewerA] = $this->provider();
        [$reviewerB] = $this->provider();
        $this->grant($requester, 'company.recover');
        $this->grant($reviewerA, 'provider.approval.review');
        $this->grant($reviewerB, 'provider.approval.review');
        $service = app(ProviderApprovalService::class);
        $id = $service->request($this->context($requester), 'company.recover', (string) Str::uuid7(),
            'Concurrent approval proof', 'TICKET-CONC-01');
        $review = ['operation' => 'decide', 'actor' => $reviewerA->id,
            'auth_version' => 1, 'authorization_version' => 1, 'request_id' => $id];
        $outputs = $this->race($review, $review);
        sort($outputs);
        $this->assertSame(['APPROVED', 'DENIED'], $outputs);
        $this->assertSame(1, DB::table('provider_approval_decisions')->where('approval_request_id', $id)->count());

        config(['provider.approval_required' => array_replace(config('provider.approval_required'),
            ['company.recover' => 2])]);
        $two = $service->request($this->context($requester), 'company.recover', (string) Str::uuid7(),
            'Two independent reviewers', 'TICKET-CONC-02');
        $reviewA = array_replace($review, ['request_id' => $two]);
        $reviewB = array_replace($review, ['actor' => $reviewerB->id, 'request_id' => $two]);
        $outputs = $this->race($reviewA, $reviewB);
        sort($outputs);
        $this->assertSame(['APPROVED', 'PENDING'], $outputs);
        $this->assertSame(2, DB::table('provider_approval_decisions')->where('approval_request_id', $two)->count());
        $this->assertSame('APPROVED', DB::table('provider_approval_requests')->where('id', $two)->value('status'));

        config(['provider.approval_required' => array_replace(config('provider.approval_required'),
            ['company.recover' => 1])]);
        $raceId = $service->request($this->context($requester), 'company.recover', (string) Str::uuid7(),
            'Revoke race proof', 'TICKET-CONC-03');
        $decision = array_replace($review, ['request_id' => $raceId]);
        $revoke = ['operation' => 'revoke', 'actor' => $requester->id,
            'auth_version' => 1, 'authorization_version' => 1, 'request_id' => $raceId];
        $outputs = $this->race($decision, $revoke);
        $this->assertContains('REVOKED', $outputs);
        $this->assertSame('REVOKED', DB::table('provider_approval_requests')->where('id', $raceId)->value('status'));
    }
}
