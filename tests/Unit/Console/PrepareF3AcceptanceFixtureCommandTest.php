<?php

declare(strict_types=1);

namespace Tests\Unit\Console;

use App\Console\Commands\PrepareF3AcceptanceFixture;
use App\Modules\Identity\Application\F3AcceptanceFixtureOrchestrator;
use App\Modules\Identity\Application\F3AcceptanceFixturePrewriteAttestor;
use Illuminate\Support\Facades\Artisan;
use LogicException;
use Symfony\Component\Console\Tester\CommandTester;
use Tests\TestCase;

final class PrepareF3AcceptanceFixtureCommandTest extends TestCase
{
    public function test_real_container_resolves_the_intended_attestor_interface_and_disabled_command_fails_closed(): void
    {
        config()->set('f3_acceptance.fixture_enabled', false);
        $command = Artisan::all()['dcrm:prepare-f3-acceptance-fixture'];
        self::assertInstanceOf(F3AcceptanceFixturePrewriteAttestor::class, app()->make(F3AcceptanceFixturePrewriteAttestor::class));

        $tester = new CommandTester($command);
        self::assertSame(1, $tester->execute([]));
        self::assertStringContainsString('F3_FIXTURE_DISABLED', $tester->getDisplay());
    }

    public function test_valid_command_invocation_validates_then_attests_once_then_prepares_once(): void
    {
        [$attestor, $workflow] = $this->bindFakes();
        $tester = $this->tester();
        $tester->setInputs([json_encode($this->validPayload(), JSON_THROW_ON_ERROR)]);

        self::assertSame(0, $tester->execute([]));
        self::assertSame(1, $attestor->calls);
        self::assertSame(1, $workflow->calls);
        self::assertSame(['attest', 'prepare'], $attestor->events);
        $decoded = json_decode(trim($tester->getDisplay()), true, 16, JSON_THROW_ON_ERROR);
        self::assertSame('F3_FIXTURE_PREPARED_REQUIRES_COLLECTOR_AND_INDEPENDENT_VERIFIER', $decoded['status']);
        self::assertSame('AUTHENTICATED', $decoded['provider']['first_factor_login'] ?? null);
        self::assertSame('ABSENT', $decoded['provider']['step_up_before_enrollment'] ?? null);
        self::assertSame('MFA_REQUIRED', $decoded['provider']['mfa_after_enrollment'] ?? null);
        self::assertSame('VERIFIED', $decoded['provider']['step_up'] ?? null);
        self::assertSame(2, $decoded['provider']['provisioned_tenants'] ?? null);
    }

    public function test_invalid_input_calls_neither_attestor_nor_workflow(): void
    {
        [$attestor, $workflow] = $this->bindFakes();
        $tester = $this->tester();
        $tester->setInputs(['{"run_id":"forged"}']);

        self::assertSame(1, $tester->execute([]));
        self::assertSame(0, $attestor->calls);
        self::assertSame(0, $workflow->calls);
        self::assertStringContainsString('F3_FIXTURE_REJECTED:', $tester->getDisplay());
    }

    public function test_attestation_failure_calls_attestor_once_and_never_calls_workflow(): void
    {
        [$attestor, $workflow] = $this->bindFakes(true);
        $tester = $this->tester();
        $tester->setInputs([json_encode($this->validPayload(), JSON_THROW_ON_ERROR)]);

        self::assertSame(1, $tester->execute([]));
        self::assertSame(1, $attestor->calls);
        self::assertSame(0, $workflow->calls);
        self::assertStringNotContainsString('synthetic-secret', $tester->getDisplay());
    }

    private function tester(): CommandTester
    {
        config()->set('f3_acceptance.fixture_enabled', true);
        config()->set('f3_acceptance.allowed_environments', ['testing']);
        config()->set('f3_acceptance.run_id', 'f3-command-test');
        config()->set('f3_acceptance.expected_database', 'dcrm_p1p2_command_test');

        return new CommandTester(Artisan::all()['dcrm:prepare-f3-acceptance-fixture']);
    }

    /** @return array{object,object} */
    private function bindFakes(bool $reject = false): array
    {
        $events = [];
        $attestor = new class($events, $reject) implements F3AcceptanceFixturePrewriteAttestor {
            public int $calls = 0;
            /** @var list<string> */ public array $events;
            /** @param list<string> $events */
            public function __construct(array &$events, private readonly bool $reject) { $this->events =& $events; }
            public function attest(string $runId, string $permitId): void
            {
                $this->calls++; $this->events[] = 'attest';
                if ($this->reject) { throw new LogicException('synthetic-secret-must-not-leak'); }
            }
        };
        $workflow = new class($events) implements F3AcceptanceFixtureOrchestrator {
            public int $calls = 0;
            /** @var list<string> */ public array $events;
            /** @param list<string> $events */
            public function __construct(array &$events) { $this->events =& $events; }
            public function prepare(array $input): array
            {
                $this->calls++; $this->events[] = 'prepare';
                return [
                    'run_id' => $input['run_id'],
                    'provider' => [
                        'first_factor_login' => 'AUTHENTICATED',
                        'step_up_before_enrollment' => 'ABSENT',
                        'mfa_after_enrollment' => 'MFA_REQUIRED',
                        'step_up' => 'VERIFIED',
                        'provisioned_tenants' => 2,
                    ],
                    'tenants' => [
                        'A' => ['tenant_id' => '11111111-1111-4111-8111-111111111111'],
                        'B' => ['tenant_id' => '22222222-2222-4222-8222-222222222222'],
                    ],
                ];
            }
        };
        app()->instance(F3AcceptanceFixturePrewriteAttestor::class, $attestor);
        app()->instance(F3AcceptanceFixtureOrchestrator::class, $workflow);
        return [$attestor, $workflow];
    }

    /** @return array<string,mixed> */
    private function validPayload(): array
    {
        return [
            'run_id' => 'f3-command-test', 'expected_database' => 'dcrm_p1p2_command_test',
            'permit_id' => str_repeat('a', 64),
            'provider' => ['bootstrap_secret' => str_repeat('b', 64), 'email' => 'provider@example.invalid', 'password' => 'Strong!Provider123'],
            'tenants' => [
                'A' => ['display_name' => 'A', 'slug' => 'tenant-a', 'timezone' => 'Africa/Cairo', 'admin_email' => 'a@example.invalid', 'initial_password' => 'Strong!Initial123A', 'password' => 'Strong!Final123A', 'observer_email' => 'observer-a@example.invalid', 'observer_password' => 'Strong!Observer123A'],
                'B' => ['display_name' => 'B', 'slug' => 'tenant-b', 'timezone' => 'Africa/Cairo', 'admin_email' => 'b@example.invalid', 'initial_password' => 'Strong!Initial123B', 'password' => 'Strong!Final123B', 'observer_email' => 'observer-b@example.invalid', 'observer_password' => 'Strong!Observer123B'],
            ],
        ];
    }
}
