<?php

declare(strict_types=1);

namespace Tests\Unit\Console;

use App\Console\Commands\RunF3ConnectionReuseProbe;
use LogicException;
use ReflectionMethod;
use Tests\TestCase;

final class RunF3ConnectionReuseProbeCommandTest extends TestCase
{
    public function test_strict_two_actor_schema_is_accepted(): void
    {
        $this->invokeValidator($this->input());
        self::assertTrue(true);
    }

    public function test_extra_actor_field_is_rejected(): void
    {
        $input = $this->input();
        $input['actors']['A']['role'] = 'owner';
        $this->expectException(LogicException::class);
        $this->invokeValidator($input);
    }

    public function test_missing_distinct_retry_key_is_rejected(): void
    {
        $input = $this->input();
        unset($input['actors']['B']['retry_key_cross']);
        $this->expectException(LogicException::class);
        $this->invokeValidator($input);
    }

    private function invokeValidator(array $input): void
    {
        $method = new ReflectionMethod(RunF3ConnectionReuseProbe::class, 'assertInput');
        $method->invoke(new RunF3ConnectionReuseProbe, $input);
    }

    private function input(): array
    {
        $actor = static fn (string $side): array => [
            'host' => strtolower($side).'.acceptance.localhost', 'email' => strtolower($side).'@example.invalid',
            'password' => 'synthetic-password', 'retry_key_own' => '11111111-1111-4111-8111-111111111111',
            'retry_key_cross' => '22222222-2222-4222-8222-222222222222',
            'tenant_id' => '11111111-1111-4111-8111-111111111111',
            'own_lead_id' => '33333333-3333-4333-8333-333333333333',
            'cross_tenant_id' => '44444444-4444-4444-8444-444444444444',
            'cross_lead_id' => '55555555-5555-4555-8555-555555555555',
        ];

        return ['version' => 'DCRM-008-F3-REUSE-V1', 'run_id' => 'reuse-test-20261110', 'actors' => ['A' => $actor('A'), 'B' => $actor('B')]];
    }
}
