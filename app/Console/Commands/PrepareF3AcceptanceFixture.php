<?php

declare(strict_types=1);

namespace App\Console\Commands;

use App\Modules\Identity\Application\F3AcceptanceFixtureInput;
use App\Modules\Identity\Application\F3AcceptanceFixtureOrchestrator;
use App\Modules\Identity\Application\F3AcceptanceFixturePrewriteAttestor;
use Illuminate\Console\Command;
use Symfony\Component\Console\Input\StreamableInputInterface;
use Throwable;

/** Internal, default-disabled acceptance command. Secrets are stdin-only. */
final class PrepareF3AcceptanceFixture extends Command
{
    protected $signature = 'dcrm:prepare-f3-acceptance-fixture';
    protected $description = 'Prepare an identity-bound F3 A/B fixture through legitimate services';

    public function handle(
        F3AcceptanceFixtureInput $inputs,
        F3AcceptanceFixturePrewriteAttestor $attestor,
        F3AcceptanceFixtureOrchestrator $workflow,
    ): int
    {
        if (config('f3_acceptance.fixture_enabled') !== true
            || ! in_array(app()->environment(), (array) config('f3_acceptance.allowed_environments'), true)
            || ! is_string(config('f3_acceptance.run_id'))
            || ! is_string(config('f3_acceptance.expected_database'))) {
            $this->error('F3_FIXTURE_DISABLED');
            return self::FAILURE;
        }
        try {
            $stream = ($this->input instanceof StreamableInputInterface ? $this->input->getStream() : null) ?? STDIN;
            $payload = json_decode(stream_get_contents($stream), true, 32, JSON_THROW_ON_ERROR);
            $validated = $inputs->validate($payload, config('f3_acceptance.run_id'), config('f3_acceptance.expected_database'));
            $attestor->attest($validated['run_id'], $validated['permit_id']);
            $result = $workflow->prepare($validated);
            if (! is_array($result['provider'] ?? null)) {
                throw new \LogicException('F3 fixture provider summary is missing.');
            }
            $this->line(json_encode([
                'status' => 'F3_FIXTURE_PREPARED_REQUIRES_COLLECTOR_AND_INDEPENDENT_VERIFIER',
                'run_id' => $result['run_id'], 'provider' => $result['provider'], 'tenants' => $result['tenants'],
            ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
            return self::SUCCESS;
        } catch (Throwable $exception) {
            $this->error('F3_FIXTURE_REJECTED:'.$exception::class);
            return self::FAILURE;
        }
    }
}
