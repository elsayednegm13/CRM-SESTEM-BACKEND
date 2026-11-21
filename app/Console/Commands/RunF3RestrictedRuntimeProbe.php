<?php

declare(strict_types=1);

namespace App\Console\Commands;

use App\Modules\Identity\Application\LaravelRestrictedTenantRuntimeAdapter;
use App\Modules\Identity\Application\RestrictedTenantProbePlan;
use App\Modules\Identity\Application\TenantHostResolver;
use App\Modules\Identity\Application\TenantRestrictedProbeCoordinator;
use App\Modules\Identity\Application\TenantAcceptanceRequestBinder;
use App\Modules\Identity\Application\TenantRuntimeConnectionProvider;
use App\Modules\Identity\Application\TenantRuntimeIdentityAttestor;
use App\Modules\Identity\Domain\EmailAddressNormalizer;
use App\Modules\Identity\Http\Middleware\EnsureTenantLoginClientProof;
use Illuminate\Console\Command;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Cookie;
use Symfony\Component\HttpFoundation\Cookie as HttpCookie;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/** Internal acceptance command. Credentials/cookies are stdin-only and never echoed. */
final class RunF3RestrictedRuntimeProbe extends Command
{
    protected $signature = 'dcrm:f3-restricted-runtime-probe';
    protected $description = 'Run owner-authorized internal F3 restricted probes from private stdin';

    public function handle(
        TenantHostResolver $hosts,
        EmailAddressNormalizer $emails,
        EnsureTenantLoginClientProof $clientProof,
        LaravelRestrictedTenantRuntimeAdapter $adapter,
        TenantAcceptanceRequestBinder $requests,
        TenantRuntimeConnectionProvider $connections,
        TenantRuntimeIdentityAttestor $identity,
    ): int {
        if (config('f3_acceptance.enabled') !== true
            || ! in_array(app()->environment(), (array) config('f3_acceptance.allowed_environments'), true)) {
            $this->error('F3_RUNTIME_PROBE_DISABLED');
            return self::FAILURE;
        }

        try {
            $input = json_decode(stream_get_contents(STDIN), true, 32, JSON_THROW_ON_ERROR);
            $this->assertInput($input);
            if (! hash_equals((string) config('f3_acceptance.run_id'), $input['run_id'])) {
                throw new \LogicException('run-id');
            }
            $preflightConnection = $connections->connection();
            if ($preflightConnection->transactionLevel() !== 0) {
                throw new \LogicException('preflight-transaction');
            }
            $identity->attest($preflightConnection);
            $host = $hosts->resolve($input['host']);
            $email = $emails->normalize($input['email']);
            $loginClientProof = $this->issueLoginClientProof($clientProof, $input['host']);
            $records = [];
            foreach ($input['probes'] as $probe) {
                $request = Request::create(
                    'https://'.$input['host'].'/api/v1/auth/login',
                    'POST', [], ['daleel_login_client' => $loginClientProof], [],
                    ['HTTP_HOST' => $input['host'], 'HTTPS' => 'on'],
                );
                $session = new Store('dcrm-f3-'.$input['run_id'], new ArraySessionHandler(900));
                $session->start();
                $request->setLaravelSession($session);
                $plan = new RestrictedTenantProbePlan(
                    $input['run_id'], $probe['case_id'], $host->tenantId, $probe['operation'],
                    'laravel-runtime', 'adapter-owned', $probe['target_tenant_id'], $probe['record_id'],
                    $probe['expected_outcome'], $probe['expected_row_effects'],
                );
                $record = null;
                $requests->run($request, function () use (&$record, $clientProof, $adapter, $host, $email, $input, $probe, $request, $plan): void {
                    $clientProof->handle($request, function () use (&$record, $adapter, $host, $email, $input, $probe, $request, $plan) {
                        $record = TenantRestrictedProbeCoordinator::forRuntimeAdapter($adapter)->authenticateAndExecuteRuntime(
                            $host, $email, $input['password'], $probe['retry_key'], $request, $plan,
                        );
                        return response()->noContent();
                    });
                });
                if (! is_array($record) || ($record['cleanup_status'] ?? null) !== 'COMPLETE'
                    || ($record['classification'] ?? null) !== 'ADAPTER_OBSERVATION_REQUIRES_INDEPENDENT_VERIFICATION') {
                    throw new \LogicException('record-incomplete');
                }
                $records[] = $record;
            }
            $this->line(json_encode([
                'version' => 'DCRM-008-F3-RUNTIME-V1', 'run_id' => $input['run_id'],
                'classification' => 'RUNTIME_OBSERVATIONS_REQUIRE_INDEPENDENT_POSTCONDITION_VERIFICATION',
                'record_count' => count($records), 'records' => $records,
            ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
            return self::SUCCESS;
        } catch (Throwable $exception) {
            $this->error('F3_RUNTIME_PROBE_REJECTED:'.$exception::class);
            return self::FAILURE;
        }
    }

    private function assertInput(mixed $input): void
    {
        $keys = ['version','run_id','host','email','password','probes'];
        if (! is_array($input) || array_keys($input) !== $keys || $input['version'] !== 'DCRM-008-F3-RUNTIME-V1'
            || ! is_string($input['run_id']) || preg_match('/^[a-z0-9-]{8,64}$/D', $input['run_id']) !== 1
            || ! is_string($input['host']) || ! is_string($input['email']) || ! is_string($input['password'])
            || $input['password'] === '' || strlen($input['password']) > 1024
            || ! is_array($input['probes']) || $input['probes'] === [] || count($input['probes']) > 16) {
            throw new \LogicException('schema');
        }
        foreach ($input['probes'] as $probe) {
            $probeKeys = ['case_id','operation','target_tenant_id','record_id','expected_outcome','expected_row_effects','retry_key'];
            if (! is_array($probe) || array_keys($probe) !== $probeKeys
                || ! is_string($probe['case_id']) || preg_match('/^[A-Z0-9_-]{3,64}$/D', $probe['case_id']) !== 1
                || ! in_array($probe['operation'] ?? null, ['read','create','update','delete'], true)
                || ! is_string($probe['target_tenant_id'] ?? null) || ! is_string($probe['record_id'] ?? null)
                || ! in_array($probe['expected_outcome'] ?? null, ['ALLOWED','DENIED_ZERO_ROWS','DENIED_SQLSTATE_42501'], true)
                || ! is_int($probe['expected_row_effects'] ?? null) || $probe['expected_row_effects'] < 0
                || ! is_string($probe['retry_key'] ?? null)
                || preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/D', $probe['retry_key']) !== 1) {
                throw new \LogicException('probe-schema');
            }
        }
    }

    private function issueLoginClientProof(EnsureTenantLoginClientProof $clientProof, string $host): string
    {
        Cookie::flushQueuedCookies();
        try {
            $request = Request::create(
                'https://'.$host.'/sanctum/csrf-cookie',
                'GET', [], [], [], ['HTTP_HOST' => $host, 'HTTPS' => 'on'],
            );
            $response = $clientProof->handle($request, static fn (): Response => new Response('', 204));
            if ($response->getStatusCode() !== 204) {
                throw new \LogicException('client-proof-bootstrap');
            }
            $cookie = collect(Cookie::getQueuedCookies())->first(
                static fn (HttpCookie $candidate): bool => $candidate->getName() === 'daleel_login_client',
            );
            if (! $cookie instanceof HttpCookie || $cookie->getValue() === '') {
                throw new \LogicException('client-proof-missing');
            }

            return $cookie->getValue();
        } finally {
            Cookie::flushQueuedCookies();
        }
    }
}
