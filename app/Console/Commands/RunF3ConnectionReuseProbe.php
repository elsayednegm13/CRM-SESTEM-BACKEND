<?php

declare(strict_types=1);

namespace App\Console\Commands;

use App\Modules\Identity\Application\LaravelRestrictedTenantRuntimeAdapter;
use App\Modules\Identity\Application\RestrictedTenantProbePlan;
use App\Modules\Identity\Application\TenantAcceptanceRequestBinder;
use App\Modules\Identity\Application\TenantHostResolver;
use App\Modules\Identity\Application\TenantRestrictedProbeCoordinator;
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

/** Acceptance-only A-to-B physical-connection reuse proof; stdin only, no route. */
final class RunF3ConnectionReuseProbe extends Command
{
    protected $signature = 'dcrm:f3-connection-reuse-probe';
    protected $description = 'Prove A-to-B context replacement on one tenant runtime connection';

    public function handle(
        TenantHostResolver $hosts,
        EmailAddressNormalizer $emails,
        EnsureTenantLoginClientProof $clientProof,
        LaravelRestrictedTenantRuntimeAdapter $adapter,
        TenantAcceptanceRequestBinder $requests,
    ): int {
        if (config('f3_acceptance.enabled') !== true
            || ! in_array(app()->environment(), (array) config('f3_acceptance.allowed_environments'), true)) {
            $this->error('F3_REUSE_PROBE_DISABLED');
            return self::FAILURE;
        }
        try {
            $input = json_decode(stream_get_contents(STDIN), true, 32, JSON_THROW_ON_ERROR);
            $this->assertInput($input);
            if (! hash_equals((string) config('f3_acceptance.run_id'), $input['run_id'])) {
                throw new \LogicException('run-id');
            }
            $records = [];
            foreach (['A', 'B'] as $side) {
                $actor = $input['actors'][$side];
                $host = $hosts->resolve($actor['host']);
                if (! hash_equals($actor['tenant_id'], $host->tenantId)) {
                    throw new \LogicException('tenant-host-mismatch');
                }
                foreach ([
                    ["{$side}_REUSE_READ_OWN", $actor['tenant_id'], $actor['own_lead_id'], 'ALLOWED', 1],
                    ["{$side}_REUSE_READ_CROSS", $actor['cross_tenant_id'], $actor['cross_lead_id'], 'DENIED_ZERO_ROWS', 0],
                ] as $index => $case) {
                    $request = $this->request($input['run_id'], $actor['host'], $clientProof);
                    $plan = new RestrictedTenantProbePlan(
                        $input['run_id'], $case[0], $host->tenantId, 'read', 'laravel-runtime-reuse',
                        'same-physical-connection', $case[1], $case[2], $case[3], $case[4],
                    );
                    $retryKey = $actor[$index === 0 ? 'retry_key_own' : 'retry_key_cross'];
                    $record = null;
                    $requests->run($request, function () use (&$record, $clientProof, $adapter, $host, $actor, $request, $plan, $emails, $retryKey): void {
                        $clientProof->handle($request, function () use (&$record, $adapter, $host, $actor, $request, $plan, $emails, $retryKey): Response {
                            $record = TenantRestrictedProbeCoordinator::forRuntimeAdapter($adapter)->authenticateAndExecuteRuntime(
                                $host, $emails->normalize($actor['email']), $actor['password'], $retryKey, $request, $plan,
                            );
                            return response()->noContent();
                        });
                    });
                    if (! is_array($record) || ($record['cleanup_status'] ?? null) !== 'COMPLETE'
                        || ($record['revoked_session_denied'] ?? null) !== true) {
                        throw new \LogicException('reuse-record-incomplete');
                    }
                    $records[] = $record;
                }
            }
            $pids = array_values(array_unique(array_map(static fn (array $record): int => (int) $record['runtime_backend_pid'], $records)));
            $sessions = array_values(array_unique(array_map(static fn (array $record): string => (string) $record['observer_session_fingerprint'], $records)));
            if (count($pids) !== 1 || $pids[0] < 1 || count($sessions) !== count($records)) {
                throw new \LogicException('reuse-provenance-invalid');
            }
            $this->line(json_encode([
                'version' => 'DCRM-008-F3-REUSE-V1', 'run_id' => $input['run_id'],
                'classification' => 'F3_CONNECTION_REUSE_A_TO_B_DENIED', 'backend_pid' => $pids[0],
                'record_count' => count($records), 'records' => $records,
            ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
            return self::SUCCESS;
        } catch (Throwable $exception) {
            $this->error('F3_REUSE_PROBE_REJECTED:'.$exception::class);
            return self::FAILURE;
        }
    }

    private function assertInput(mixed $input): void
    {
        if (! is_array($input) || array_keys($input) !== ['version','run_id','actors']
            || $input['version'] !== 'DCRM-008-F3-REUSE-V1'
            || ! is_string($input['run_id']) || preg_match('/^[a-z0-9-]{8,64}$/D', $input['run_id']) !== 1
            || ! is_array($input['actors']) || array_keys($input['actors']) !== ['A','B']) {
            throw new \LogicException('schema');
        }
        foreach ($input['actors'] as $actor) {
            if (! is_array($actor) || array_keys($actor) !== ['host','email','password','retry_key_own','retry_key_cross','tenant_id','own_lead_id','cross_tenant_id','cross_lead_id']) {
                throw new \LogicException('actor-schema');
            }
            foreach (['host','email','password','retry_key_own','retry_key_cross','tenant_id','own_lead_id','cross_tenant_id','cross_lead_id'] as $key) {
                if (! is_string($actor[$key]) || $actor[$key] === '' || strlen($actor[$key]) > 1024) {
                    throw new \LogicException('actor-value');
                }
            }
        }
    }

    private function request(string $runId, string $host, EnsureTenantLoginClientProof $clientProof): Request
    {
        Cookie::flushQueuedCookies();
        try {
            $bootstrap = Request::create('https://'.$host.'/sanctum/csrf-cookie', 'GET', [], [], [], ['HTTP_HOST' => $host, 'HTTPS' => 'on']);
            $response = $clientProof->handle($bootstrap, static fn (): Response => new Response('', 204));
            $cookie = collect(Cookie::getQueuedCookies())->first(static fn (HttpCookie $candidate): bool => $candidate->getName() === 'daleel_login_client');
            if ($response->getStatusCode() !== 204 || ! $cookie instanceof HttpCookie || $cookie->getValue() === '') {
                throw new \LogicException('client-proof');
            }
            $request = Request::create('https://'.$host.'/api/v1/auth/login', 'POST', [], ['daleel_login_client' => $cookie->getValue()], [], ['HTTP_HOST' => $host, 'HTTPS' => 'on']);
            $session = new Store('dcrm-f3-reuse-'.$runId, new ArraySessionHandler(900));
            $session->start();
            $request->setLaravelSession($session);
            return $request;
        } finally {
            Cookie::flushQueuedCookies();
        }
    }
}
