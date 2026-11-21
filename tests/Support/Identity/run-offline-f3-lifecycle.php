<?php
declare(strict_types=1);

use App\Modules\Identity\Application\TenantAuthorityAuthenticator;
use App\Modules\Identity\Application\TenantAuthorityBridge;
use App\Modules\Identity\Application\{RestrictedTenantProbePlan,RestrictedTenantProbeScope,RestrictedTenantProbeTransport,TenantRestrictedProbeCoordinator};
use App\Modules\Identity\Domain\TenantHostContext;
use App\Modules\Identity\Domain\TenantStaffContext;
use App\Modules\Identity\Infrastructure\Persistence\TenantStaffUser;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Tests\Support\Identity\OfflineF3LifecycleOrchestrator;
use Tests\Support\Identity\StatefulAuthorityAffinityTransport;
use Tests\Support\Identity\StatefulTenantProbeOrchestrator;

require dirname(__DIR__, 3) . '/vendor/autoload.php';

/** Test-only stdin/stdout adapter. It has no route, database, or production DI binding. */
function fail(string $code): never { fwrite(STDERR, $code . PHP_EOL); exit(2); }
$raw = stream_get_contents(STDIN);
try { $input = json_decode($raw, true, 512, JSON_THROW_ON_ERROR); } catch (Throwable) { fail('OFFLINE_F3_INPUT_INVALID_JSON'); }
if (!is_array($input) || array_diff(array_keys($input), ['version','environment','probes']) || ($input['version'] ?? null) !== '008-offline-v1' || !is_array($input['environment'] ?? null) || !is_array($input['probes'] ?? null)) { fail('OFFLINE_F3_INPUT_SCHEMA_REJECTED'); }
$generation = '019c4a5b-5010-7f00-8a00-50e6e64c335d';
$authenticator = new class($generation) implements TenantAuthorityAuthenticator {
    public function __construct(private readonly string $generation) {}
    public function authenticate(TenantHostContext $host, string $email, string $password, string $retryKey, Request $request): TenantStaffUser {
        $request->session()->migrate(true);
        $request->attributes->set('tenant_staff_context', new TenantStaffContext($host->tenantId, $host->hostname, '019c4a5b-5010-7f00-8a00-50e6e64c335b', '019c4a5b-5010-7f00-8a00-50e6e64c335c', 1, 1));
        $request->session()->put('identity.tenant_staff', ['authority_generation' => $this->generation]);
        return new TenantStaffUser;
    }
};
$request = Request::create('/', 'POST'); $session = new Store('offline-f3-cli', new ArraySessionHandler(60)); $session->start(); $request->setLaravelSession($session);
$transport = new StatefulAuthorityAffinityTransport;
$lifecycle = new OfflineF3LifecycleOrchestrator(new TenantAuthorityBridge($authenticator), new StatefulTenantProbeOrchestrator($transport, 'offline-f3-run'), $transport);
try {
    $coordinator = new TenantRestrictedProbeCoordinator(new TenantAuthorityBridge($authenticator), new class implements RestrictedTenantProbeTransport { public function beginBound(TenantStaffContext $context, string $generation, RestrictedTenantProbePlan $plan): RestrictedTenantProbeScope { return new class implements RestrictedTenantProbeScope { public function execute(): array { return ['outcome'=>'ALLOWED','row_effects'=>0]; } public function close(): void {} }; } });
    $probe = $input['probes'][0] ?? null;
    if (!is_array($probe)) { fail('OFFLINE_F3_INPUT_PROBE_MISSING'); }
    $coordinatorRequest = Request::create('/', 'POST'); $coordinatorSession = new Store('offline-f3-coordinator', new ArraySessionHandler(60)); $coordinatorSession->start(); $coordinatorRequest->setLaravelSession($coordinatorSession);
    $coordinator->authenticateAndExecute(new TenantHostContext('019c4a5b-5010-7f00-8a00-50e6e64c335a', 'a', 'a.test', 'test', 'LOCAL_TEST'), 'offline@example.test', 'not-a-secret', 'offline-retry', $coordinatorRequest, new RestrictedTenantProbePlan('offline-f3-run', (string)($probe['case_id'] ?? ''), '019c4a5b-5010-7f00-8a00-50e6e64c335a', (string)($probe['operation'] ?? ''), (string)($probe['connection'] ?? ''), (string)($probe['transaction'] ?? '')));
    $result = $lifecycle->run($input['environment'], new TenantHostContext('019c4a5b-5010-7f00-8a00-50e6e64c335a', 'a', 'a.test', 'test', 'LOCAL_TEST'), $request, $input['probes']);
    echo json_encode(['version' => '008-offline-v1', 'classification' => $result['classification'], 'f3_classification' => $result['f3_classification'], 'terminal' => $result['terminal'], 'record_count' => count($result['records']), 'transport_clean' => $transport->state() === ['transaction'=>null,'bound'=>null]], JSON_THROW_ON_ERROR) . PHP_EOL;
} catch (Throwable $e) { fwrite(STDERR, 'OFFLINE_F3_REJECTED:' . $e->getMessage() . PHP_EOL); exit(3); }
