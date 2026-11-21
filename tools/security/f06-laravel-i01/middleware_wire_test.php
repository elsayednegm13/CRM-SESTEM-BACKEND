<?php

/**
 * SECURITY-F06-LARAVEL-IMPLEMENT-01 : middleware-level real-Laravel wire test.
 *
 * Boots the actual Laravel application (same vendor/, same classes under test),
 * points pgsql_tenant_runtime and pgsql_f06_bootstrap ONLY at the new isolated
 * sandbox container (127.0.0.1:55450), forces SESSION_DRIVER/CACHE_STORE/QUEUE
 * to array/sync so nothing else is touched on boot, and drives
 * TenantStaffRequestContext::handle() directly with a real Request + real Closure
 * $next, exactly as the route pipeline would call it for GET /api/v1/company/leads.
 *
 * This is NOT a HTTP-socket test (no artisan serve / cookie jar); it is a direct,
 * in-process invocation of the real middleware/guard/factory/resolver classes
 * against a real PostgreSQL connection. REAL_LARAVEL_HTTP_WIRE is reported as
 * PARTIAL on this basis -- see the Arabic report for the explicit scope note.
 */

$secrets = getenv('F06_SECRETS_DIR');
if (! is_string($secrets) || $secrets === '') {
    fwrite(STDERR, "F06_SECRETS_DIR not set\n");
    exit(2);
}
$readSecret = static fn (string $name): string => trim((string) file_get_contents($secrets.'/'.$name));

putenv('APP_ENV=testing');
putenv('APP_KEY=base64:9VOcF8isaS3rkETFWjWCVCMVbh0tQKGb1cYfn9sEYsA=');
putenv('APP_DEBUG=false');
putenv('SESSION_DRIVER=array');
putenv('CACHE_STORE=array');
putenv('QUEUE_CONNECTION=sync');
putenv('DB_CONNECTION=pgsql');
putenv('DB_HOST=127.0.0.1');
putenv('DB_PORT=1'); // deliberately unreachable: proves the default connection is never touched
putenv('DB_DATABASE=unused_default_connection_must_not_be_queried');

putenv('TENANT_RUNTIME_DB_HOST=127.0.0.1');
putenv('TENANT_RUNTIME_DB_PORT=55450');
putenv('TENANT_RUNTIME_DB_DATABASE=f06i01');
putenv('TENANT_RUNTIME_DB_USERNAME=daleel_f06i01_actor_a1'); // placeholder; factory overrides per actor
putenv('TENANT_RUNTIME_DB_PASSWORD='.$readSecret('.a1'));
putenv('TENANT_RUNTIME_DB_SSLMODE=disable');

putenv('F06_BOOTSTRAP_DB_HOST=127.0.0.1');
putenv('F06_BOOTSTRAP_DB_PORT=55450');
putenv('F06_BOOTSTRAP_DB_DATABASE=f06i01');
putenv('F06_BOOTSTRAP_DB_USERNAME=daleel_f06i01_bootstrap_client');
putenv('F06_BOOTSTRAP_DB_PASSWORD='.$readSecret('.bc'));
putenv('F06_BOOTSTRAP_DB_SSLMODE=disable');

putenv('F06_ACTOR_SQL_INTEGRATION_ENABLED=true');
putenv('F06_ACTOR_SQL_ALLOWED_APP_ENV=testing');
putenv('F06_ACTOR_PW_A1='.$readSecret('.a1'));
putenv('F06_ACTOR_PW_A2='.$readSecret('.a2'));
putenv('F06_ACTOR_PW_B1='.$readSecret('.b1'));

require __DIR__.'/../../../vendor/autoload.php';
/** @var \Illuminate\Foundation\Application $app */
$app = require __DIR__.'/../../../bootstrap/app.php';
$kernel = $app->make(Illuminate\Contracts\Console\Kernel::class);
$kernel->bootstrap();

use App\Modules\Identity\Domain\TenantHostContext;
use App\Modules\Identity\Http\Middleware\TenantStaffRequestContext;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\DB;
use Symfony\Component\HttpFoundation\Response;

$TENANT_A = '11111111-1111-1111-1111-111111111111';
$TENANT_B = '22222222-2222-2222-2222-222222222222';
$HOST_A = 'tenant-a.sandbox.local';
$HOST_B = 'tenant-b.sandbox.local';

$host = static fn (string $tenantId, string $hostname) => new TenantHostContext($tenantId, 'sandbox', $hostname, 'sandbox.local', 'sandbox');

function makeRequest(string $hostname): Request
{
    $request = Request::create('http://'.$hostname.'/api/v1/company/leads', 'GET');
    $session = new Store('f06i01_test_session', new ArraySessionHandler(120));
    $session->start();
    $request->setLaravelSession($session);

    return $request;
}

function setSessionTuple(Request $request, string $tenantId, string $hostname, string $userId, string $membershipId, int $authVersion, int $authorizationVersion): void
{
    $request->session()->put('identity.tenant_staff', [
        'tenant_id' => $tenantId,
        'hostname' => $hostname,
        'user_id' => $userId,
        'membership_id' => $membershipId,
        'auth_version' => $authVersion,
        'authorization_version' => $authorizationVersion,
    ]);
}

$results = [];
$record = static function (string $id, bool $pass, string $detail) use (&$results) {
    $results[] = [$id, $pass ? 'PASS' : 'FAIL', $detail];
    fwrite(STDOUT, sprintf("%-28s %-5s %s\n", $id, $pass ? 'PASS' : 'FAIL', $detail));
};

$middleware = $app->make(TenantStaffRequestContext::class);

$runLeadsAsSessionUser = static function (Request $request, TenantHostContext $hostContext) use ($middleware) {
    $request->attributes->set('tenant_host_context', $hostContext);
    $capturedSessionUser = null;
    $response = $middleware->handle($request, function (Request $req) use (&$capturedSessionUser) {
        $capturedSessionUser = DB::connection('pgsql_tenant_runtime')->selectOne('SELECT session_user AS value')->value ?? null;
        $leads = DB::connection('pgsql_tenant_runtime')->select('SELECT id, tenant_id, name FROM public.f06i01_leads ORDER BY id');

        return new Response(json_encode(['data' => $leads, 'meta' => ['session_user' => $capturedSessionUser]]), 200);
    });

    return [$response, $capturedSessionUser];
};

// GATE-03 / GATE-06 step 1: A1 request.
$reqA1 = makeRequest($HOST_A);
setSessionTuple($reqA1, $TENANT_A, $HOST_A, 'aaaaaaa1-0000-0000-0000-000000000001', 'a1111111-0000-0000-0000-00000000a001', 1, 1);
[$respA1, $suA1] = $runLeadsAsSessionUser($reqA1, $host($TENANT_A, $HOST_A));
$bodyA1 = json_decode($respA1->getContent(), true);
$record('GATE-03-GET-A1', $respA1->getStatusCode() === 200 && $suA1 === 'daleel_f06i01_actor_a1' && count($bodyA1['data']) === 2,
    'status='.$respA1->getStatusCode().' session_user='.$suA1.' rows='.count($bodyA1['data'] ?? []));

// GATE-06: immediately after, same PHP process, B1 request -- must not inherit A1's connection/credential.
$reqB1 = makeRequest($HOST_B);
setSessionTuple($reqB1, $TENANT_B, $HOST_B, 'bbbbbbb1-0000-0000-0000-000000000001', 'b1111111-0000-0000-0000-00000000b001', 1, 1);
[$respB1, $suB1] = $runLeadsAsSessionUser($reqB1, $host($TENANT_B, $HOST_B));
$bodyB1 = json_decode($respB1->getContent(), true);
$record('GATE-06-LIFECYCLE-B1-AFTER-A1', $respB1->getStatusCode() === 200 && $suB1 === 'daleel_f06i01_actor_b1' && count($bodyB1['data']) === 1
    && $bodyB1['data'][0]['tenant_id'] === $TENANT_B,
    'status='.$respB1->getStatusCode().' session_user='.$suB1.' rows='.count($bodyB1['data'] ?? []));

// GATE-04 (app layer): B1 cannot see tenant A leads via the HTTP path either.
$record('GATE-04-APP-NO-CROSS-TENANT-LEAK', ! in_array($TENANT_A, array_column($bodyB1['data'] ?? [], 'tenant_id'), true),
    'tenant_ids_seen='.json_encode(array_column($bodyB1['data'] ?? [], 'tenant_id')));

// GATE-06 / NC-02: suspended + unmapped A3 must be denied before any data SQL, no fallback.
$reqA3 = makeRequest($HOST_A);
setSessionTuple($reqA3, $TENANT_A, $HOST_A, 'aaaaaaa3-0000-0000-0000-000000000003', 'a1111111-0000-0000-0000-00000000a003', 1, 1);
$deniedA3 = false;
$exceptionClassA3 = null;
try {
    $runLeadsAsSessionUser($reqA3, $host($TENANT_A, $HOST_A));
} catch (\Throwable $e) {
    $deniedA3 = true;
    $exceptionClassA3 = get_class($e);
}
$record('GATE-06-DENY-SUSPENDED-A3', $deniedA3, 'exception='.$exceptionClassA3);

// NC-05: session tuple claims tenant A but Host header resolves tenant B -> must deny.
$reqMismatch = makeRequest($HOST_B);
setSessionTuple($reqMismatch, $TENANT_A, $HOST_A, 'aaaaaaa1-0000-0000-0000-000000000001', 'a1111111-0000-0000-0000-00000000a001', 1, 1);
$deniedMismatch = false;
try {
    $runLeadsAsSessionUser($reqMismatch, $host($TENANT_B, $HOST_B));
} catch (\Throwable $e) {
    $deniedMismatch = true;
}
$record('NC-05-HOST-TENANT-MISMATCH', $deniedMismatch, 'denied='.($deniedMismatch ? 'yes' : 'no'));

// GATE-01: feature flag OFF -> legacy path, must not touch ActorConnectionFactory at all,
// and must not require the F06 bootstrap connection to be configured correctly.
putenv('F06_ACTOR_SQL_INTEGRATION_ENABLED=false');
$app->make('config')->set('f06_actor_sql.enabled', false);
$legacyMiddleware = $app->make(TenantStaffRequestContext::class);
$reqLegacy = makeRequest($HOST_A);
setSessionTuple($reqLegacy, $TENANT_A, $HOST_A, 'aaaaaaa1-0000-0000-0000-000000000001', 'a1111111-0000-0000-0000-00000000a001', 1, 1);
$reqLegacy->attributes->set('tenant_host_context', $host($TENANT_A, $HOST_A));
$legacyThrew = null;
try {
    // Legacy path will try pgsql_tenant_runtime with the ambient (actor_a1) credential
    // configured above and attempt its own SQL revalidation against public.tenants /
    // tenant_staff_users / tenant_staff_memberships, which do not exist under those
    // exact (real-product) names in this sandbox -- so this call is EXPECTED to throw
    // on a missing-relation error, not on an auth/flag error. That distinction is the
    // actual assertion: the flag truly gated which code path ran.
    $legacyMiddleware->handle($reqLegacy, fn ($r) => new Response('unreachable', 200));
} catch (\Throwable $e) {
    $legacyThrew = $e;
}
$record('GATE-01-FLAG-OFF-TAKES-LEGACY-PATH', $legacyThrew !== null && ! str_contains($legacyThrew->getMessage(), 'F06')
    && ! ($legacyThrew instanceof RuntimeException && str_contains($legacyThrew->getMessage(), 'bootstrap')),
    'exception='.($legacyThrew ? get_class($legacyThrew).': '.$legacyThrew->getMessage() : 'none'));

$failures = array_filter($results, static fn ($r) => $r[1] === 'FAIL');
fwrite(STDOUT, "\nTOTAL=".count($results).' PASS='.(count($results) - count($failures)).' FAIL='.count($failures)."\n");
exit(count($failures) > 0 ? 1 : 0);
