<?php

declare(strict_types=1);

use App\Console\Commands\BootstrapProviderRoot;
use App\Modules\Identity\Domain\EmailAddressNormalizer;
use App\Modules\Provider\Application\ProviderBootstrapService;
use App\Modules\Provider\Domain\ProviderAccessException;
use App\Modules\Provider\Domain\ProviderBootstrapPolicy;
use App\Modules\Provider\Http\Controllers\ProviderBootstrapController;
use App\Modules\Provider\Http\Middleware\ForceProviderBootstrapCsrf;
use App\Modules\Provider\Http\Middleware\RequireProviderBootstrapRequest;
use App\Modules\Provider\Http\Middleware\RequireProviderOrigin;
use App\Modules\Provider\Infrastructure\Persistence\ProviderDatabaseContext;
use App\Modules\Shared\Audit\SecurityAuditWriter;
use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\RateLimiter as CacheRateLimiter;
use Illuminate\Cache\Repository as CacheRepository;
use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Encryption\Encrypter;
use Illuminate\Hashing\BcryptHasher;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Session\TokenMismatchException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Facade;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\RateLimiter;
use Symfony\Component\Console\Output\BufferedOutput;
use Illuminate\Console\OutputStyle;
use Symfony\Component\HttpFoundation\Response;
use Tests\Support\P1Bootstrap\FakeProviderDatabase;

require_once __DIR__.'/../../../vendor/autoload.php';
require_once __DIR__.'/FakeProviderDatabase.php';

// A container, not a Laravel Application. No bootstrap/app.php, .env, live config,
// PHPUnit configuration, PDO, external cache, HTTP client or network is loaded.
$app = new class extends Container {
    public function environment(...$names): bool { return in_array('local', $names, true); }
    public function abort(int $code, string $message = '', array $headers = []): never
    {
        throw new Symfony\Component\HttpKernel\Exception\HttpException($code, $message, null, $headers);
    }
};
Container::setInstance($app);
Facade::setFacadeApplication($app);
$app->instance('config', new Repository);
Hash::swap(new BcryptHasher(['rounds' => 4]));
$policy = new ProviderBootstrapPolicy;
$emails = new EmailAddressNormalizer;
$requestId = '00000000-0000-4000-8000-000000000001';
$checks = 0;
$cases = 0;

function check(bool $condition, string $label): void
{
    global $checks;
    $checks++;
    if (! $condition) {
        throw new RuntimeException('Assertion failed: '.$label);
    }
}
function rejects(callable $operation, int $status, string $label): ProviderAccessException
{
    try { $operation(); } catch (ProviderAccessException $e) {
        check($e->status === $status, $label.' status');
        check($e->getPrevious() === null, $label.' no sensitive previous exception');
        return $e;
    }
    throw new RuntimeException('Expected safe rejection: '.$label);
}
function runCase(string $id, callable $test): void
{
    global $cases;
    $test();
    $cases++;
    echo $id." PASS_OFFLINE\n";
}
function settings(): array
{
    // Public synthetic test values only; never deployment material.
    return ['enabled' => true, 'secret' => str_repeat('a', 64), 'expires_at' => time() + 600, 'allow_loopback_http' => false];
}
function input(): array
{
    $password = 'Offline'.str_repeat('x', 8).'A1!';
    return ['bootstrap_secret' => settings()['secret'], 'email' => ' OWNER@EXAMPLE.INVALID ',
        'password' => $password, 'password_confirmation' => $password];
}
function fixture(): array
{
    global $policy, $emails;
    config(['provider.bootstrap' => settings()]);
    RateLimiter::swap(new CacheRateLimiter(new CacheRepository(new ArrayStore)));
    $db = new FakeProviderDatabase;
    DB::swap($db);
    return [$db, new ProviderBootstrapService($policy, $emails, new ProviderDatabaseContext, new SecurityAuditWriter)];
}
function jsonRequest(string $body, string $path = '/api/v1/super/setup'): Request
{
    global $requestId;
    $request = Request::create('https://api.example.invalid'.$path, 'POST', [], [], [],
        ['CONTENT_TYPE' => 'application/json', 'HTTP_ORIGIN' => 'https://super.example.invalid'], $body);
    $request->attributes->set('request_id', $requestId);
    return $request;
}

runCase('C01', function () use ($requestId) {
    [$db, $service] = fixture();
    check($service->status() === ['state' => 'AVAILABLE'], 'available status');
    $response = (new ProviderBootstrapController)->store(jsonRequest(json_encode(input())), $service);
    $payload = $response->getData(true);
    check($response->getStatusCode() === 201, 'created response status');
    check($payload === ['data' => ['status' => 'created', 'next' => 'LOGIN_AVAILABLE'],
        'meta' => ['request_id' => $requestId]], 'exact creation response');
    check($response->headers->get('Cache-Control') === 'no-store, private', 'private no-store');
    $user = $db->rows['provider_users'][0];
    check(count($db->rows['provider_users']) === 1 && $user['email'] === 'owner@example.invalid', 'normalized one user');
    check(Hash::check(input()['password'], $user['password']), 'actual Laravel hashing');
    check($user['status'] === 'ACTIVE' && $user['email_verified_at'] !== null && $user['mfa_enrolled_at'] === null
        && $user['auth_version'] === 1 && $user['authorization_version'] === 1, 'initial identity shape');
    check(count($db->rows['provider_user_capabilities']) === 2, 'all and only active grants');
    $audit = $db->rows['security_audit_events'][0];
    check(count($db->rows['security_audit_events']) === 1 && $audit['event_type'] === 'provider.team.member_created'
        && $audit['actor_id'] === $user['id'] && $audit['target_id'] === $user['id']
        && $audit['request_id'] === $requestId && $audit['metadata'] === '{}', 'actual existing audit writer');
    check($db->rows['provider_installation_setup'][0]['sealed'] === true
        && $db->rows['provider_installation_setup'][0]['completed_at'] === $user['created_at'], 'durable seal operation');
    check(array_search('provider_installation_setup.lock', $db->events, true)
        < array_search('provider_users.insert', $db->events, true), 'lock before mutation');
    check(array_search('provider_installation_setup.update', $db->events, true)
        < array_search('provider_users.insert', $db->events, true), 'seal before first account insert');
    check(array_search('provider_users.insert', $db->events, true)
        < array_search('security_audit_events.insert', $db->events, true), 'account before same-transaction audit');
    check(! in_array('population-trigger.seal', $db->events, true)
        && count(array_keys($db->events, 'population-trigger.no-op', true)) === 2, 'account and audit population hooks no-op after pre-seal');
});

runCase('C02', function () use ($policy, $requestId) {
    foreach ([null, '', 'wrong', str_repeat('b', 64), [], 123] as $proof) {
        [$db, $service] = fixture();
        rejects(fn () => $service->create(array_replace(input(), ['bootstrap_secret' => $proof]), $requestId), 403, 'invalid proof');
        check($db->connections === 0, 'invalid proof before data access');
    }
    foreach ([['enabled' => false], ['secret' => ''], ['secret' => str_repeat('g', 64)], ['expires_at' => ''],
        ['expires_at' => time()], ['expires_at' => time() - 1], ['expires_at' => time() + 3602],
        ['expires_at' => true], ['expires_at' => '1e10'], ['expires_at' => []], ['enabled' => 'true']] as $delta) {
        [$db, $service] = fixture();
        config(['provider.bootstrap' => array_replace(settings(), $delta)]);
        rejects(fn () => $service->status(), 403, 'disabled configuration status');
        rejects(fn () => $service->create(input(), $requestId), 403, 'disabled configuration mutation');
        check($db->connections === 0, 'configuration before data access');
    }
    $policy->assertConfigured(array_replace(settings(), ['expires_at' => 4600]), 1000);
    rejects(fn () => $policy->assertConfigured(array_replace(settings(), ['expires_at' => 4601]), 1000), 403, 'one hour boundary');
});

runCase('C03', function () use ($policy, $emails, $requestId) {
    foreach ([['email' => ''], ['email' => 'invalid'], ['email' => []], ['password' => 'short'],
        ['password' => str_repeat('x', 14)], ['password' => str_repeat('X', 14)],
        ['password' => 'NoNumbersHere!!'], ['password' => 'NoSymbolsHere123'], ['password' => "HasNoSymbolA123\x01"],
        ['password' => str_repeat('x', 70).'A1!'], ['password' => "BadUtf8\xffWithA1!"],
        ['password' => "NoNull\0PasswordA1!"], ['password_confirmation' => 'mismatch'], ['role' => 'root'],
        ['tenant_id' => 'untrusted'], ['password' => []]] as $delta) {
        [$db, $service] = fixture();
        if (isset($delta['password']) && is_string($delta['password'])) {
            $delta['password_confirmation'] = $delta['password'];
        }
        rejects(fn () => $service->create(array_replace(input(), $delta), $requestId), 422, 'invalid identity');
        check($db->connections === 0, 'input validation before data access');
    }
    foreach ([14, 72] as $bytes) {
        $password = str_repeat('x', $bytes - 3).'A1!';
        check($policy->identity(array_replace(input(), ['password' => $password, 'password_confirmation' => $password]), $emails)['password'] === $password,
            'password byte boundary');
    }
    $password = str_repeat('é', 35).'A1!';
    rejects(fn () => $policy->identity(array_replace(input(), ['password' => $password, 'password_confirmation' => $password]), $emails), 422, 'multibyte byte limit');
});

runCase('C04', function () use ($requestId) {
    [$db, $service] = fixture();
    $db->rows['provider_users'][] = ['id' => 'synthetic-existing-provider', 'status' => 'DISABLED'];
    $before = $db->rows;
    rejects(fn () => $service->create(input(), $requestId), 409, 'any existing provider');
    rejects(fn () => $service->status(), 409, 'existing provider status');
    check($db->rows === $before, 'no reset or replacement');
});

runCase('C05', function () use ($requestId) {
    foreach (['sealed', 'missing-row', 'missing-table', 'inconsistent', 'unknown-boolean'] as $mode) {
        [$db, $service] = fixture();
        match ($mode) {
            'sealed' => $db->rows['provider_installation_setup'][0]['sealed'] = true,
            'missing-row' => $db->rows['provider_installation_setup'] = [],
            'missing-table' => $db->missingMarkerTable = true,
            'inconsistent' => $db->rows['provider_installation_setup'][0]['completed_at'] = 'synthetic-completed',
            'unknown-boolean' => $db->rows['provider_installation_setup'][0]['sealed'] = 'unknown',
        };
        $before = $db->rows;
        config(['provider.bootstrap.secret' => str_repeat('b', 64)]);
        rejects(fn () => $service->create(array_replace(input(), ['bootstrap_secret' => str_repeat('b', 64)]), $requestId), 409, $mode);
        rejects(fn () => $service->status(), 409, $mode.' status');
        check($db->rows === $before, 'marker no resurrection');
    }
});

runCase('C06', function () use ($requestId) {
    [$db, $service] = fixture();
    // Both callers observed AVAILABLE. Simulate serialized execution, not real locks.
    check($service->status() === $service->status(), 'both advisory checks available');
    $service->create(input(), $requestId);
    rejects(fn () => $service->create(input(), $requestId), 409, 'serialized second contender');
    check(count($db->rows['provider_users']) === 1, 'one serialized winner');
    foreach (['audit', 'insert', 'seal', 'capability', 'driver', 'expiry-while-waiting'] as $failure) {
        [$db, $service] = fixture();
        match ($failure) {
            'audit' => $db->failAudit = true,
            'insert' => $db->failInsert = true,
            'seal' => $db->failSeal = true,
            'capability' => $db->rows['provider_capabilities'] = [],
            'driver' => $db->driver = 'sqlite',
            'expiry-while-waiting' => $db->beforeTransaction = fn () => config(['provider.bootstrap.expires_at' => time() - 1]),
        };
        $before = $db->rows;
        rejects(fn () => $service->create(input(), $requestId), $failure === 'expiry-while-waiting' ? 403 : 409, 'transaction failure '.$failure);
        check($db->rows === $before, 'all-or-nothing simulation '.$failure);
        if (in_array($failure, ['audit', 'insert'], true)) {
            check(in_array('provider_installation_setup.update', $db->events, true)
                && in_array('transaction.rollback', $db->events, true), 'early seal rolled back on '.$failure);
        }
    }
});

runCase('C07', function () use ($requestId) {
    [$db, $service] = fixture();
    $service->create(input(), $requestId);
    $before = $db->rows;
    rejects(fn () => $service->create(input(), $requestId), 409, 'replay');
    check($db->rows === $before, 'replay no mutation');
});

runCase('C08', function () use ($policy, $requestId) {
    $frameworkApp = Mockery::mock(Application::class);
    $encrypter = new Encrypter(str_repeat('x', 32), 'AES-256-CBC');
    $csrf = new ForceProviderBootstrapCsrf($frameworkApp, $encrypter);
    $next = fn () => new Response('safe');
    $request = jsonRequest('{}');
    try { $csrf->handle($request, $next); throw new RuntimeException('Missing session accepted.'); }
    catch (TokenMismatchException) { check(true, 'missing session rejected'); }
    $session = new Store('p1-offline', new ArraySessionHandler(120));
    $session->start();
    $request->setLaravelSession($session);
    $request->headers->set('Sec-Fetch-Site', 'same-origin');
    ForceProviderBootstrapCsrf::except(['api/v1/super/setup']);
    foreach ([null, 'wrong'] as $token) {
        $request->headers->set('X-CSRF-TOKEN', $token);
        try { $csrf->handle($request, $next); throw new RuntimeException('Bad CSRF accepted.'); }
        catch (TokenMismatchException) { check(true, 'no fetch-site bypass'); }
    }
    $request->headers->set('X-CSRF-TOKEN', $session->token());
    check($csrf->handle($request, $next)->getStatusCode() === 200, 'real token verifier');
    $request->headers->remove('X-CSRF-TOKEN');
    $request->headers->set('X-XSRF-TOKEN', $encrypter->encrypt(
        Illuminate\Cookie\CookieValuePrefix::create('XSRF-TOKEN', str_repeat('x', 32)).$session->token(), false));
    check($csrf->handle($request, $next)->getStatusCode() === 200, 'encrypted bridge XSRF header verifier');
    config(['provider.api_hosts' => ['api.example.invalid'], 'provider.allowed_origins' => ['https://super.example.invalid'],
        'cors.allowed_origins' => ['https://super.example.invalid']]);
    $origin = new RequireProviderOrigin;
    check($origin->handle($request, $next)->getStatusCode() === 200, 'existing origin middleware accepts exact values');
    foreach (['host', 'origin'] as $bad) {
        $invalid = clone $request;
        if ($bad === 'host') { $invalid->server->set('HTTP_HOST', 'untrusted.invalid'); }
        else { $invalid->headers->set('Origin', 'https://untrusted.invalid'); }
        try { $origin->handle($invalid, $next); throw new RuntimeException('Untrusted boundary accepted.'); }
        catch (Symfony\Component\HttpKernel\Exception\HttpException $e) { check($e->getStatusCode() === 403, 'existing '.$bad.' denied'); }
    }
    $policy->assertTransport(true, 'api.example.invalid', 'https://super.example.invalid', false, false);
    $policy->assertTransport(false, 'api.localhost', 'http://super.localhost:13002', true, true);
    foreach ([[false, 'api.example.invalid', 'https://super.example.invalid', false, false],
        [true, 'api.example.invalid', 'http://super.example.invalid', false, false],
        [false, 'localhost', 'http://localhost:13002', true, false],
        [false, 'localhost', 'http://localhost:13002', false, true],
        [false, 'localhost', 'http://evil.invalid', true, true],
        [true, 'api.example.invalid', 'https://user@super.example.invalid', false, false],
        [true, 'api.example.invalid', 'https://super.example.invalid/path', false, false]] as $args) {
        rejects(fn () => $policy->assertTransport(...$args), 403, 'unsafe transport');
    }
    [$db, $service] = fixture();
    $middleware = new RequireProviderBootstrapRequest($policy);
    for ($i = 0; $i < 25; $i++) {
        check($middleware->handle(jsonRequest('{}'), $next)->getStatusCode() === 200, 'middleware has no global accounting');
        check($service->status() === ['state' => 'AVAILABLE'], 'advisory status remains available');
    }
    check(RateLimiter::attempts('provider:installation-setup:global') === 0, 'status does not spend creation quota');
    [$db, $service] = fixture();
    for ($i = 0; $i < 25; $i++) {
        rejects(fn () => $service->create(array_replace(input(), ['bootstrap_secret' => 'invalid']), $requestId), 403, 'invalid proof not globally counted');
    }
    check(RateLimiter::attempts('provider:installation-setup:global') === 0 && $db->connections === 0, 'invalid proof no quota or provider data access');
    for ($i = 0; $i < 20; $i++) {
        rejects(fn () => $service->create(array_replace(input(), ['password' => 'weak']), $requestId), 422, 'valid proof consumes quota before identity');
    }
    rejects(fn () => $service->create(input(), $requestId), 429, 'global twenty-first valid proof rejected');
    check($db->connections === 0, 'global limit before provider database access');
    check($service->status() === ['state' => 'AVAILABLE'], 'status unaffected by creation quota exhaustion');
    rejects(fn () => $service->create(array_replace(input(), ['bootstrap_secret' => 'invalid']), $requestId), 403, 'invalid proof remains 403 after quota exhaustion');
    Mockery::close();
});

runCase('C09', function () use ($requestId) {
    [$db, $service] = fixture();
    $response = (new ProviderBootstrapController)->store(jsonRequest(json_encode(input())), $service);
    foreach ([input()['bootstrap_secret'], input()['password'], 'owner@example.invalid', $db->rows['provider_users'][0]['id']] as $sensitive) {
        check(! str_contains($response->getContent(), $sensitive), 'no sensitive success response');
    }
    check(! str_contains(json_encode($db->rows['security_audit_events']), input()['password']), 'no password in audit');
    check(! str_contains(json_encode($db->rows['security_audit_events']), input()['bootstrap_secret']), 'no secret in audit');
    $exception = rejects(fn () => $service->create(array_replace(input(), ['password' => 'bad']), $requestId), 422, 'safe validation');
    check(! $exception instanceof Illuminate\Validation\ValidationException, 'no old-input validation exception');
    check((new ReflectionParameter([ProviderBootstrapService::class, 'create'], 'input'))->getAttributes(SensitiveParameter::class) !== [], 'sensitive service argument');
    $factory = Mockery::mock(Illuminate\Contracts\Routing\ResponseFactory::class);
    $factory->shouldReceive('json')->andReturnUsing(fn ($data, $status) => new Illuminate\Http\JsonResponse($data, $status));
    app()->instance(Illuminate\Contracts\Routing\ResponseFactory::class, $factory);
    $error = App\Modules\Shared\Http\ApiErrorResponse::fromException($exception, jsonRequest('{}'));
    check($error->getStatusCode() === 422 && $error->getData(true)['meta']['request_id'] === $requestId, 'existing safe error envelope');
    check($error->getData(true)['error']['code'] === 'PROVIDER_SETUP_INPUT_INVALID', 'stable validation error code');
    check(! str_contains($error->getContent(), input()['bootstrap_secret']) && ! str_contains($error->getContent(), input()['password']), 'safe validation response');
    Mockery::close();
});

runCase('C10', function () {
    $root = dirname(__DIR__, 3);
    $auth = file_get_contents($root.'/app/Modules/Provider/Application/ProviderAuthenticationService.php');
    $authorization = file_get_contents($root.'/app/Modules/Provider/Application/ProviderAuthorizationService.php');
    $activation = file_get_contents($root.'/app/Modules/Identity/Http/Controllers/FirstAdminActivationController.php');
    check(str_contains($auth, "return 'AUTHENTICATED';"), 'optional-MFA routine login completes without a pending challenge');
    check(str_contains($auth, "return 'MFA_REQUIRED';"), 'confirmed MFA accounts retain their challenge');
    check(str_contains($authorization, '$user->mfa_enrolled_at === null'), 'MFA required authorization unchanged');
    check(str_contains($activation, "abort(503, 'CORE01_SECURITY_GATE_CLOSED')"), 'activation 503 preserved');
    $service = file_get_contents($root.'/app/Modules/Provider/Application/ProviderBootstrapService.php');
    foreach (['registerSession', 'recordStepUp', 'Auth::', 'issuer()', 'core01_'] as $forbidden) {
        check(! str_contains($service, $forbidden), 'no authority/login bypass');
    }
});

runCase('C11', function () use ($requestId) {
    // Adapter-modeled trigger/commit-order scenarios, NOT PostgreSQL execution.
    foreach (['provider_users', 'users', 'tenant_staff_users', 'tenants', 'security_audit_events',
        'provider_control_operations', 'provider_approval_requests'] as $table) {
        [$db, $service] = fixture();
        check($service->status() === ['state' => 'AVAILABLE'], 'initially fresh '.$table);
        $db->transaction(fn () => $db->table($table)->insert(['synthetic' => true]));
        check($db->rows['provider_installation_setup'][0]['sealed'] === true, 'post-migration population seals '.$table);
        check($db->rows[$table] === [['synthetic' => true]], 'legitimate inserted data preserved '.$table);
        rejects(fn () => $service->status(), 409, 'population wins status '.$table);
        rejects(fn () => $service->create(input(), $requestId), 409, 'population wins creation '.$table);
        $db->rows[$table] = []; // Model later deletion; marker is not reopened.
        rejects(fn () => $service->create(input(), $requestId), 409, 'population history survives deletion '.$table);
        check($db->rows['provider_users'] === [], 'no replacement bootstrap '.$table);

        [$db, $service] = fixture();
        try {
            $db->transaction(function () use ($db, $table) {
                $db->table($table)->insert(['synthetic' => true]);
                throw new RuntimeException('Synthetic population rollback.');
            });
        } catch (RuntimeException) {
            check(! $db->rows['provider_installation_setup'][0]['sealed'], 'population rollback restores eligibility '.$table);
        }
        check($service->status() === ['state' => 'AVAILABLE'] && $db->rows[$table] === [], 'rolled-back insert leaves no population '.$table);

        [$db, $service] = fixture();
        $service->create(input(), $requestId); // Setup wins the serialized commit order.
        $marker = $db->rows['provider_installation_setup'][0];
        $db->transaction(fn () => $db->table($table)->insert(['synthetic' => true]));
        check($db->rows['provider_installation_setup'][0] === $marker, 'later insert cannot rewrite completion '.$table);
        check(in_array(['synthetic' => true], $db->rows[$table], true), 'post-setup data preserved '.$table);
        rejects(fn () => $service->create(input(), $requestId), 409, 'setup-first still sealed '.$table);
    }
    [$db, $service] = fixture();
    $db->transaction(static fn () => null); // Zero inserted rows means no row hook.
    check($service->status() === ['state' => 'AVAILABLE'], 'zero-row operation does not seal in model');
});

runCase('C12', function () {
    [$db, $service] = fixture();
    $controller = new ProviderBootstrapController;
    $response = $controller->status(jsonRequest('{}'), $service);
    check($response->getStatusCode() === 200 && $response->getData(true)['data'] === ['state' => 'AVAILABLE'], 'frontend status contract');
    foreach (['[]', 'null', '{broken', '{"extra":1}', '"text"'] as $body) {
        rejects(fn () => $controller->status(jsonRequest($body), $service), 422, 'status requires empty JSON object');
    }
    check($response->headers->get('Cache-Control') === 'no-store, private', 'status not cached');
    // UI itself is parent-owned; this case verifies the actual backend-facing contract only.
});

runCase('C13', function () {
    $output = new BufferedOutput;
    $cli = new BootstrapProviderRoot;
    $cli->setOutput(new OutputStyle(new Symfony\Component\Console\Input\ArrayInput([]), $output));
    check($cli->handle() === 1, 'deprecated command fails closed without services');
    check(str_contains($output->fetch(), 'No account was created'), 'explicit deprecation');
    $property = new ReflectionProperty($cli, 'signature');
    check(str_starts_with($property->getValue($cli), 'provider:bootstrap-root {email :'), 'legacy CLI name and argument retained');
    $routes = file_get_contents(dirname(__DIR__, 3).'/routes/api.php');
    check(str_contains($routes, "->middleware(RequireProviderOrigin::class)"), 'origin enclosing group');
    check(str_contains($routes, "ForceProviderBootstrapCsrf::class, RequireProviderBootstrapRequest::class, 'throttle:5,60'"), 'route defenses');
});

runCase('C14', function () {
    $migration = file_get_contents(dirname(__DIR__, 3).'/database/migrations/2026_11_07_000070_create_provider_installation_setup.php');
    foreach (['SET LOCAL row_security = off', 'SHARE ROW EXCLUSIVE MODE', 'CHECK (id = 1)', 'OLD.sealed',
        'BEFORE UPDATE OR DELETE', 'BEFORE TRUNCATE', 'FROM PUBLIC, dl_provider',
        'GRANT UPDATE (sealed, completed_at)', 'Forward-only', 'transactionLevel() < 1', 'END;',
        "pg_has_role('dl_provider', current_user, 'MEMBER')", 'JOIN aclexplode', 'FROM %I',
        "'provider_users', 'users', 'tenant_staff_users', 'tenants', 'security_audit_events'",
        "'provider_control_operations', 'provider_approval_requests'"] as $needle) {
        check(str_contains($migration, $needle), 'migration safety source contract');
    }
    foreach (['DROP TABLE', 'ALTER ROLE', 'CREATE ROLE', 'BYPASSRLS', 'DISABLE ROW LEVEL SECURITY'] as $forbidden) {
        check(! str_contains($migration, $forbidden), 'no authority or destructive migration widening');
    }
    check(substr_count($migration, 'SECURITY DEFINER') === 1, 'only one narrowly authorized definer');
    $matched = preg_match('/CREATE FUNCTION public\.provider_installation_setup_seal_on_population\(\) RETURNS trigger\s+LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS \$seal\$(.*?)\$seal\$;/s', $migration, $matches);
    check($matched === 1, 'no-argument fixed-search-path definer');
    check(preg_replace('/\s+/', ' ', trim($matches[1])) ===
        'BEGIN UPDATE public.provider_installation_setup SET sealed = true, completed_at = clock_timestamp() WHERE id = 1 AND NOT sealed; RETURN NEW; END;',
        'definer body only seals fixed marker; no payload, reads, auth, reopening or dynamic SQL');
    check(str_contains($migration, 'REVOKE ALL ON FUNCTION public.provider_installation_setup_seal_on_population() FROM PUBLIC;'), 'no public function execution grant');
    check(str_contains($migration, 'CREATE TRIGGER provider_installation_setup_population AFTER INSERT ON public.'), 'population hook installed on whitelist loop');
    check(str_contains($migration, ' FOR EACH ROW EXECUTE FUNCTION public.provider_installation_setup_seal_on_population()'), 'row hook skips zero-row statements');
    check(substr_count($migration, 'foreach ($tables as $table)') === 3, 'all seven tables locked, attested and hooked');
    check(strpos($migration, 'LOCK TABLE public.') < strpos($migration, 'CREATE TRIGGER provider_installation_setup_population'), 'population hooks installed while attestation locks held');
});

echo 'P1_BOOTSTRAP_OFFLINE cases='.$cases.' assertions='.$checks." PASS\n";
echo "REAL_DB_CONCURRENCY=NOT_RUN; MIGRATION_ACL_RLS=NOT_RUN; HTTP_BROWSER=NOT_RUN; UI=NOT_RUN_PARENT_OWNED\n";
