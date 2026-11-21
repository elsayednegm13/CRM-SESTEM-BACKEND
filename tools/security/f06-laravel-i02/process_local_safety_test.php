<?php

/**
 * SECURITY-F06-LARAVEL-IMPLEMENT-02: G07-12 (same-PHP-process connection switch
 * safety) and NC-01/NC-02/NC-03 against the real-schema sandbox, run directly
 * against ActorConnectionFactory in a single PHP process (artisan serve forks a
 * fresh process per request, so true PHP-FPM worker reuse cannot be exercised by
 * curl alone -- HTTP_SAME_WORKER_REUSE is reported NOT_VERIFIED for a persistent
 * worker; this script instead proves the identity-switch code itself is safe
 * across repeated use within one process, which is the mechanism GATE-06 relies
 * on regardless of worker model).
 */

$secrets = getenv('F06_SECRETS_DIR');
$readSecret = static fn (string $name): string => trim((string) file_get_contents($secrets.'\\'.$name));

putenv('APP_ENV=local');
putenv('APP_KEY=base64:9VOcF8isaS3rkETFWjWCVCMVbh0tQKGb1cYfn9sEYsA=');
putenv('APP_DEBUG=false');
putenv('SESSION_DRIVER=array');
putenv('CACHE_STORE=array');
putenv('QUEUE_CONNECTION=sync');
putenv('DB_CONNECTION=pgsql');
putenv('DB_HOST=127.0.0.1');
putenv('DB_PORT=1');
putenv('DB_DATABASE=unused_default_connection_must_not_be_queried');

putenv('TENANT_RUNTIME_DB_HOST=127.0.0.1');
putenv('TENANT_RUNTIME_DB_PORT=55460');
putenv('TENANT_RUNTIME_DB_DATABASE=f06i02');
putenv('TENANT_RUNTIME_DB_USERNAME=daleel_f06i02_shared_bootstrap');
putenv('TENANT_RUNTIME_DB_PASSWORD='.$readSecret('.shared_bootstrap'));
putenv('TENANT_RUNTIME_DB_SSLMODE=disable');

putenv('F06_ACTOR_SQL_INTEGRATION_ENABLED=true');
putenv('F06_ACTOR_SQL_ALLOWED_APP_ENV=local');
putenv('F06_ACTOR_PW_A1='.$readSecret('.actor_a1'));
putenv('F06_ACTOR_PW_A2='.$readSecret('.actor_a2'));
putenv('F06_ACTOR_PW_B1='.$readSecret('.actor_b1'));

require __DIR__.'/../../../vendor/autoload.php';
/** @var \Illuminate\Foundation\Application $app */
$app = require __DIR__.'/../../../bootstrap/app.php';
$app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();

use App\Modules\Identity\Application\ActorConnectionFactory;
use App\Modules\Identity\Application\ActorSqlIdentityResolver;
use Illuminate\Support\Facades\DB;

$results = [];
$record = static function (string $id, bool $pass, string $detail) use (&$results) {
    $results[] = $pass;
    fwrite(STDOUT, sprintf("%-30s %-5s %s\n", $id, $pass ? 'PASS' : 'FAIL', $detail));
};

$resolver = new ActorSqlIdentityResolver;

// G07-12: A1 -> B1 -> A2 sequential switches in ONE PHP process, no leakage.
$sequence = ['daleel_f06i02_actor_a1', 'daleel_f06i02_actor_b1', 'daleel_f06i02_actor_a2', 'daleel_f06i02_actor_a1'];
$ok = true;
$observed = [];
foreach ($sequence as $role) {
    $factory = new ActorConnectionFactory;
    try {
        $factory->switchTo($role, $resolver->passwordFor($role));
        $su = DB::connection('pgsql_tenant_runtime')->selectOne('SELECT session_user AS value')->value ?? null;
        $observed[] = $su;
        $ok = $ok && ($su === $role);
    } finally {
        $factory->reset();
        $after = DB::connection('pgsql_tenant_runtime')->selectOne('SELECT session_user AS value')->value ?? null;
        $ok = $ok && ($after === 'daleel_f06i02_shared_bootstrap');
    }
}
$record('G07-12-SEQUENTIAL-SWITCH-SAFETY', $ok, 'observed='.implode(',', $observed));

// NC-02a: missing password.
try {
    $factory = new ActorConnectionFactory;
    $factory->switchTo('daleel_f06i02_actor_a1', null);
    $record('NC-02a-MISSING-PASSWORD', false, 'no exception');
} catch (\RuntimeException $e) {
    $record('NC-02a-MISSING-PASSWORD', true, $e->getMessage());
}

// NC-02b: wrong password, config not left corrupted afterward.
try {
    $factory = new ActorConnectionFactory;
    $factory->switchTo('daleel_f06i02_actor_a1', 'wrong_password_value');
    $record('NC-02b-WRONG-PASSWORD', false, 'connection unexpectedly succeeded');
} catch (\Throwable $e) {
    $authFail = str_contains($e->getMessage(), 'password authentication failed');
    $ambient = config('database.connections.pgsql_tenant_runtime.username');
    $record('NC-02b-WRONG-PASSWORD', $authFail, get_class($e));
    $record('NC-02b-CONFIG-RESTORED', $ambient === 'daleel_f06i02_shared_bootstrap', 'ambient now='.$ambient);
}
// Prove the connection is still usable (not left broken) after NC-02b.
$su = DB::connection('pgsql_tenant_runtime')->selectOne('SELECT session_user AS value')->value ?? null;
$record('NC-02b-CONNECTION-USABLE-AFTER', $su === 'daleel_f06i02_shared_bootstrap', 'session_user='.$su);

// NC-03: refuse to switch while a transaction is open.
DB::connection('pgsql_tenant_runtime')->beginTransaction();
try {
    $factory = new ActorConnectionFactory;
    try {
        $factory->switchTo('daleel_f06i02_actor_a2', $resolver->passwordFor('daleel_f06i02_actor_a2'));
        $record('NC-03-PURGE-DURING-OPEN-TX', false, 'no exception');
    } catch (\LogicException $e) {
        $record('NC-03-PURGE-DURING-OPEN-TX', true, $e->getMessage());
    }
} finally {
    if (DB::connection('pgsql_tenant_runtime')->transactionLevel() > 0) {
        DB::connection('pgsql_tenant_runtime')->rollBack();
    }
}

$fail = count(array_filter($results, static fn ($p) => ! $p));
fwrite(STDOUT, "\nTOTAL=".count($results).' PASS='.(count($results) - $fail).' FAIL='.$fail."\n");
exit($fail > 0 ? 1 : 0);
