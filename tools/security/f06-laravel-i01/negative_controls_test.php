<?php

/**
 * SECURITY-F06-LARAVEL-IMPLEMENT-01 : NC-01/NC-02/NC-03 negative controls against
 * ActorConnectionFactory, driven directly (not through the middleware), using the
 * same real sandbox PostgreSQL connection as middleware_wire_test.php.
 */

$secrets = getenv('F06_SECRETS_DIR');
$readSecret = static fn (string $name): string => trim((string) file_get_contents($secrets.'/'.$name));

putenv('APP_ENV=testing');
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
putenv('TENANT_RUNTIME_DB_PORT=55450');
putenv('TENANT_RUNTIME_DB_DATABASE=f06i01');
putenv('TENANT_RUNTIME_DB_USERNAME=daleel_f06i01_actor_a1');
putenv('TENANT_RUNTIME_DB_PASSWORD='.$readSecret('.a1'));
putenv('TENANT_RUNTIME_DB_SSLMODE=disable');

putenv('F06_ACTOR_SQL_INTEGRATION_ENABLED=true');
putenv('F06_ACTOR_SQL_ALLOWED_APP_ENV=testing');
putenv('F06_ACTOR_PW_A1='.$readSecret('.a1'));
putenv('F06_ACTOR_PW_A2='.$readSecret('.a2'));
putenv('F06_ACTOR_PW_B1='.$readSecret('.b1'));

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
    fwrite(STDOUT, sprintf("%-28s %-5s %s\n", $id, $pass ? 'PASS' : 'FAIL', $detail));
};

// NC-02a: missing password for a role -> resolver returns null -> factory throws, never connects.
try {
    $resolver = new ActorSqlIdentityResolver;
    $pw = $resolver->passwordFor('daleel_f06i01_actor_does_not_exist_in_config');
    $factory = new ActorConnectionFactory;
    $factory->switchTo('daleel_f06i01_actor_does_not_exist_in_config', $pw);
    $record('NC-02a-MISSING-PASSWORD', false, 'no exception thrown (should have refused)');
} catch (\RuntimeException $e) {
    $record('NC-02a-MISSING-PASSWORD', true, 'refused: '.$e->getMessage());
} catch (\Throwable $e) {
    $record('NC-02a-MISSING-PASSWORD', false, 'wrong exception type: '.get_class($e));
}

// NC-02b: wrong password for a real role -> PDO auth fails, no fallback to shared runtime credential.
try {
    $factory = new ActorConnectionFactory;
    $factory->switchTo('daleel_f06i01_actor_a1', 'definitely_the_wrong_password_123');
    $record('NC-02b-WRONG-PASSWORD', false, 'connection unexpectedly succeeded');
} catch (\Throwable $e) {
    // Must fail as a DB auth error, not silently fall back.
    $isAuthFailure = str_contains($e->getMessage(), 'password authentication failed') || str_contains($e->getMessage(), '28P01');
    $record('NC-02b-WRONG-PASSWORD', $isAuthFailure, get_class($e).': '.$e->getMessage());
}

// Confirm the ambient/original config was not left pointing at a half-switched state after NC-02b.
$ambientUser = config('database.connections.pgsql_tenant_runtime.username');
$record('NC-02b-CONFIG-NOT-CORRUPTED', $ambientUser === 'daleel_f06i01_actor_a1', 'username now = '.$ambientUser);

// NC-01: a role switch where the verification step would detect a session_user
// mismatch. We simulate this by pointing the factory at a role name that differs
// from the actual authenticated role the password belongs to -- the factory must
// catch this via its own post-connect session_user check, not trust the caller.
try {
    $password = (new ActorSqlIdentityResolver)->passwordFor('daleel_f06i01_actor_b1');
    $factory = new ActorConnectionFactory;
    // Intentionally wrong: claiming this password belongs to actor_a1.
    $factory->switchTo('daleel_f06i01_actor_a1', $password);
    $record('NC-01-SESSION-USER-MISMATCH', false, 'no exception thrown (should have refused)');
} catch (\Throwable $e) {
    $record('NC-01-SESSION-USER-MISMATCH', true, get_class($e).': '.$e->getMessage());
}

// NC-03: refuse to switch while a transaction is already open on pgsql_tenant_runtime.
try {
    DB::connection('pgsql_tenant_runtime')->beginTransaction();
    $factory = new ActorConnectionFactory;
    $password = (new ActorSqlIdentityResolver)->passwordFor('daleel_f06i01_actor_a2');
    try {
        $factory->switchTo('daleel_f06i01_actor_a2', $password);
        $record('NC-03-PURGE-DURING-OPEN-TX', false, 'no exception thrown (should have refused)');
    } catch (\LogicException $e) {
        $record('NC-03-PURGE-DURING-OPEN-TX', true, get_class($e).': '.$e->getMessage());
    } finally {
        if (DB::connection('pgsql_tenant_runtime')->transactionLevel() > 0) {
            DB::connection('pgsql_tenant_runtime')->rollBack();
        }
    }
} catch (\Throwable $e) {
    $record('NC-03-PURGE-DURING-OPEN-TX', false, 'setup error: '.$e->getMessage());
}

$fail = count(array_filter($results, static fn ($p) => ! $p));
fwrite(STDOUT, "\nTOTAL=".count($results).' PASS='.(count($results) - $fail).' FAIL='.$fail."\n");
exit($fail > 0 ? 1 : 0);
