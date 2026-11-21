<?php

// Source-only preflight. It never opens a database connection or prints a secret.
require dirname(__DIR__, 3).'/vendor/autoload.php';

use App\Modules\Identity\Application\ActorConnectionFactory;
use App\Modules\Identity\Application\ActorSqlIdentityResolver;
use Illuminate\Config\Repository;
use Illuminate\Container\Container;

$role = 'daleel_f06i03_actor_a4';
putenv('F06_ACTOR_PW_A4');
unset($_ENV['F06_ACTOR_PW_A4'], $_SERVER['F06_ACTOR_PW_A4']);
putenv('F06_ACTOR_SQL_INTEGRATION_ENABLED');
unset($_ENV['F06_ACTOR_SQL_INTEGRATION_ENABLED'], $_SERVER['F06_ACTOR_SQL_INTEGRATION_ENABLED']);
$without = require dirname(__DIR__, 3).'/config/f06_actor_sql.php';
if ($without['enabled'] !== false || ($without['synthetic_actor_passwords'][$role] ?? null) !== null) {
    throw new RuntimeException('Default-off or missing-credential check failed');
}

$container = new Container;
Container::setInstance($container);
$without['enabled'] = true;
$container->instance('config', new Repository(['f06_actor_sql' => $without]));
$resolver = new ActorSqlIdentityResolver;
if ($resolver->passwordFor($role) !== null) {
    throw new RuntimeException('Missing credential did not resolve to null');
}
try {
    (new ActorConnectionFactory)->switchTo($role, null);
    throw new RuntimeException('Missing credential did not fail closed');
} catch (RuntimeException $e) {
    if ($e->getMessage() !== 'No synthetic credential resolved for actor role; refusing to open a connection.') {
        throw $e;
    }
}

putenv('F06_ACTOR_PW_A4=synthetic-preflight-only');
$_ENV['F06_ACTOR_PW_A4'] = 'synthetic-preflight-only';
$with = require dirname(__DIR__, 3).'/config/f06_actor_sql.php';
if (($with['synthetic_actor_passwords'][$role] ?? null) !== 'synthetic-preflight-only') {
    throw new RuntimeException('A4 environment mapping check failed');
}
$container->instance('config', new Repository(['f06_actor_sql' => ['enabled' => true, 'synthetic_actor_passwords' => $with['synthetic_actor_passwords']]]));
if ($resolver->passwordFor($role) !== 'synthetic-preflight-only') {
    throw new RuntimeException('Resolver did not use the distinct A4 key');
}
if ($resolver->passwordFor('daleel_f06i03_actor_unknown') !== null) {
    throw new RuntimeException('Unknown role gained a credential');
}

echo "G0_DEFAULT_OFF=PASS\nG0_MISSING_A4_FAIL_CLOSED=PASS\nG0_DISTINCT_A4_ENV_MAPPING=PASS\nG0_UNKNOWN_ROLE_FAIL_CLOSED=PASS\n";
