<?php

require dirname(__DIR__, 3).'/vendor/autoload.php';

use App\Modules\Identity\Application\ActorConnectionFactory;
use App\Modules\Identity\Domain\Exceptions\ActorSqlUnavailableException;
use Illuminate\Config\Repository;
use Illuminate\Container\Container;

$container = new Container;
Container::setInstance($container);
$container->instance('config', new Repository([
    'database' => ['connections' => ['pgsql_tenant_runtime' => ['username' => 'unused', 'password' => 'unused']]],
    'f06_actor_sql' => ['synthetic_actor_passwords' => ['mapped_actor' => null]],
]));

$factory = new ActorConnectionFactory;
foreach (['mapped_actor' => 'MISSING_CREDENTIAL', 'unknown_actor' => 'UNMAPPED_ACTOR'] as $actor => $expected) {
    try {
        $factory->switchTo($actor, null);
        throw new RuntimeException('Missing actor credential unexpectedly accepted');
    } catch (ActorSqlUnavailableException $exception) {
        if ($exception->reason !== $expected || $exception->getMessage() !== 'Actor SQL service is unavailable.') {
            throw new RuntimeException('Actor SQL classification mismatch');
        }
    }
}
if (ActorSqlUnavailableException::missingFunction()->reason !== 'MISSING_FUNCTION') {
    throw new RuntimeException('Function classification mismatch');
}
echo "G2_SOURCE_GATE=PASS MISSING_CREDENTIAL/UNMAPPED_ACTOR/MISSING_FUNCTION\n";
