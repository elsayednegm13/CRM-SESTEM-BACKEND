<?php

/** Disposable child-process proof harness. Receives synthetic factor data only on stdin. */
require dirname(__DIR__, 2).'/vendor/autoload.php';

use App\Modules\Provider\Application\ProviderApprovalService;
use App\Modules\Provider\Application\ProviderMfaService;
use App\Modules\Provider\Domain\ProviderAccessException;
use App\Modules\Provider\Domain\ProviderContext;
use App\Modules\Provider\Infrastructure\Persistence\ProviderDatabaseContext;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Support\Str;

$input = json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);
$barrier = $argv[1] ?? '';
$ready = $argv[2] ?? '';
if (! is_array($input) || ! is_string($barrier) || ! is_string($ready)
    || ! str_contains($barrier, 'daleel-b10b-concurrency-')
    || ! str_contains($ready, 'daleel-b10b-concurrency-')) {
    exit(20);
}
file_put_contents($ready, 'ready');
$deadline = microtime(true) + 15;
while (! is_file($barrier) && microtime(true) < $deadline) {
    usleep(10000);
}
if (! is_file($barrier)) {
    exit(21);
}

$app = require dirname(__DIR__, 2).'/bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();
try {
    $actor = (string) $input['actor'];
    $operation = (string) $input['operation'];
    if ($operation === 'factor') {
        app(ProviderDatabaseContext::class)->run($actor, function ($connection) use ($actor, $input): void {
            app(ProviderMfaService::class)->consumeFactor($connection, $actor,
                (string) $input['code'], (string) Str::uuid());
        });
        echo 'ACCEPTED';
    } else {
        $context = new ProviderContext($actor, (int) $input['auth_version'],
            (int) $input['authorization_version'], (string) Str::uuid(),
            time(), time());
        if ($operation === 'decide') {
            echo app(ProviderApprovalService::class)->decide($context,
                (string) $input['request_id'], 'APPROVE');
        } elseif ($operation === 'revoke') {
            app(ProviderApprovalService::class)->revoke($context, (string) $input['request_id']);
            echo 'REVOKED';
        } else {
            exit(22);
        }
    }
} catch (ProviderAccessException $exception) {
    echo 'DENIED';
}
