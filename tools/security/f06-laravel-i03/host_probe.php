<?php

// Diagnostic only; no secrets or SQL rows are printed.
require dirname(__DIR__, 3).'/vendor/autoload.php';
$app = require dirname(__DIR__, 3).'/bootstrap/app.php';
$app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
echo 'ENV='.config('app.env').' AUTH_ENABLED='.(config('identity.tenant_auth_client_enabled') ? 'true' : 'false')
    .' BASE='.config('tenancy.base_domain').' LOCAL='.config('tenancy.local_test_base_domain').'\n';
try {
    $host = app(App\Modules\Identity\Application\TenantHostResolver::class)->resolve('tenant-a.f06i03.localhost');
    echo 'HOST_RESOLVED='.$host->tenantId.'\n';
} catch (Throwable $e) {
    echo 'HOST_ERROR='.get_class($e).' '.$e->getMessage().'\n';
    exit(1);
}
