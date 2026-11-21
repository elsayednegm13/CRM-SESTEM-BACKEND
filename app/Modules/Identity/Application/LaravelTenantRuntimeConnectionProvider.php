<?php

declare(strict_types=1);

namespace App\Modules\Identity\Application;

use Illuminate\Database\Connection;
use Illuminate\Support\Facades\DB;

final class LaravelTenantRuntimeConnectionProvider implements TenantRuntimeConnectionProvider
{
    public function connection(): Connection
    {
        /** @var Connection $connection */
        $connection = DB::connection('pgsql_tenant_runtime');

        return $connection;
    }
}
