<?php

declare(strict_types=1);

namespace App\Modules\Identity\Application;

use Illuminate\Database\Connection;

interface TenantRuntimeIdentityAttestor
{
    /** @return array{principal:string,database:string,system_identifier:string,database_oid:int,backend_pid:int} */
    public function attest(Connection $connection): array;
}
