<?php

declare(strict_types=1);

namespace App\Modules\Identity\Application;

use Illuminate\Database\Connection;

interface TenantRuntimeConnectionProvider
{
    public function connection(): Connection;
}
