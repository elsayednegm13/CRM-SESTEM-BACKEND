<?php

declare(strict_types=1);

namespace App\Modules\Identity\Application;

use App\Modules\Identity\Domain\TenantHostContext;
use Illuminate\Database\Connection;
use Illuminate\Http\Request;

interface RevokedTenantSessionVerifier
{
    public function assertDenied(TenantHostContext $host, Request $request, Connection $connection): void;
}
