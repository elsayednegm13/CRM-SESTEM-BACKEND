<?php

namespace App\Modules\Tenancy\Infrastructure\Persistence;

use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;

class ActiveMembershipLookup
{
    public function forUser(string $userId): Collection
    {
        return DB::table('tenant_memberships')
            ->where('user_id', $userId)->where('status', 'ACTIVE')
            ->limit(2)->get(['id', 'tenant_id', 'authorization_version']);
    }
}
