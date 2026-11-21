<?php

namespace App\Modules\Identity\Infrastructure\Persistence;

use Illuminate\Foundation\Auth\User as Authenticatable;

/** Tenant-local staff principal. Never fall back to the legacy global User model. */
final class TenantStaffUser extends Authenticatable
{
    protected $connection = 'pgsql_tenant_runtime';

    protected $table = 'tenant_staff_users';

    protected $primaryKey = 'id';

    public $incrementing = false;

    protected $keyType = 'string';

    protected $guarded = ['*'];

    protected $hidden = ['password_hash'];

    protected $authPasswordName = 'password_hash';

    protected function casts(): array
    {
        return [
            'auth_version' => 'integer',
        ];
    }
}
