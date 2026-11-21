<?php

namespace App\Modules\Identity\Infrastructure\Persistence;

use Illuminate\Database\Eloquent\Model;

/** Positive catalog-backed grant for exactly one tenant staff membership. */
final class TenantStaffPermissionGrant extends Model
{
    protected $table = 'tenant_staff_permission_grants';

    protected $primaryKey = 'id';

    public $incrementing = false;

    protected $keyType = 'string';

    protected $guarded = ['*'];

    protected function casts(): array
    {
        return [
            'granted_at' => 'immutable_datetime',
            'revoked_at' => 'immutable_datetime',
        ];
    }
}
