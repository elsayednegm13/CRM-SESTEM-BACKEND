<?php

namespace App\Modules\Identity\Infrastructure\Persistence;

use Illuminate\Database\Eloquent\Model;

/** One immutable company membership per tenant-local staff identity. */
final class TenantStaffMembership extends Model
{
    protected $table = 'tenant_staff_memberships';

    protected $primaryKey = 'id';

    public $incrementing = false;

    protected $keyType = 'string';

    protected $guarded = ['*'];

    protected function casts(): array
    {
        return [
            'authorization_version' => 'integer',
            'joined_at' => 'immutable_datetime',
        ];
    }
}
