<?php

namespace App\Modules\Identity\Infrastructure\Persistence;

use Illuminate\Database\Eloquent\Model;

/** Historical tenant-role assignment; revocation is represented by revoked_at. */
final class TenantStaffMembershipRole extends Model
{
    protected $table = 'tenant_staff_membership_roles';

    protected $primaryKey = 'id';

    public $incrementing = false;

    protected $keyType = 'string';

    protected $guarded = ['*'];

    protected function casts(): array
    {
        return [
            'assigned_at' => 'immutable_datetime',
            'revoked_at' => 'immutable_datetime',
        ];
    }
}
