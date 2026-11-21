<?php

namespace App\Modules\Identity\Infrastructure\Persistence;

use Illuminate\Database\Eloquent\Model;

/** Append-only event metadata; sensitive credentials and token values are excluded. */
final class TenantStaffSecurityEvent extends Model
{
    protected $table = 'tenant_staff_security_events';

    protected $primaryKey = 'id';

    public $incrementing = false;

    protected $keyType = 'string';

    protected $guarded = ['*'];

    public $timestamps = false;

    protected function casts(): array
    {
        return [
            'occurred_at' => 'immutable_datetime',
            'metadata' => 'array',
        ];
    }
}
