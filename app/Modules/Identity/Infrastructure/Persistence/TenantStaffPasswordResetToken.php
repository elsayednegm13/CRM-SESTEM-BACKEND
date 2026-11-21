<?php

namespace App\Modules\Identity\Infrastructure\Persistence;

use Illuminate\Database\Eloquent\Model;

/** Hash-only reset metadata; raw reset tokens are never persisted. */
final class TenantStaffPasswordResetToken extends Model
{
    protected $table = 'tenant_staff_password_reset_tokens';

    protected $primaryKey = 'id';

    public $incrementing = false;

    protected $keyType = 'string';

    protected $guarded = ['*'];

    protected $hidden = ['token_hash'];

    public $timestamps = false;

    protected function casts(): array
    {
        return [
            'created_at' => 'immutable_datetime',
            'expires_at' => 'immutable_datetime',
            'consumed_at' => 'immutable_datetime',
        ];
    }
}
