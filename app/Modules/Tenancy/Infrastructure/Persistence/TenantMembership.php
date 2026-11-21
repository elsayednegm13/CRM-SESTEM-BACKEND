<?php

namespace App\Modules\Tenancy\Infrastructure\Persistence;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;

final class TenantMembership extends Model
{
    use HasUuids;

    protected $fillable = ['tenant_id', 'user_id', 'joined_at'];

    protected function casts(): array
    {
        return ['authorization_version' => 'integer', 'joined_at' => 'immutable_datetime'];
    }

    public function newUniqueId(): string
    {
        return (string) Str::uuid7();
    }
}
