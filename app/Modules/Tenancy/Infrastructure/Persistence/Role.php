<?php

namespace App\Modules\Tenancy\Infrastructure\Persistence;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;

final class Role extends Model
{
    use HasUuids;

    protected $fillable = ['tenant_id', 'display_name', 'normalized_name', 'source_template_id'];

    protected function casts(): array
    {
        return ['version' => 'integer', 'archived_at' => 'immutable_datetime'];
    }

    public function newUniqueId(): string
    {
        return (string) Str::uuid7();
    }
}
