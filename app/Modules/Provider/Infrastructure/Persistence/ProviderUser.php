<?php

namespace App\Modules\Provider\Infrastructure\Persistence;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Support\Str;

final class ProviderUserQueryBuilder extends Builder
{
    private const DEFAULT_PROJECTION = [
        'id', 'email', 'status', 'email_verified_at', 'mfa_enrolled_at',
        'auth_version', 'authorization_version',
    ];

    public function get($columns = ['*'])
    {
        if ($columns === ['*']) {
            $selected = $this->getQuery()->columns;
            $columns = $selected === null || $selected === ['*'] || $selected === ['provider_users.*']
                ? self::DEFAULT_PROJECTION
                : $selected;
        }

        return parent::get($columns);
    }
}

final class ProviderUser extends Authenticatable
{
    use HasUuids;

    protected $connection = 'pgsql_provider';
    protected $table = 'provider_users';
    protected $fillable = ['email', 'password'];
    protected $hidden = ['password', 'auth_version', 'authorization_version'];

    public function newEloquentBuilder($query)
    {
        return new ProviderUserQueryBuilder($query);
    }

    protected function casts(): array
    {
        return [
            'password' => 'hashed',
            'email_verified_at' => 'datetime',
            'mfa_enrolled_at' => 'datetime',
            'auth_version' => 'integer',
            'authorization_version' => 'integer',
        ];
    }

    public function newUniqueId(): string
    {
        return (string) Str::uuid7();
    }
}
