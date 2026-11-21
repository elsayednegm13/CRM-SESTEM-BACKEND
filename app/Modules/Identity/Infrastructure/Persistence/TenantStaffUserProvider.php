<?php

namespace App\Modules\Identity\Infrastructure\Persistence;

use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Str;

/** Session-only principal loader. Credential verification uses the narrow SQL function. */
final class TenantStaffUserProvider extends EloquentUserProvider
{
    public function retrieveById($identifier)
    {
        if (! is_string($identifier) || ! Str::isUuid($identifier)) {
            return null;
        }

        $model = $this->createModel();

        return $model->newQuery()
            ->select(['id', 'tenant_id', 'canonical_email', 'display_email', 'display_name', 'status', 'auth_version'])
            ->where($model->getAuthIdentifierName(), $identifier)
            ->first();
    }

    public function retrieveByToken($identifier, #[\SensitiveParameter] $token)
    {
        return null;
    }

    public function updateRememberToken(Authenticatable $user, #[\SensitiveParameter] $token)
    {
        // Tenant staff do not use Laravel remember tokens in this foundation.
    }

    public function retrieveByCredentials(#[\SensitiveParameter] array $credentials)
    {
        // Prevent an accidental email/password query outside the pre-auth function.
        return null;
    }

    public function validateCredentials(Authenticatable $user, #[\SensitiveParameter] array $credentials)
    {
        return false;
    }

    public function rehashPasswordIfRequired(Authenticatable $user, #[\SensitiveParameter] array $credentials, bool $force = false)
    {
        // Rehashing requires a separately reviewed credential write path.
    }
}
