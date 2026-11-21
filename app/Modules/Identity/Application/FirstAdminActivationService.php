<?php

namespace App\Modules\Identity\Application;

use App\Modules\Identity\Domain\TenantHostContext;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use RuntimeException;

/** One-use founder password rotation, followed by normal tenant login. */
final class FirstAdminActivationService
{
    public function activate(TenantHostContext $host, string $email, string $initialPassword, string $newPassword, string $requestId): void
    {
        $credentials = DB::connection('pgsql_tenant_auth')->selectOne(
            'SELECT * FROM public.core01_lookup_pending_first_admin(?, ?, ?, ?)',
            [$host->hostname, $host->baseDomain, $host->environmentScope, $email],
        );
        $oldHash = $credentials?->password_hash;
        $matches = is_string($oldHash) && str_starts_with($oldHash, '$argon2id$')
            && Hash::driver('argon2id')->check($initialPassword, $oldHash);
        if (! $matches || ! hash_equals((string) $credentials->tenant_id, $host->tenantId)
            || ! Str::isUuid((string) $credentials->staff_user_id)
            || ! Str::isUuid((string) $credentials->membership_id)) {
            throw new \App\Modules\Identity\Domain\Exceptions\InvalidCredentialsException;
        }
        $newHash = Hash::driver('argon2id')->make($newPassword);
        $db = DB::connection('pgsql_onboarding');
        try {
            $result = $db->transaction(function () use ($db, $host, $credentials, $oldHash, $newHash, $requestId): object {
                $db->selectOne('SELECT pg_catalog.set_config(?, ?, true) AS value', ['app.core01_base_domain', $host->baseDomain]);
                return $db->selectOne(
                    'SELECT public.core01_activate_first_admin(?::uuid,?::uuid,?::uuid,?,?,?,?::uuid) AS activated',
                    [$host->tenantId, $credentials->staff_user_id, $credentials->membership_id,
                        $oldHash, $newHash, $host->hostname, $requestId],
                );
            });
            if ($result?->activated !== true && $result?->activated !== 't' && $result?->activated !== 1) {
                throw new RuntimeException('First administrator activation returned no result.');
            }
        } catch (QueryException $exception) {
            $state = (string) ($exception->errorInfo[0] ?? $exception->getCode());
            if ($state === 'PZ403' || $state === '23505') {
                throw new \App\Modules\Identity\Domain\Exceptions\InvalidCredentialsException;
            }
            logger()->error('First administrator activation failed.', ['request_id' => $requestId,
                'sqlstate' => preg_match('/^[A-Z0-9]{5}$/D', $state) ? $state : 'UNKNOWN']);
            throw new RuntimeException('First administrator activation is unavailable.');
        }
    }
}
