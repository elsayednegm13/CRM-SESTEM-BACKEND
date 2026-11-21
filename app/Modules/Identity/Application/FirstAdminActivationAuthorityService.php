<?php

namespace App\Modules\Identity\Application;

use App\Modules\Identity\Domain\Exceptions\InvalidCredentialsException;
use App\Modules\Identity\Domain\TenantHostContext;
use Illuminate\Database\QueryException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use RuntimeException;

/**
 * Actor-bound first-admin activation (CORE-01, migration 058).
 *
 * Mints a signed, single-use, session-bound receipt through the issuer identity
 * (dl_tauth -> daleel_tenant_auth_lookup), which independently re-attests the
 * PENDING founder before issuing. The consumer (dl_onboarding) then redeems and
 * rotates atomically. This path does NOT touch the old core01_activate_first_admin,
 * migration 048 REVOKE, or the HTTP 503 gate; it uses independent authority.
 */
final class FirstAdminActivationAuthorityService
{
    public function enabled(): bool
    {
        return (bool) config('core_sql.activation_authority_enabled');
    }

    public function activate(Request $request, TenantHostContext $host, string $email,
        string $initialPassword, string $newPassword, string $requestId): void
    {
        if (! $this->enabled()) {
            abort(503, 'CORE01_SECURITY_GATE_CLOSED');
        }

        $issuer = DB::connection('pgsql_tenant_auth');
        $credentials = $issuer->selectOne(
            'SELECT * FROM public.core01_lookup_pending_first_admin(?, ?, ?, ?)',
            [$host->hostname, $host->baseDomain, $host->environmentScope, $email],
        );
        $oldHash = $credentials?->password_hash;
        $matches = is_string($oldHash) && str_starts_with($oldHash, '$argon2id$')
            && Hash::driver('argon2id')->check($initialPassword, $oldHash);
        if (! $matches || ! hash_equals((string) $credentials->tenant_id, $host->tenantId)
            || ! Str::isUuid((string) $credentials->staff_user_id)
            || ! Str::isUuid((string) $credentials->membership_id)) {
            throw new InvalidCredentialsException;
        }
        $newHash = Hash::driver('argon2id')->make($newPassword);

        $generation = (string) Str::uuid7();
        $request->session()->put('activation.authority_generation', $generation);
        $sessionHash = $this->sessionHash($request, $generation);
        $token = bin2hex(random_bytes(32));

        try {
            $issuer->selectOne(
                'SELECT public.core01_first_admin_activation_issue_receipt(?,?,?,?,?,?,?,?::uuid,?::uuid,?) AS id',
                [$host->hostname, $host->baseDomain, $host->environmentScope, $email,
                    $oldHash, $newHash, $sessionHash, $generation, $requestId, hash('sha256', $token)],
            );

            $onboarding = DB::connection('pgsql_onboarding');
            $result = $onboarding->transaction(function () use (
                $onboarding, $host, $credentials, $token, $sessionHash, $generation, $requestId
            ): object {
                $onboarding->selectOne('SELECT pg_catalog.set_config(?, ?, true) AS value',
                    ['app.core01_base_domain', $host->baseDomain]);
                return $onboarding->selectOne(
                    'SELECT public.core01_activate_first_admin_with_authority(?,?,?::uuid,?::uuid,?::uuid,?::uuid,?,?::uuid) AS activated',
                    [$token, $sessionHash, $generation, $host->tenantId, $credentials->staff_user_id,
                        $credentials->membership_id, $host->hostname, $requestId],
                );
            });
            if ($result?->activated !== true && $result?->activated !== 't' && $result?->activated !== 1) {
                throw new RuntimeException('First administrator activation returned no result.');
            }
        } catch (QueryException $exception) {
            $state = (string) ($exception->errorInfo[0] ?? $exception->getCode());
            if ($state === 'PZ403' || $state === 'PZ409' || $state === '23505') {
                throw new InvalidCredentialsException;
            }
            logger()->error('First administrator activation (authority) failed.', ['request_id' => $requestId,
                'sqlstate' => preg_match('/^[A-Z0-9]{5}$/D', $state) ? $state : 'UNKNOWN']);
            throw new RuntimeException('First administrator activation is unavailable.');
        } finally {
            $request->session()->forget('activation.authority_generation');
        }
    }

    private function sessionHash(Request $request, string $generation): string
    {
        $key = config('core_sql.session_binding_key');
        if (! is_string($key) || preg_match('/^[a-f0-9]{64}$/D', $key) !== 1) {
            throw new RuntimeException('Activation session binding key is unavailable.');
        }
        return hash_hmac('sha256', $request->session()->getId().'|'.$generation, hex2bin($key));
    }
}
