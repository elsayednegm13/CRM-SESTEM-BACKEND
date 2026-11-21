<?php

namespace App\Modules\Identity\Application;

use App\Modules\Identity\Domain\Exceptions\LoginAttemptConflictException;
use App\Modules\Identity\Domain\TenantStaffContext;
use Illuminate\Http\Request;
use Illuminate\Database\QueryException;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use RuntimeException;

/** Registers server-side tenant session authority outside the tenant runtime role. */
final class TenantAuthoritySessionService implements TenantAuthorityRevoker
{
    /** @return array{attempt_hash: string, client_hash: string, host_hash: string} */
    public function attemptBinding(Request $request, string $retryKey, string $hostname): array
    {
        if (preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/D', $retryKey) !== 1) {
            throw new RuntimeException('Tenant login attempt key is invalid.');
        }
        $clientHash = $request->attributes->get('tenant_login_client_hash');
        if (! is_string($clientHash) || preg_match('/^[a-f0-9]{64}$/D', $clientHash) !== 1) {
            throw new RuntimeException('Tenant login client proof is unavailable.');
        }

        return [
            'attempt_hash' => $this->bindingHash('login-attempt', $retryKey),
            'client_hash' => $clientHash,
            'host_hash' => $this->bindingHash('login-host', strtolower($hostname)),
        ];
    }

    /** @param array{attempt_hash: string, client_hash: string, host_hash: string} $attempt
     *  @return array{generation: string, authenticated_at: int, disposition: string}
     */
    public function register(Request $request, TenantStaffContext $context, array $attempt): array
    {
        $generation = (string) Str::uuid7();
        $request->session()->put('identity.tenant_authority_generation', $generation);
        $connection = DB::connection('pgsql_tenant_auth');
        try {
            $result = $connection->selectOne(
                'SELECT * FROM public.core01_tenant_authority_register_attempt(?::uuid, ?::uuid, ?::uuid, ?::bigint, ?::bigint, ?, ?::uuid, ?::timestamptz, ?, ?, ?)',
                [$context->tenantId, $context->userId, $context->membershipId, $context->authVersion,
                    $context->authorizationVersion, $this->sessionHash($request, $generation), $generation,
                    now('UTC')->addSeconds(max(1, (int) config('identity.absolute_session_lifetime', 28800)))->toIso8601String(),
                    $attempt['attempt_hash'], $attempt['client_hash'], $attempt['host_hash']]
            );
        } catch (QueryException $exception) {
            if (($exception->errorInfo[0] ?? $exception->getCode()) === 'PZ409') {
                throw new LoginAttemptConflictException(previous: $exception);
            }
            throw $exception;
        }
        if (! is_object($result) || ! in_array($result->disposition ?? null, ['CREATED', 'REBOUND'], true)
            || ! is_string($result->authority_issued_at ?? null)) {
            throw new RuntimeException('Tenant authority attempt result is invalid.');
        }

        return [
            'generation' => $generation,
            'authenticated_at' => Carbon::parse($result->authority_issued_at, 'UTC')->getTimestamp(),
            'disposition' => $result->disposition,
        ];
    }

    public function revoke(Request $request): void
    {
        $identity = $this->snapshot($request);
        if ($identity === null) {
            return;
        }
        $this->revokeHash($identity['hash'], $identity['generation']);
    }

    /** @return array{hash: string, generation: string}|null */
    public function snapshot(Request $request): ?array
    {
        $generation = $request->session()->get('identity.tenant_authority_generation');
        if ($generation === null) {
            $stored = $request->session()->get('identity.tenant_staff');
            $generation = is_array($stored) ? ($stored['authority_generation'] ?? null) : null;
        }
        if (! is_string($generation) || ! Str::isUuid($generation)) {
            return null;
        }

        return ['hash' => $this->sessionHash($request, $generation), 'generation' => $generation];
    }

    public function revokeHash(string $sessionHash, string $generation): void
    {
        if (preg_match('/^[a-f0-9]{64}$/D', $sessionHash) !== 1 || ! Str::isUuid($generation)) {
            throw new RuntimeException('Tenant authority revocation identity is unavailable.');
        }
        DB::connection('pgsql_tenant_auth')->selectOne('SELECT public.core01_tenant_authority_revoke_session(?, ?::uuid)',
            [$sessionHash, $generation]);
    }

    public function sessionHash(Request $request, string $generation): string
    {
        if (! Str::isUuid($generation)) {
            throw new RuntimeException('Tenant authority session generation is unavailable.');
        }
        $key = $this->bindingKey();
        return hash_hmac('sha256', $request->session()->getId().'|'.$generation, $key);
    }

    private function bindingHash(string $domain, string $value): string
    {
        return hash_hmac('sha256', $domain."\0".$value, $this->bindingKey());
    }

    private function bindingKey(): string
    {
        $key = config('core_sql.session_binding_key');
        if (! is_string($key) || preg_match('/^[a-f0-9]{64}$/D', $key) !== 1) {
            throw new RuntimeException('Tenant authority session binding key is unavailable.');
        }
        return hex2bin($key);
    }
}
