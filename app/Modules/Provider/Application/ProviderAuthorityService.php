<?php

namespace App\Modules\Provider\Application;

use App\Modules\Provider\Domain\ProviderAccessException;
use App\Modules\Provider\Domain\ProviderContext;
use Illuminate\Database\QueryException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use RuntimeException;

/** Durable authority state issued only after the real Provider MFA flow. */
final class ProviderAuthorityService
{
    public function enabled(): bool
    {
        return (bool) config('core_sql.provider_authority_enabled');
    }

    public function registerSession(Request $request, ProviderContext $context): void
    {
        if (! $this->enabled()) {
            return;
        }
        $generation = (string) Str::uuid7();
        $request->session()->put('provider.authority_generation', $generation);
        $request->session()->forget('provider.authority_receipts');
        $this->issuer()->selectOne(
            'SELECT public.core01_provider_authority_register_session(?::uuid, ?::bigint, ?::bigint, ?, ?::uuid, ?::timestamptz)',
            [$context->providerUserId, $context->authVersion, $context->authorizationVersion,
                $this->sessionHash($request, $generation), $generation,
                now('UTC')->addSeconds((int) config('provider.absolute_session_seconds'))->toIso8601String()]
        );
    }

    public function recordStepUp(Request $request, ProviderContext $context): void
    {
        if (! $this->enabled()) {
            return;
        }
        $generation = $this->generation($request);
        $request->session()->forget('provider.authority_receipts');
        $this->issuer()->selectOne(
            'SELECT public.core01_provider_authority_record_stepup(?::uuid, ?::bigint, ?::bigint, ?, ?::uuid) AS id',
            [$context->providerUserId, $context->authVersion, $context->authorizationVersion,
                $this->sessionHash($request, $generation), $generation]
        );
    }

    /** @return array{token:string,session_hash:string} */
    public function obtainProvisionReceipt(Request $request, ProviderContext $context, string $idempotencyHash,
        string $intentDigest, string $payloadHash, string $passwordHash): array
    {
        if (! $this->enabled()) {
            throw new RuntimeException('Provider authority issuer is unavailable.');
        }
        $generation = $this->generation($request);
        $sessionHash = $this->sessionHash($request, $generation);
        $cacheKey = hash('sha256', $idempotencyHash.'|'.$intentDigest.'|'.$payloadHash);
        $cached = $request->session()->get('provider.authority_receipts.'.$cacheKey);
        if (is_array($cached) && is_string($cached['token'] ?? null)
            && is_numeric($cached['issued_at'] ?? null)
            && now('UTC')->timestamp - (int) $cached['issued_at'] < 85
            && preg_match('/^[a-f0-9]{64}$/D', $cached['token']) === 1) {
            return ['token' => $cached['token'], 'session_hash' => $sessionHash];
        }
        $token = bin2hex(random_bytes(32));
        try {
            $this->issuer()->selectOne(
                'SELECT public.core01_provider_authority_issue_receipt(?::uuid, ?::bigint, ?::bigint, ?, ?::uuid, ?, ?::uuid, ?, ?, ?, ?, ?) AS id',
                [$context->providerUserId, $context->authVersion, $context->authorizationVersion,
                    $sessionHash, $generation, 'company.provision', $context->requestId,
                    $idempotencyHash, $intentDigest, $payloadHash, $passwordHash, hash('sha256', $token)]
            );
        } catch (QueryException $exception) {
            $state = (string) ($exception->errorInfo[0] ?? $exception->getCode());
            if ($state === 'PZ403') {
                throw ProviderAccessException::stepUpRequired();
            }
            throw new RuntimeException('Provider authority issuer is unavailable.', previous: $exception);
        }
        $request->session()->put('provider.authority_receipts.'.$cacheKey, [
            'token' => $token,
            'issued_at' => now('UTC')->timestamp,
        ]);
        return ['token' => $token, 'session_hash' => $sessionHash];
    }

    public function sessionHash(Request $request, ?string $generation = null): string
    {
        $generation ??= $this->generation($request);
        $key = config('core_sql.session_binding_key');
        if (! is_string($key) || preg_match('/^[a-f0-9]{64}$/D', $key) !== 1) {
            throw new RuntimeException('Provider authority session binding key is unavailable.');
        }
        return hash_hmac('sha256', $request->session()->getId().'|'.$generation, hex2bin($key));
    }

    public function revokeCurrentSession(Request $request): void
    {
        if (! $this->enabled()) {
            return;
        }
        $generation = $request->session()->get('provider.authority_generation');
        if (! is_string($generation) || ! Str::isUuid($generation)) {
            return;
        }
        $this->issuer()->selectOne('SELECT public.core01_provider_authority_revoke_session(?, ?::uuid)',
            [$this->sessionHash($request, $generation), $generation]);
    }

    private function generation(Request $request): string
    {
        $generation = $request->session()->get('provider.authority_generation');
        if (! is_string($generation) || ! Str::isUuid($generation)) {
            throw ProviderAccessException::stepUpRequired();
        }
        return $generation;
    }

    private function issuer(): \Illuminate\Database\Connection
    {
        $connection = DB::connection('pgsql_provider_issuer');
        if ($connection->getDriverName() !== 'pgsql' || trim((string) $connection->getConfig('username')) === '') {
            throw new RuntimeException('Provider authority issuer is not configured.');
        }
        return $connection;
    }
}
