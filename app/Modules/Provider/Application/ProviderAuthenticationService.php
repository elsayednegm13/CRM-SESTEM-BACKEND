<?php

namespace App\Modules\Provider\Application;

use App\Modules\Identity\Domain\EmailAddressNormalizer;
use App\Modules\Provider\Domain\ProviderAccessException;
use App\Modules\Provider\Domain\ProviderContext;
use App\Modules\Provider\Infrastructure\Persistence\ProviderDatabaseContext;
use App\Modules\Provider\Infrastructure\Persistence\ProviderUser;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use InvalidArgumentException;

final class ProviderAuthenticationService
{
    public function __construct(
        private readonly EmailAddressNormalizer $emails,
        private readonly ProviderRateLimiter $limits,
        private readonly ProviderMfaService $mfa,
        private readonly ProviderDatabaseContext $dbContext,
        private readonly ProviderAuthorityService $authority,
    ) {}

    public function login(Request $request, string $rawEmail, string $password): string
    {
        try {
            $email = $this->emails->normalize($rawEmail);
        } catch (InvalidArgumentException) {
            $email = hash('sha256', $rawEmail).'@invalid.local';
        }
        $this->limits->assertLogin($email, $request);
        $user = ProviderUser::query()->where('email', $email)->first([
            'id', 'email', 'password', 'status', 'email_verified_at', 'auth_version', 'mfa_enrolled_at',
        ]);
        $hash = $user?->password ?? config('identity.dummy_password_hash');
        $valid = is_string($hash) && Hash::check($password, $hash);
        if (! $user || ! $valid || $user->status !== 'ACTIVE' || $user->email_verified_at === null) {
            $this->limits->failLogin($email, $request);
            throw ProviderAccessException::invalidCredentials();
        }
        // Re-login rotates the PHP session. Revoke any old durable authority
        // before its generation and session id are discarded.
        $this->authority->revokeCurrentSession($request);
        Auth::guard('provider')->logout();
        $request->session()->forget(['provider.pending', 'provider.settings_mfa', 'provider.authenticated_at', 'provider.auth_version', 'provider.step_up', 'provider.authority_generation', 'provider.authority_receipts']);
        $request->session()->regenerate();
        $request->session()->put('provider.pending', [
            'provider_id' => $user->getKey(), 'auth_version' => $user->auth_version,
            'challenge_id' => (string) Str::uuid7(), 'expires_at' => now('UTC')->timestamp + (int) config('provider.pending_seconds'),
            'attempts' => 0,
        ]);
        // Authority issuance is intentionally post-MFA: PostgreSQL requires an
        // enrolled factor before the issuer may register a durable session.
        return $user->mfa_enrolled_at === null ? 'MFA_ENROLLMENT_REQUIRED' : 'MFA_REQUIRED';
    }

    /** @return array{secret:string,otpauth_uri:string} */
    public function startEnrollment(Request $request): array
    {
        [$pending, $user] = $this->pending($request);
        if ($user->mfa_enrolled_at !== null) {
            throw ProviderAccessException::mfaRequired();
        }
        $setup = $this->mfa->startEnrollment($user->email);
        $pending['enrollment_secret'] = Crypt::encryptString($setup['secret']);
        $request->session()->put('provider.pending', $pending);
        return $setup;
    }

    /** Authenticated Security Settings enrollment; distinct from login pending MFA. */
    public function startSettingsEnrollment(Request $request, ProviderContext $context, string $password): array
    {
        $this->limits->assertStepUp($context->providerUserId, $request);
        $user = ProviderUser::query()->whereKey($context->providerUserId)->first(['id', 'email', 'password', 'status', 'auth_version', 'mfa_enrolled_at']);
        if (! $user || $user->status !== 'ACTIVE' || $user->auth_version !== $context->authVersion
            || $user->mfa_enrolled_at !== null || ! Hash::check($password, $user->password)) {
            $this->limits->failStepUp($context->providerUserId, $request);
            throw ProviderAccessException::authRequired();
        }
        $setup = $this->mfa->startEnrollment($user->email);
        $request->session()->put('provider.settings_mfa', [
            'provider_id' => $user->getKey(), 'auth_version' => $user->auth_version,
            'challenge_id' => (string) Str::uuid7(), 'expires_at' => now('UTC')->timestamp + 300,
            'session_id' => $request->session()->getId(), 'secret' => Crypt::encryptString($setup['secret']),
        ]);
        return $setup;
    }

    /** @return list<string> */
    public function confirmSettingsEnrollment(Request $request, ProviderContext $context, string $code): array
    {
        $pending = $request->session()->get('provider.settings_mfa');
        if (! is_array($pending) || ($pending['provider_id'] ?? null) !== $context->providerUserId
            || ($pending['auth_version'] ?? null) !== $context->authVersion
            || ($pending['session_id'] ?? null) !== $request->session()->getId()
            || ! is_numeric($pending['expires_at'] ?? null) || now('UTC')->timestamp >= (int) $pending['expires_at']
            || ! is_string($pending['secret'] ?? null)) {
            $request->session()->forget('provider.settings_mfa');
            throw ProviderAccessException::authRequired();
        }
        $this->limits->assertMfa((string) $pending['challenge_id'], $request);
        $secret = Crypt::decryptString($pending['secret']);
        $counter = $this->mfa->matchingCounter($secret, $code);
        if ($counter === null) {
            $this->limits->failMfa((string) $pending['challenge_id'], $request);
            throw ProviderAccessException::mfaInvalid();
        }
        $codes = $this->dbContext->run($context->providerUserId, function ($connection) use ($context, $secret, $counter): array {
            $locked = $connection->table('provider_users')->where('id', $context->providerUserId)->lockForUpdate()
                ->first(['status', 'auth_version', 'mfa_enrolled_at']);
            if (! $locked || $locked->status !== 'ACTIVE' || $locked->auth_version != $context->authVersion || $locked->mfa_enrolled_at !== null) {
                throw ProviderAccessException::unavailable();
            }
            $codes = $this->mfa->enroll($connection, $context->providerUserId, $secret, $counter, $context->requestId);
            $connection->table('provider_users')->where('id', $context->providerUserId)->update([
                'mfa_enrolled_at' => now('UTC'), 'auth_version' => $context->authVersion + 1, 'updated_at' => now('UTC'),
            ]);
            return $codes;
        });
        $request->session()->forget('provider.settings_mfa');
        $this->logout($request);
        return $codes;
    }

    /** @return list<string> */
    public function confirmEnrollment(Request $request, string $code): array
    {
        [$pending, $user] = $this->pending($request);
        if ($user->mfa_enrolled_at !== null || ! is_string($pending['enrollment_secret'] ?? null)) {
            throw ProviderAccessException::mfaRequired();
        }
        $this->limits->assertMfa($pending['challenge_id'], $request);
        $secret = Crypt::decryptString($pending['enrollment_secret']);
        $counter = $this->mfa->matchingCounter($secret, $code);
        if ($counter === null) {
            $this->failPending($request, $pending);
            throw ProviderAccessException::mfaInvalid();
        }
        $codes = $this->dbContext->run($user->getKey(), function ($connection) use ($user, $secret, $counter, $request) {
            $locked = $connection->table('provider_users')->where('id', $user->getKey())->lockForUpdate()
                ->first(['status', 'email_verified_at', 'auth_version', 'mfa_enrolled_at']);
            if (! $locked || $locked->status !== 'ACTIVE' || $locked->email_verified_at === null
                || $locked->auth_version != $user->auth_version || $locked->mfa_enrolled_at !== null) {
                throw ProviderAccessException::unavailable();
            }
            $codes = $this->mfa->enroll($connection, $user->getKey(), $secret, $counter,
                (string) $request->attributes->get('request_id'));
            $connection->table('provider_users')->where('id', $user->getKey())
                ->update(['mfa_enrolled_at' => now('UTC'), 'last_login_at' => now('UTC'), 'updated_at' => now('UTC')]);
            return $codes;
        });
        $this->completeLogin($request, $this->refreshForSession($user));
        return $codes;
    }

    public function verify(Request $request, string $code): void
    {
        [$pending, $user] = $this->pending($request);
        if ($user->mfa_enrolled_at === null) {
            throw ProviderAccessException::mfaRequired();
        }
        $this->limits->assertMfa($pending['challenge_id'], $request);
        try {
            $this->dbContext->run($user->getKey(), function ($connection) use ($user, $code, $request): void {
                $locked = $connection->table('provider_users')->where('id', $user->getKey())->lockForUpdate()
                    ->first(['status', 'email_verified_at', 'auth_version', 'mfa_enrolled_at']);
                if (! $locked || $locked->status !== 'ACTIVE' || $locked->email_verified_at === null
                    || $locked->auth_version != $user->auth_version || $locked->mfa_enrolled_at === null) {
                    throw ProviderAccessException::unavailable();
                }
                $this->mfa->consumeFactor($connection, $user->getKey(), $code,
                    (string) $request->attributes->get('request_id'));
                $connection->table('provider_users')->where('id', $user->getKey())
                    ->update(['last_login_at' => now('UTC'), 'updated_at' => now('UTC')]);
            });
        } catch (ProviderAccessException $exception) {
            if (in_array($exception->safeCode, ['PROVIDER_MFA_INVALID', 'PROVIDER_MFA_REPLAYED'], true)) {
                $this->failPending($request, $pending);
            }
            throw $exception;
        }
        $this->completeLogin($request, $this->refreshForSession($user));
    }

    public function stepUp(Request $request, ProviderContext $context, string $password, string $code): void
    {
        $this->limits->assertStepUp($context->providerUserId, $request);
        $user = ProviderUser::query()->whereKey($context->providerUserId)->first(['id', 'password']);
        if (! $user || ! Hash::check($password, $user->password)) {
            $this->limits->failStepUp($context->providerUserId, $request);
            throw ProviderAccessException::invalidCredentials();
        }
        try {
            $this->dbContext->run($context->providerUserId, function ($connection) use ($context, $code): void {
                $locked = $connection->table('provider_users')->where('id', $context->providerUserId)
                    ->lockForUpdate()->first(['status', 'auth_version']);
                if (! $locked || $locked->status !== 'ACTIVE' || $locked->auth_version != $context->authVersion) {
                    throw ProviderAccessException::authRequired();
                }
                $this->mfa->consumeFactor($connection, $context->providerUserId, $code, $context->requestId);
            });
        } catch (ProviderAccessException $exception) {
            $this->limits->failStepUp($context->providerUserId, $request);
            throw $exception;
        }
        $this->authority->recordStepUp($request, $context);
        $this->setStepUp($request, $context->providerUserId, $context->authVersion);
    }

    public function logout(Request $request): void
    {
        try {
            $this->authority->revokeCurrentSession($request);
        } finally {
            // A failed server-side revoke must remain visible to the caller, but
            // it must not leave the browser's local Provider session usable.
            Auth::guard('provider')->logout();
            $request->session()->forget(['provider.pending', 'provider.settings_mfa', 'provider.authenticated_at', 'provider.auth_version', 'provider.step_up', 'provider.authority_generation', 'provider.authority_receipts']);
            // Rotate the shared session; a coexisting tenant guard may remain authenticated.
            $request->session()->regenerate();
        }
    }

    /** @return array{array<string,mixed>,ProviderUser} */
    private function pending(Request $request): array
    {
        $pending = $request->session()->get('provider.pending');
        if (! is_array($pending) || ! Str::isUuid((string) ($pending['provider_id'] ?? ''))
            || ! Str::isUuid((string) ($pending['challenge_id'] ?? ''))
            || ! is_numeric($pending['auth_version'] ?? null)
            || ! is_numeric($pending['expires_at'] ?? null)
            || ! is_int($pending['attempts'] ?? null)
            || $pending['attempts'] >= (int) config('provider.max_mfa_attempts')
            || now('UTC')->timestamp >= (int) $pending['expires_at']) {
            $request->session()->forget('provider.pending');
            throw ProviderAccessException::mfaRequired();
        }
        $user = ProviderUser::query()->whereKey($pending['provider_id'])->first([
            'id', 'email', 'status', 'email_verified_at', 'auth_version', 'mfa_enrolled_at',
        ]);
        if (! $user || $user->status !== 'ACTIVE' || $user->email_verified_at === null
            || $user->auth_version !== (int) $pending['auth_version']) {
            $request->session()->forget('provider.pending');
            throw ProviderAccessException::mfaRequired();
        }
        return [$pending, $user];
    }

    private function failPending(Request $request, array $pending): void
    {
        $this->limits->failMfa($pending['challenge_id'], $request);
        $pending['attempts']++;
        if ($pending['attempts'] >= (int) config('provider.max_mfa_attempts')) {
            $request->session()->forget('provider.pending');
        } else {
            $request->session()->put('provider.pending', $pending);
        }
    }

    private function completeLogin(Request $request, ProviderUser $user): void
    {
        Auth::guard('provider')->login($user);
        $request->session()->regenerate();
        $request->session()->forget('provider.pending');
        $request->session()->put('provider.auth_version', $user->auth_version);
        $request->session()->put('provider.authenticated_at', now('UTC')->timestamp);
        $this->authority->registerSession($request, new ProviderContext($user->getKey(), $user->auth_version,
            $user->authorization_version, (string) $request->attributes->get('request_id'), now('UTC')->timestamp, null));
    }

    private function refreshForSession(ProviderUser $user): ?ProviderUser
    {
        return ProviderUser::query()->whereKey($user->getKey())->useWritePdo()
            ->first(['id', 'auth_version', 'authorization_version']);
    }

    private function setStepUp(Request $request, string $providerId, int $authVersion): void
    {
        $request->session()->put('provider.step_up', [
            'provider_id' => $providerId, 'auth_version' => $authVersion,
            'verified_at' => now('UTC')->timestamp,
            'expires_at' => now('UTC')->timestamp + (int) config('provider.step_up_seconds'),
        ]);
    }
}
