<?php

namespace App\Modules\Identity\Application;

use App\Modules\Identity\Domain\Exceptions\InvalidCredentialsException;
use App\Modules\Identity\Domain\TenantHostContext;
use App\Modules\Identity\Domain\TenantStaffContext;
use App\Modules\Identity\Infrastructure\Persistence\TenantStaffUser;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Throwable;

final class TenantStaffLoginService implements TenantAuthorityAuthenticator
{
    public function __construct(
        private readonly TenantStaffCredentialLookup $credentials,
        private readonly TenantStaffContextGuard $contexts,
        private readonly TenantStaffRateLimiter $limits,
        private readonly AuthSecurityEvents $events,
        private readonly TenantAuthoritySessionService $authoritySessions,
    ) {
    }

    public function authenticate(TenantHostContext $host, string $email, string $password, string $retryKey, Request $request): TenantStaffUser
    {
        $this->limits->assertLoginAllowed($host, $email, $request);
        $lookup = $this->credentials->forHostAndEmail($host, $email);
        $passwordHash = is_string($lookup?->password_hash ?? null)
            ? $lookup->password_hash
            : config('identity.dummy_password_hash');
        $passwordMatches = is_string($passwordHash)
            && str_starts_with($passwordHash, '$argon2id$')
            && Hash::driver('argon2id')->check($password, $passwordHash);

        if (! $lookup || ! $passwordMatches) {
            $this->limits->recordFailure($host, $email, $request);
            $this->events->emit('TenantStaffLoginFailed', $request, null, 'invalid_credentials');
            throw new InvalidCredentialsException;
        }

        $candidate = new TenantStaffContext($host->tenantId, $host->hostname,
            (string) $lookup->staff_user_id, (string) $lookup->membership_id,
            (int) $lookup->auth_version, (int) $lookup->membership_authorization_version);
        // Capture the incoming pre-auth session before SessionGuard rotates it.
        // The raw retry key and raw session id never leave this process.
        $attempt = $this->authoritySessions->attemptBinding($request, $retryKey, $host->hostname);
        try {
            // The credential lookup is the restricted pre-auth authority. Build only
            // the principal SessionGuard needs to rotate the session ID; tenant data
            // access still waits for the durable v3 authority registered below.
            $principal = new TenantStaffUser;
            $principal->setRawAttributes([
                'id' => (string) $lookup->staff_user_id,
                'tenant_id' => (string) $lookup->tenant_id,
                'canonical_email' => (string) $lookup->canonical_email,
                'display_email' => (string) $lookup->display_email,
                'display_name' => (string) $lookup->display_name,
                'password_hash' => (string) $lookup->password_hash,
                'status' => 'ACTIVE',
                'auth_version' => (int) $lookup->auth_version,
            ], true);
            Auth::guard('tenant_staff')->login($principal);

            // SessionGuard::login has now performed the single session-ID rotation.
            // Register once, against that final ID, then prove the full v3 tuple.
            $registration = $this->authoritySessions->register($request, $candidate, $attempt);
            $generation = $registration['generation'];
            $request->attributes->set('tenant_staff_authority_cleanup', [
                'hash' => $this->authoritySessions->sessionHash($request, $generation),
                'generation' => $generation,
            ]);
            $context = $this->contexts->activateAfterCredentialCheck($host, $lookup, $request, $generation);
            $verifiedPrincipal = Auth::guard('tenant_staff')->getProvider()->retrieveById($context->userId);
            if (! $verifiedPrincipal instanceof TenantStaffUser) {
                throw new InvalidCredentialsException;
            }
            Auth::guard('tenant_staff')->setUser($verifiedPrincipal);
            $principal = $verifiedPrincipal;
            $this->limits->clearIdentityFailures($host, $email, $request);
            $request->session()->put('identity.tenant_staff', [
                'tenant_id' => $context->tenantId, 'hostname' => $context->hostname,
                'user_id' => $context->userId, 'membership_id' => $context->membershipId,
                'auth_version' => $context->authVersion,
                'authorization_version' => $context->authorizationVersion,
                // Retries preserve the original PostgreSQL authority start time;
                // they cannot extend the absolute session lifetime.
                'authenticated_at' => $registration['authenticated_at'],
                'authority_generation' => $generation,
            ]);
            $request->attributes->set('tenant_staff_context', $context);
            $request->attributes->set('tenant_staff_new_authority', true);
            $this->events->emit('TenantStaffLoginSucceeded', $request, $context->userId);
        } catch (Throwable $exception) {
            // Durable authority cleanup is intentionally deferred to the request
            // middleware, after it has rolled back the runtime transaction.
            Auth::guard('tenant_staff')->logout();
            $request->session()->forget('identity.tenant_staff');
            $request->session()->forget('identity.tenant_authority_generation');
            throw $exception;
        }

        return $principal;
    }
}
