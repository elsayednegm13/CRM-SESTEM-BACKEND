<?php

namespace App\Modules\Identity\Application;

use App\Modules\Identity\Domain\Exceptions\AuthRateLimitedException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;

final class AuthRateLimiter
{
    public function assertLoginAllowed(string $email, Request $request): void
    {
        $keys = $this->loginKeys($email, $request);
        $this->assertAllowed(
            $keys,
            (int) config('identity.login.max_failures'),
            (int) config('identity.login.ip_max_failures'),
        );
    }

    public function recordLoginFailure(string $email, Request $request): void
    {
        [$identityKey, $ipKey] = $this->loginKeys($email, $request);
        $decay = (int) config('identity.login.decay_seconds');
        RateLimiter::hit($identityKey, $decay);
        RateLimiter::hit($ipKey, $decay);
    }

    public function clearLoginIdentityFailures(string $email, Request $request): void
    {
        [$identityKey] = $this->loginKeys($email, $request);
        RateLimiter::clear($identityKey);
    }

    public function assertForgotAllowed(string $email, Request $request): void
    {
        $identity = $this->key('auth:forgot:identity-ip', $email.'|'.$request->ip());
        $ip = $this->key('auth:forgot:ip', (string) $request->ip());
        $this->assertAllowed(
            [$identity, $ip],
            (int) config('identity.forgot.max_attempts'),
            (int) config('identity.forgot.ip_max_attempts'),
        );
        RateLimiter::hit($identity, (int) config('identity.forgot.decay_seconds'));
        RateLimiter::hit($ip, (int) config('identity.forgot.decay_seconds'));
    }

    public function assertResetAllowed(string $email, Request $request): void
    {
        $key = $this->key('auth:reset:identity-ip', $email.'|'.$request->ip());
        $max = (int) config('identity.reset.max_attempts');
        if (RateLimiter::tooManyAttempts($key, $max)) {
            throw new AuthRateLimitedException(max(1, RateLimiter::availableIn($key)));
        }
        RateLimiter::hit($key, (int) config('identity.reset.decay_seconds'));
    }

    public function assertVerificationResendAllowed(string $userId, Request $request): void
    {
        $key = $this->key('auth:verify:identity-ip', $userId.'|'.$request->ip());
        $max = (int) config('identity.verification.max_resends');
        if (RateLimiter::tooManyAttempts($key, $max)) {
            throw new AuthRateLimitedException(max(1, RateLimiter::availableIn($key)));
        }
        RateLimiter::hit($key, (int) config('identity.verification.decay_seconds'));
    }

    /** @return array{string, string} */
    private function loginKeys(string $email, Request $request): array
    {
        return [
            $this->key('auth:login:identity-ip', $email.'|'.$request->ip()),
            $this->key('auth:login:ip', (string) $request->ip()),
        ];
    }

    /** @param array{string, string} $keys */
    private function assertAllowed(array $keys, int $identityLimit, int $ipLimit): void
    {
        [$identity, $ip] = $keys;
        $identityLimited = RateLimiter::tooManyAttempts($identity, $identityLimit);
        $ipLimited = RateLimiter::tooManyAttempts($ip, $ipLimit);
        if ($identityLimited || $ipLimited) {
            $wait = max(RateLimiter::availableIn($identity), RateLimiter::availableIn($ip), 1);
            throw new AuthRateLimitedException($wait);
        }
    }

    private function key(string $scope, string $value): string
    {
        return $scope.':'.hash('sha256', $value);
    }
}
