<?php

namespace App\Modules\Provider\Application;

use App\Modules\Provider\Domain\ProviderAccessException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;

final class ProviderRateLimiter
{
    public function assertLogin(string $email, Request $request): void
    {
        $this->assertKeys([$this->key('login:identity', $email.'|'.$request->ip()), $this->key('login:ip', (string) $request->ip())], [5, 50]);
    }

    public function failLogin(string $email, Request $request): void
    {
        $this->hit($this->key('login:identity', $email.'|'.$request->ip()));
        $this->hit($this->key('login:ip', (string) $request->ip()));
    }

    public function assertMfa(string $challengeId, Request $request): void
    {
        $this->assertKeys([$this->key('mfa:challenge', $challengeId.'|'.$request->ip()), $this->key('mfa:ip', (string) $request->ip())], [5, 30]);
    }

    public function failMfa(string $challengeId, Request $request): void
    {
        $this->hit($this->key('mfa:challenge', $challengeId.'|'.$request->ip()));
        $this->hit($this->key('mfa:ip', (string) $request->ip()));
    }

    public function assertStepUp(string $providerId, Request $request): void
    {
        $this->assertKeys([$this->key('step-up', $providerId.'|'.$request->ip())], [5]);
    }

    public function failStepUp(string $providerId, Request $request): void
    {
        $this->hit($this->key('step-up', $providerId.'|'.$request->ip()));
    }

    private function key(string $scope, string $subject): string
    {
        return 'provider:'.$scope.':'.hash('sha256', $subject);
    }

    private function hit(string $key): void
    {
        RateLimiter::hit($key, 900);
    }

    private function assertKeys(array $keys, array $limits): void
    {
        foreach ($keys as $index => $key) {
            if (RateLimiter::tooManyAttempts($key, $limits[$index])) {
                throw ProviderAccessException::rateLimited();
            }
        }
    }
}
