<?php

namespace App\Modules\Identity\Application;

use App\Modules\Identity\Domain\Exceptions\AuthRateLimitedException;
use App\Modules\Identity\Domain\TenantHostContext;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;

final class TenantStaffRateLimiter
{
    public function assertLoginAllowed(TenantHostContext $host, string $email, Request $request): void
    {
        [$identity, $ip] = $this->keys($host, $email, $request);
        $maxIdentity = (int) config('identity.login.max_failures', 5);
        $maxIp = (int) config('identity.login.ip_max_failures', 100);
        if (RateLimiter::tooManyAttempts($identity, $maxIdentity) || RateLimiter::tooManyAttempts($ip, $maxIp)) {
            throw new AuthRateLimitedException(max(RateLimiter::availableIn($identity), RateLimiter::availableIn($ip), 1));
        }
    }

    public function recordFailure(TenantHostContext $host, string $email, Request $request): void
    {
        [$identity, $ip] = $this->keys($host, $email, $request);
        $decay = (int) config('identity.login.decay_seconds', 900);
        RateLimiter::hit($identity, $decay);
        RateLimiter::hit($ip, $decay);
    }

    public function clearIdentityFailures(TenantHostContext $host, string $email, Request $request): void
    {
        [$identity] = $this->keys($host, $email, $request);
        RateLimiter::clear($identity);
    }

    /** @return array{string,string} */
    private function keys(TenantHostContext $host, string $email, Request $request): array
    {
        $ip = (string) ($request->ip() ?? 'unknown');
        return [
            'auth:tenant-staff:identity-ip:'.hash('sha256', $host->tenantId.'|'.$email.'|'.$ip),
            'auth:tenant-staff:ip:'.hash('sha256', $ip),
        ];
    }
}
