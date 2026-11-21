<?php

namespace App\Modules\Identity\Http\Middleware;

use App\Modules\Tenancy\Domain\TenantAccessException;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpFoundation\Response;

final class RejectCompanyContextSelectors
{
    private const SELECTOR_HEADERS = [
        'X-Tenant-ID',
        'X-Company-ID',
        'X-Membership-ID',
        'X-Member-ID',
        'X-Actor-ID',
        'X-Role-ID',
        'X-Permission',
        'X-Capability',
    ];

    private const SELECTOR_FIELDS = [
        'tenant_id',
        'tenant_slug',
        'company_id',
        'company_slug',
        'membership_id',
        'member_id',
        'staff_user_id',
        'user_id',
        'actor_id',
        'role_id',
        'role',
        'permission',
        'permission_key',
        'permissions',
        'grant',
        'grants',
        'capability',
        'capabilities',
        'scope',
        'authorization_version',
    ];

    public function handle(Request $request, Closure $next): Response
    {
        if (! $request->routeIs('api.v1.company.context', 'api.v1.company.authorization')) {
            return $next($request);
        }

        foreach (self::SELECTOR_HEADERS as $header) {
            if ($request->headers->has($header)) {
                throw TenantAccessException::selectorNotAllowed();
            }
        }

        $field = $this->findSelector($request->all());
        if ($field !== null) {
            throw ValidationException::withMessages([
                $field => ['This field is not accepted.'],
            ]);
        }

        return $next($request);
    }

    private function findSelector(array $input): ?string
    {
        foreach ($input as $key => $value) {
            if (is_string($key)) {
                $normalized = strtolower(str_replace('-', '_', $key));
                if (in_array($normalized, self::SELECTOR_FIELDS, true)) {
                    return $normalized;
                }
            }

            if (is_array($value) && ($nested = $this->findSelector($value)) !== null) {
                return $nested;
            }
        }

        return null;
    }
}
