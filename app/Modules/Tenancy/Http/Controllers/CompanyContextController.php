<?php

namespace App\Modules\Tenancy\Http\Controllers;

use App\Modules\Identity\Domain\TenantHostContext;
use App\Modules\Identity\Domain\TenantStaffContext;
use App\Modules\Identity\Infrastructure\Persistence\TenantStaffUser;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class CompanyContextController
{
    public function __invoke(Request $request): JsonResponse
    {
        $host = $request->attributes->get('tenant_host_context');
        $context = $request->attributes->get('tenant_staff_context');
        $staff = $request->user('tenant_staff');

        if (! $host instanceof TenantHostContext
            || ! $context instanceof TenantStaffContext
            || ! $staff instanceof TenantStaffUser
            || ! hash_equals($host->tenantId, $context->tenantId)
            || ! hash_equals($host->hostname, $context->hostname)
            || ! hash_equals($context->tenantId, (string) $staff->tenant_id)
            || ! hash_equals($context->userId, (string) $staff->getAuthIdentifier())
            || $staff->status !== 'ACTIVE'
            || (int) $staff->auth_version !== $context->authVersion) {
            throw new AuthenticationException;
        }

        return response()->json([
            'data' => [
                'company' => [
                    'id' => $host->tenantId,
                    'slug' => $host->tenantSlug,
                    'status' => 'ACTIVE',
                ],
                'staff' => [
                    'id' => (string) $staff->getAuthIdentifier(),
                    'email' => $staff->display_email,
                    'name' => $staff->display_name,
                    'status' => 'ACTIVE',
                ],
                'membership' => [
                    'id' => $context->membershipId,
                    'status' => 'ACTIVE',
                    'authorization_version' => $context->authorizationVersion,
                ],
            ],
            'meta' => ['request_id' => $request->attributes->get('request_id')],
        ]);
    }
}
