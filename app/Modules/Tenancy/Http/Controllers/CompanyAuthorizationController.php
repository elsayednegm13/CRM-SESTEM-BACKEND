<?php

namespace App\Modules\Tenancy\Http\Controllers;

use App\Modules\Identity\Application\TenantStaffEffectiveAuthorizationService;
use App\Modules\Identity\Domain\TenantStaffContext;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Auth\AuthenticationException;

final class CompanyAuthorizationController
{
    public function __invoke(Request $request, TenantStaffEffectiveAuthorizationService $authorization): JsonResponse
    {
        $context = $request->attributes->get('tenant_staff_context');
        if (! $context instanceof TenantStaffContext) {
            throw new AuthenticationException;
        }
        $permissions = $authorization->snapshot($context);

        return response()->json([
            'data' => [
                'membership_id' => $context->membershipId,
                'authorization_version' => $context->authorizationVersion,
                'permissions' => $permissions,
            ],
            'meta' => ['request_id' => $request->attributes->get('request_id')],
        ]);
    }
}
