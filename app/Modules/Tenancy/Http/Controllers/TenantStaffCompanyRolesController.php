<?php

namespace App\Modules\Tenancy\Http\Controllers;

use App\Modules\Identity\Application\TenantStaffAuthorizationService;
use App\Modules\Identity\Domain\TenantStaffContext;
use App\Modules\Tenancy\Domain\TenantAccessException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class TenantStaffCompanyRolesController
{
    public function __invoke(Request $request, TenantStaffAuthorizationService $authorization): JsonResponse
    {
        $context = $request->attributes->get('tenant_staff_context');
        if (! $context instanceof TenantStaffContext) {
            throw TenantAccessException::contextRequired();
        }

        return response()->json([
            'data' => ['roles' => $authorization->listRoles($context)],
            'meta' => ['request_id' => $request->attributes->get('request_id')],
        ]);
    }
}
