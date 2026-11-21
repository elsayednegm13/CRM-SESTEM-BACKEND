<?php

namespace App\Modules\Tenancy\Http\Controllers;

use App\Modules\Tenancy\Application\TenantAuthorizationService;
use App\Modules\Tenancy\Domain\TenantAccessException;
use App\Modules\Tenancy\Domain\TenantContext;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class CompanyRolesController
{
    public function __invoke(Request $request, TenantAuthorizationService $authorization): JsonResponse
    {
        $context = $request->attributes->get('tenant_context');
        if (! $context instanceof TenantContext) {
            throw TenantAccessException::contextRequired();
        }
        return response()->json([
            'data' => ['roles' => $authorization->listRoles($context)],
            'meta' => ['request_id' => $context->requestId],
        ]);
    }
}
