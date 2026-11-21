<?php

namespace App\Modules\Tenancy\Http\Controllers;

use App\Modules\Identity\Application\TenantStaffAccountService;
use App\Modules\Identity\Domain\TenantStaffContext;
use App\Modules\Tenancy\Domain\TenantAccessException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class TenantStaffMemberController
{
    public function index(Request $request, TenantStaffAccountService $service): JsonResponse
    {
        $context = $this->context($request);
        return response()->json(['data' => $service->listStaff($context),
            'meta' => ['request_id' => $request->attributes->get('request_id')]]);
    }

    public function store(Request $request, TenantStaffAccountService $service): JsonResponse
    {
        $context = $this->context($request);
        $input = $request->validate([
            'email' => ['required', 'email', 'max:254'],
            'display_name' => ['required', 'string', 'max:160'],
            'initial_password' => ['required', 'string', 'min:12', 'max:1024'],
            'role_id' => ['sometimes', 'nullable', 'uuid'],
        ]);
        $result = $service->createStaffMember($context, $input['email'], $input['display_name'],
            $input['initial_password'], $input['role_id'] ?? null);
        return response()->json(['data' => $result,
            'meta' => ['request_id' => $request->attributes->get('request_id')]], 201);
    }

    public function disable(Request $request, string $membership, TenantStaffAccountService $service): JsonResponse
    {
        $context = $this->context($request);
        $service->disableStaffMember($context, $membership);
        return response()->json(['data' => ['status' => 'SUSPENDED'],
            'meta' => ['request_id' => $request->attributes->get('request_id')]]);
    }

    public function reactivate(Request $request, string $membership, TenantStaffAccountService $service): JsonResponse
    {
        $context = $this->context($request);
        $service->reactivateStaffMember($context, $membership);
        return response()->json(['data' => ['status' => 'ACTIVE'],
            'meta' => ['request_id' => $request->attributes->get('request_id')]]);
    }

    private function context(Request $request): TenantStaffContext
    {
        $context = $request->attributes->get('tenant_staff_context');
        if (! $context instanceof TenantStaffContext) {
            throw TenantAccessException::contextRequired();
        }
        return $context;
    }
}
