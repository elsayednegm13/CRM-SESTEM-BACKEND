<?php

namespace App\Modules\Tenancy\Http\Controllers;

use App\Modules\Identity\Application\TenantStaffRoleMutationService;
use App\Modules\Identity\Domain\TenantStaffContext;
use App\Modules\Tenancy\Domain\TenantAccessException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class TenantStaffRoleManagementController
{
    public function store(Request $request, TenantStaffRoleMutationService $service): JsonResponse
    {
        $context = $this->context($request);
        $input = $request->validate(['name' => ['required', 'string', 'max:160']]);
        $id = $service->createRole($context, $input['name']);
        return response()->json(['data' => ['id' => $id],
            'meta' => ['request_id' => $request->attributes->get('request_id')]], 201);
    }

    public function updateGrants(Request $request, string $role, TenantStaffRoleMutationService $service): JsonResponse
    {
        $context = $this->context($request);
        $input = $request->validate([
            'grants' => ['required', 'array'],
            'grants.*.permission' => ['required', 'string', 'max:100'],
            'grants.*.scope' => ['sometimes', 'nullable', 'string', 'max:16'],
        ]);
        $grants = array_map(fn ($g) => ['permission' => $g['permission'], 'scope' => $g['scope'] ?? null], $input['grants']);
        $service->updateRoleGrants($context, $role, $grants);
        return response()->json(['data' => ['status' => 'UPDATED'],
            'meta' => ['request_id' => $request->attributes->get('request_id')]]);
    }

    public function archive(Request $request, string $role, TenantStaffRoleMutationService $service): JsonResponse
    {
        $context = $this->context($request);
        $service->archiveRole($context, $role);
        return response()->json(['data' => ['status' => 'ARCHIVED'],
            'meta' => ['request_id' => $request->attributes->get('request_id')]]);
    }

    public function assign(Request $request, string $membership, TenantStaffRoleMutationService $service): JsonResponse
    {
        $context = $this->context($request);
        $input = $request->validate(['role_id' => ['required', 'uuid']]);
        $service->assignRole($context, $membership, $input['role_id']);
        return response()->json(['data' => ['status' => 'ASSIGNED'],
            'meta' => ['request_id' => $request->attributes->get('request_id')]], 201);
    }

    public function revoke(Request $request, string $membership, string $role, TenantStaffRoleMutationService $service): JsonResponse
    {
        $context = $this->context($request);
        $service->revokeRole($context, $membership, $role);
        return response()->json(['data' => ['status' => 'REVOKED'],
            'meta' => ['request_id' => $request->attributes->get('request_id')]]);
    }

    public function grantPermission(Request $request, string $membership, TenantStaffRoleMutationService $service): JsonResponse
    {
        $context = $this->context($request);
        $input = $request->validate([
            'permission' => ['required', 'string', 'max:100'],
            'scope' => ['sometimes', 'nullable', 'string', 'max:16'],
        ]);
        $service->grantPermission($context, $membership, $input['permission'], $input['scope'] ?? null);
        return response()->json(['data' => ['status' => 'GRANTED'],
            'meta' => ['request_id' => $request->attributes->get('request_id')]], 201);
    }

    public function revokePermission(Request $request, string $membership, string $permission,
        TenantStaffRoleMutationService $service): JsonResponse
    {
        $context = $this->context($request);
        $scope = $request->query('scope');
        $service->revokePermission($context, $membership, $permission, is_string($scope) ? $scope : null);
        return response()->json(['data' => ['status' => 'REVOKED'],
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
