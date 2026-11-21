<?php

namespace App\Modules\Tenancy\Http\Controllers;

use App\Modules\Identity\Domain\TenantStaffContext;
use App\Modules\Tenancy\Application\LeadService;
use App\Modules\Tenancy\Domain\TenantAccessException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class LeadController
{
    public function index(Request $request, LeadService $service): JsonResponse
    {
        $context = $this->context($request);
        $input = $request->validate(['stage' => ['sometimes', 'nullable', 'string', 'max:20']]);
        return response()->json(['data' => $service->listLeads($context, $input['stage'] ?? null),
            'meta' => ['request_id' => $request->attributes->get('request_id')]]);
    }

    public function show(Request $request, string $lead, LeadService $service): JsonResponse
    {
        $context = $this->context($request);
        return response()->json(['data' => $service->getLead($context, $lead),
            'meta' => ['request_id' => $request->attributes->get('request_id')]]);
    }

    public function store(Request $request, LeadService $service): JsonResponse
    {
        $context = $this->context($request);
        $input = $request->validate([
            'name' => ['required', 'string', 'max:160'],
            'phone' => ['sometimes', 'nullable', 'string', 'max:32'],
            'email' => ['sometimes', 'nullable', 'email', 'max:254'],
            'city' => ['sometimes', 'nullable', 'string', 'max:100'],
            'country' => ['sometimes', 'nullable', 'string', 'max:100'],
            'source' => ['sometimes', 'nullable', 'string', 'max:100'],
            'campaign' => ['sometimes', 'nullable', 'string', 'max:160'],
            'interest_level' => ['sometimes', 'nullable', 'string', 'in:HOT,WARM,COLD'],
            'estimated_value_minor' => ['sometimes', 'nullable', 'integer', 'min:0'],
            'assigned_membership_id' => ['sometimes', 'nullable', 'uuid'],
        ]);
        return response()->json(['data' => $service->createLead($context, $input),
            'meta' => ['request_id' => $request->attributes->get('request_id')]], 201);
    }

    public function update(Request $request, string $lead, LeadService $service): JsonResponse
    {
        $context = $this->context($request);
        $input = $request->validate([
            'name' => ['sometimes', 'string', 'max:160'],
            'phone' => ['sometimes', 'nullable', 'string', 'max:32'],
            'email' => ['sometimes', 'nullable', 'email', 'max:254'],
            'city' => ['sometimes', 'nullable', 'string', 'max:100'],
            'country' => ['sometimes', 'nullable', 'string', 'max:100'],
            'source' => ['sometimes', 'nullable', 'string', 'max:100'],
            'campaign' => ['sometimes', 'nullable', 'string', 'max:160'],
            'interest_level' => ['sometimes', 'nullable', 'string', 'in:HOT,WARM,COLD'],
            'estimated_value_minor' => ['sometimes', 'nullable', 'integer', 'min:0'],
        ]);
        return response()->json(['data' => $service->updateLead($context, $lead, $input),
            'meta' => ['request_id' => $request->attributes->get('request_id')]]);
    }

    public function updateStage(Request $request, string $lead, LeadService $service): JsonResponse
    {
        $context = $this->context($request);
        $input = $request->validate(['stage' => ['required', 'string', 'max:20']]);
        return response()->json(['data' => $service->updateStage($context, $lead, $input['stage']),
            'meta' => ['request_id' => $request->attributes->get('request_id')]]);
    }

    public function assign(Request $request, string $lead, LeadService $service): JsonResponse
    {
        $context = $this->context($request);
        $input = $request->validate(['assigned_membership_id' => ['required', 'uuid']]);
        return response()->json(['data' => $service->assignLead($context, $lead, $input['assigned_membership_id']),
            'meta' => ['request_id' => $request->attributes->get('request_id')]]);
    }

    public function archive(Request $request, string $lead, LeadService $service): JsonResponse
    {
        $context = $this->context($request);
        $service->archiveLead($context, $lead);
        return response()->json(['data' => ['status' => 'ARCHIVED'],
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
