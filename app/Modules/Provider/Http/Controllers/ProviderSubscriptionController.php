<?php

namespace App\Modules\Provider\Http\Controllers;

use App\Modules\Provider\Application\TenantSubscriptionService;
use App\Modules\Provider\Domain\ProviderContext;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class ProviderSubscriptionController
{
    public function show(Request $request, string $tenant, TenantSubscriptionService $service): JsonResponse
    {
        $context = $this->context($request);
        return response()->json(['data' => $service->getSubscription($context, $tenant),
            'meta' => ['request_id' => $context->requestId]])
            ->withHeaders(['Cache-Control' => 'private, no-store', 'Pragma' => 'no-cache']);
    }

    public function store(Request $request, string $tenant, TenantSubscriptionService $service): JsonResponse
    {
        $context = $this->context($request);
        $input = $request->validate([
            'plan_id' => ['required', 'uuid'],
            'billing_cycle' => ['required', 'string', 'in:MONTHLY,ANNUAL'],
        ]);
        $result = $service->assignPlan($context, $tenant, $input['plan_id'], $input['billing_cycle']);
        return response()->json(['data' => $result,
            'meta' => ['request_id' => $context->requestId]], 201)->header('Cache-Control', 'no-store');
    }

    public function destroy(Request $request, string $tenant, TenantSubscriptionService $service): JsonResponse
    {
        $context = $this->context($request);
        $service->cancelSubscription($context, $tenant);
        return response()->json(['data' => ['status' => 'CANCELLED'],
            'meta' => ['request_id' => $context->requestId]])->header('Cache-Control', 'no-store');
    }

    public function setLimitOverride(Request $request, string $tenant, TenantSubscriptionService $service): JsonResponse
    {
        $context = $this->context($request);
        $input = $request->validate([
            'key' => ['required', 'string', 'max:64'],
            'value' => ['nullable', 'integer', 'min:0'],
            'reason' => ['required', 'string', 'max:500'],
        ]);
        $service->setLimitOverride($context, $tenant, $input['key'], $input['value'] ?? null, $input['reason']);
        return response()->json(['data' => ['status' => 'UPDATED'],
            'meta' => ['request_id' => $context->requestId]])->header('Cache-Control', 'no-store');
    }

    public function removeLimitOverride(Request $request, string $tenant, string $key,
        TenantSubscriptionService $service): JsonResponse
    {
        $context = $this->context($request);
        $service->removeLimitOverride($context, $tenant, $key);
        return response()->json(['data' => ['status' => 'REMOVED'],
            'meta' => ['request_id' => $context->requestId]])->header('Cache-Control', 'no-store');
    }

    private function context(Request $request): ProviderContext
    {
        $context = $request->attributes->get('provider_context');
        abort_unless($context instanceof ProviderContext, 401);
        return $context;
    }
}
