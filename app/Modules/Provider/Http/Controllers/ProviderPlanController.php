<?php

namespace App\Modules\Provider\Http\Controllers;

use App\Modules\Provider\Application\PlanCatalogService;
use App\Modules\Provider\Domain\ProviderContext;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class ProviderPlanController
{
    public function index(Request $request, PlanCatalogService $service): JsonResponse
    {
        $context = $this->context($request);
        return response()->json(['data' => $service->listPlans($context),
            'meta' => ['request_id' => $context->requestId]])
            ->withHeaders(['Cache-Control' => 'private, no-store', 'Pragma' => 'no-cache']);
    }

    public function store(Request $request, PlanCatalogService $service): JsonResponse
    {
        $context = $this->context($request);
        $input = $request->validate([
            'code' => ['required', 'string', 'max:40'],
            'display_name' => ['required', 'string', 'max:120'],
            'price_monthly_minor' => ['required', 'integer', 'min:1'],
            'price_annual_minor' => ['required', 'integer', 'min:1'],
            'limits' => ['sometimes', 'array'],
        ]);
        $result = $service->createPlan($context, $input);
        return response()->json(['data' => $result,
            'meta' => ['request_id' => $context->requestId]], 201)->header('Cache-Control', 'no-store');
    }

    public function update(Request $request, string $plan, PlanCatalogService $service): JsonResponse
    {
        $context = $this->context($request);
        $input = $request->validate([
            'display_name' => ['sometimes', 'string', 'max:120'],
            'price_monthly_minor' => ['sometimes', 'integer', 'min:1'],
            'price_annual_minor' => ['sometimes', 'integer', 'min:1'],
            'status' => ['sometimes', 'string', 'in:ACTIVE,RETIRED'],
        ]);
        $service->updatePlan($context, $plan, $input);
        return response()->json(['data' => ['status' => 'UPDATED'],
            'meta' => ['request_id' => $context->requestId]])->header('Cache-Control', 'no-store');
    }

    public function setLimit(Request $request, string $plan, PlanCatalogService $service): JsonResponse
    {
        $context = $this->context($request);
        $input = $request->validate([
            'key' => ['required', 'string', 'max:64'],
            'value' => ['nullable', 'integer', 'min:0'],
        ]);
        $service->setLimit($context, $plan, $input['key'], $input['value'] ?? null);
        return response()->json(['data' => ['status' => 'UPDATED'],
            'meta' => ['request_id' => $context->requestId]])->header('Cache-Control', 'no-store');
    }

    private function context(Request $request): ProviderContext
    {
        $context = $request->attributes->get('provider_context');
        abort_unless($context instanceof ProviderContext, 401);
        return $context;
    }
}
