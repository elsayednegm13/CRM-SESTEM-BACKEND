<?php

namespace App\Modules\Provider\Http\Controllers;

use App\Modules\Provider\Application\ProviderTeamService;
use App\Modules\Provider\Domain\ProviderContext;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class ProviderTeamController
{
    public function index(Request $request, ProviderTeamService $service): JsonResponse
    {
        $context = $this->context($request);
        return response()->json(['data' => $service->listTeam($context),
            'meta' => ['request_id' => $context->requestId]])
            ->withHeaders(['Cache-Control' => 'private, no-store', 'Pragma' => 'no-cache']);
    }

    public function store(Request $request, ProviderTeamService $service): JsonResponse
    {
        $context = $this->context($request);
        $input = $request->validate(['email' => ['required', 'email', 'max:254']]);
        $result = $service->createMember($context, $input['email']);
        return response()->json(['data' => $result,
            'meta' => ['request_id' => $context->requestId]], 201)->header('Cache-Control', 'no-store');
    }

    public function grant(Request $request, string $provider, ProviderTeamService $service): JsonResponse
    {
        $context = $this->context($request);
        $input = $request->validate(['capability_key' => ['required', 'string', 'max:64']]);
        $service->grantCapability($context, $provider, $input['capability_key']);
        return response()->json(['data' => ['status' => 'GRANTED'],
            'meta' => ['request_id' => $context->requestId]])->header('Cache-Control', 'no-store');
    }

    public function revoke(Request $request, string $provider, string $capability,
        ProviderTeamService $service): JsonResponse
    {
        $context = $this->context($request);
        $service->revokeCapability($context, $provider, $capability);
        return response()->json(['data' => ['status' => 'REVOKED'],
            'meta' => ['request_id' => $context->requestId]])->header('Cache-Control', 'no-store');
    }

    public function status(Request $request, string $provider, ProviderTeamService $service): JsonResponse
    {
        $context = $this->context($request);
        $input = $request->validate(['status' => ['required', 'string', 'in:ACTIVE,DISABLED']]);
        $service->setStatus($context, $provider, $input['status']);
        return response()->json(['data' => ['status' => $input['status']],
            'meta' => ['request_id' => $context->requestId]])->header('Cache-Control', 'no-store');
    }

    private function context(Request $request): ProviderContext
    {
        $context = $request->attributes->get('provider_context');
        abort_unless($context instanceof ProviderContext, 401);
        return $context;
    }
}
