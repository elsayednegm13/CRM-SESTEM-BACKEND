<?php

namespace App\Modules\Provider\Http\Controllers;

use App\Modules\Provider\Application\ProviderBootstrapService;
use App\Modules\Provider\Domain\ProviderAccessException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use JsonException;
use stdClass;

final class ProviderBootstrapController
{
    public function status(Request $request, ProviderBootstrapService $service): JsonResponse
    {
        if ($this->input($request) !== []) {
            throw new ProviderAccessException('PROVIDER_SETUP_INPUT_INVALID', 422);
        }
        return $this->response($request, $service->status(), 200);
    }

    public function store(Request $request, ProviderBootstrapService $service): JsonResponse
    {
        // No ValidationException/redirect/old-input flashing for the setup proof.
        $data = $service->create($this->input($request), (string) $request->attributes->get('request_id'));
        return $this->response($request, $data, 201);
    }

    private function input(Request $request): array
    {
        try {
            $input = $request->isJson() ? json_decode($request->getContent(), false, 8, JSON_THROW_ON_ERROR) : null;
        } catch (JsonException) {
            throw new ProviderAccessException('PROVIDER_SETUP_INPUT_INVALID', 422);
        }
        if (! $input instanceof stdClass) {
            throw new ProviderAccessException('PROVIDER_SETUP_INPUT_INVALID', 422);
        }
        return get_object_vars($input);
    }

    private function response(Request $request, array $data, int $status): JsonResponse
    {
        return new JsonResponse(['data' => $data,
            'meta' => ['request_id' => $request->attributes->get('request_id')]], $status,
            ['Cache-Control' => 'private, no-store', 'Pragma' => 'no-cache']);
    }
}
