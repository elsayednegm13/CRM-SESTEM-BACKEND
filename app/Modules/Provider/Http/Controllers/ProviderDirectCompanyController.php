<?php

namespace App\Modules\Provider\Http\Controllers;

use App\Modules\Provider\Application\ProviderDirectProvisionService;
use App\Modules\Provider\Domain\ProviderContext;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;

final class ProviderDirectCompanyController
{
    public function __invoke(Request $request, ProviderDirectProvisionService $service): JsonResponse
    {
        $actor = $request->attributes->get('provider_context');
        abort_unless($actor instanceof ProviderContext, 401);
        $allowed = ['display_name', 'slug', 'timezone', 'first_admin_email',
            'first_admin_display_name', 'initial_password'];
        if (array_diff(array_keys($request->all()), $allowed) !== []) {
            throw ValidationException::withMessages(['company' => ['Unsupported fields were provided.']]);
        }
        $input = $request->validate([
            'display_name' => ['required', 'string', 'max:160'],
            'slug' => ['required', 'string', 'max:100'],
            'timezone' => ['required', 'timezone'],
            'first_admin_email' => ['required', 'email', 'max:254'],
            'first_admin_display_name' => ['required', 'string', 'max:160'],
            'initial_password' => ['required', 'string', 'min:12', 'max:1024'],
        ]);
        $result = $service->create($actor, $input, (string) $request->header('Idempotency-Key', ''), $request);
        return response()->json(['data' => $result, 'meta' => ['request_id' => $actor->requestId]],
            ! empty($result['replay']) ? 200 : 201)->header('Cache-Control', 'private, no-store');
    }
}
