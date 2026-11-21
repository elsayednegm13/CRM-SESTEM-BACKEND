<?php

namespace App\Modules\Identity\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class AuthRecoveryNotImplementedController
{
    public function __invoke(Request $request): JsonResponse
    {
        return response()->json([
            'error' => [
                'code' => 'AUTH_TENANT_RECOVERY_NOT_IMPLEMENTED',
                'message' => 'Tenant account recovery is not available yet.',
            ],
            'meta' => ['request_id' => $request->attributes->get('request_id')],
        ], 501);
    }
}
