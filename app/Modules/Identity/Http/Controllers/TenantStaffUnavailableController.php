<?php

namespace App\Modules\Identity\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class TenantStaffUnavailableController
{
    public function __invoke(Request $request): JsonResponse
    {
        return response()->json([
            'error' => [
                'code' => 'TENANT_STAFF_ACTION_NOT_IMPLEMENTED',
                'message' => 'This tenant staff action is not available in this foundation.',
            ],
            'meta' => ['request_id' => $request->attributes->get('request_id')],
        ], 501);
    }
}
