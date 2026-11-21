<?php

namespace App\Modules\System\Http\Controllers;

use Illuminate\Database\DatabaseManager;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Redis;
use Throwable;

class HealthController
{
    public function __invoke(Request $request): JsonResponse
    {
        $dependencies = $this->dependencies();
        $status = in_array('healthy', $dependencies, true)
            && ! in_array('degraded', $dependencies, true)
            && ! in_array('not_configured', $dependencies, true)
                ? 'healthy'
                : 'degraded';

        return $this->response($request, ['status' => $status, 'dependencies' => $dependencies]);
    }

    public function live(Request $request): JsonResponse
    {
        return $this->response($request, ['status' => 'alive']);
    }

    public function ready(Request $request): JsonResponse
    {
        $dependencies = $this->dependencies();
        $ready = ! in_array('degraded', $dependencies, true)
            && ! in_array('not_configured', $dependencies, true);

        return $this->response(
            $request,
            ['status' => $ready ? 'healthy' : 'degraded', 'dependencies' => $dependencies],
            $ready ? 200 : 503,
        );
    }

    /** @return array<string, string> */
    private function dependencies(): array
    {
        if (! config('foundation.dependency_checks_enabled')) {
            return ['database' => 'not_configured', 'redis' => 'not_configured'];
        }

        $database = 'degraded';
        try {
            app(DatabaseManager::class)->connection()->select('SELECT 1');
            $database = 'healthy';
        } catch (Throwable) {
            // Keep connection details out of public health responses.
        }

        $redis = 'not_configured';
        if (config('foundation.redis_dependency_configured')) {
            $redis = 'degraded';
            try {
                Redis::connection()->ping();
                $redis = 'healthy';
            } catch (Throwable) {
                // Keep connection details out of public health responses.
            }
        }

        return ['database' => $database, 'redis' => $redis];
    }

    /** @param array<string, mixed> $data */
    private function response(Request $request, array $data, int $status = 200): JsonResponse
    {
        return response()->json([
            'data' => $data,
            'meta' => ['request_id' => $request->attributes->get('request_id')],
        ], $status);
    }
}
