<?php

namespace App\Modules\Shared\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

class RequestIdMiddleware
{
    public function handle(Request $request, Closure $next): Response
    {
        $incoming = $request->header('X-Request-ID');
        $requestId = is_string($incoming) && Str::isUuid($incoming)
            ? strtolower($incoming)
            : (string) Str::uuid();

        $request->attributes->set('request_id', $requestId);
        Log::withContext(['request_id' => $requestId]);

        $startedAt = hrtime(true);
        $response = null;

        try {
            $response = $next($request);

            return $response;
        } catch (Throwable $exception) {
            throw $exception;
        } finally {
            $durationMs = round((hrtime(true) - $startedAt) / 1_000_000, 2);
            $route = $request->route();
            $context = [
                'request_id' => $requestId,
                'route' => $route?->uri() ?? 'unmatched',
                'method' => $request->method(),
                'status' => $response?->getStatusCode() ?? 500,
                'duration_ms' => $durationMs,
            ];

            Log::channel('structured')->info('api.request', $context);
            Log::withoutContext();

            if ($response instanceof Response) {
                $response->headers->set('X-Request-ID', $requestId);
            }
        }
    }
}
