<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        api: __DIR__.'/../routes/api.php',
        commands: __DIR__.'/../routes/console.php',
    )
    ->withMiddleware(function (Middleware $middleware): void {
        // This value is already an HMAC envelope and must survive destruction
        // of the anonymous Laravel session during login rotation.
        $middleware->encryptCookies(except: ['daleel_login_client']);
        $middleware->statefulApi();
        $middleware->prepend([
            \App\Modules\Shared\Http\Middleware\RequestIdMiddleware::class,
            \App\Modules\Shared\Http\Middleware\CoreRuntimeBoundary::class,
            \App\Modules\Shared\Http\Middleware\SecurityHeadersMiddleware::class,
        ]);
        $middleware->append(\App\Modules\Identity\Http\Middleware\EnsureTenantLoginClientProof::class);

        // Laravel's default priority sorter otherwise moves Authenticate and
        // SubstituteBindings ahead of these tenant-scoped context boundaries.
        // Resolve the host and bind the RLS actor before the session guard loads
        // a staff principal or any route binding can query tenant data.
        $middleware->prependToPriorityList(
            \Illuminate\Contracts\Auth\Middleware\AuthenticatesRequests::class,
            \App\Modules\Identity\Http\Middleware\ResolveTenantHost::class,
        );
        $middleware->prependToPriorityList(
            \Illuminate\Contracts\Auth\Middleware\AuthenticatesRequests::class,
            \App\Modules\Identity\Http\Middleware\RequireAllowedSpaOrigin::class,
        );
        $middleware->prependToPriorityList(
            \Illuminate\Contracts\Auth\Middleware\AuthenticatesRequests::class,
            \App\Modules\Identity\Http\Middleware\TenantStaffRequestContext::class,
        );
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        $exceptions->shouldRenderJsonWhen(
            fn (Request $request) => $request->is('api/*') || $request->expectsJson(),
        );

        $exceptions->render(function (Throwable $exception, Request $request) {
            if (! $request->is('api/*')) {
                return null;
            }

            return \App\Modules\Shared\Http\ApiErrorResponse::fromException($exception, $request);
        });

        $exceptions->respond(function (Response $response, Throwable $exception, Request $request): Response {
            if ($request->is('api/*')) {
                $requestId = $request->attributes->get('request_id');
                if (is_string($requestId)) {
                    $response->headers->set('X-Request-ID', $requestId);
                }

                \App\Modules\Shared\Http\Middleware\SecurityHeadersMiddleware::apply($request, $response);
                if ($request->is('api/v1/super/*') || $request->is('api/v1/auth/*')) {
                    $response->headers->set('Cache-Control', 'private, no-store');
                    $response->headers->set('Pragma', 'no-cache');
                }
            }

            return $response;
        });
    })->create();
