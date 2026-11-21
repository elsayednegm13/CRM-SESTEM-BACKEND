<?php

namespace App\Modules\Provider\Http\Middleware;

use Closure;
use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;
use Illuminate\Session\TokenMismatchException;

/** Setup requires a session token even for direct/non-stateful API requests. */
final class ForceProviderBootstrapCsrf extends ValidateCsrfToken
{
    protected $addHttpCookie = false;

    public function handle($request, Closure $next)
    {
        if (! $request->hasSession()) {
            throw new TokenMismatchException('CSRF token mismatch.');
        }
        return parent::handle($request, $next);
    }

    protected function isReading($request) { return false; }
    protected function runningUnitTests() { return false; }
    protected function inExceptArray($request) { return false; }

    // Laravel 13 otherwise accepts Sec-Fetch-Site without checking the token.
    protected function hasValidOrigin($request) { return false; }
}
