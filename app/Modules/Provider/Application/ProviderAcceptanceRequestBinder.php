<?php

declare(strict_types=1);

namespace App\Modules\Provider\Application;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use LogicException;

/** Acceptance-only in-process request binding; no route and no identity bypass. */
final class ProviderAcceptanceRequestBinder
{
    public function run(Request $request, Closure $callback): mixed
    {
        $hadPrevious = app()->bound('request');
        $previous = $hadPrevious ? app('request') : null;
        try {
            Auth::forgetGuards();
            app()->instance('request', $request);
            $guard = Auth::guard('provider');
            if (! method_exists($guard, 'setRequest')) {
                throw new LogicException('Provider guard cannot bind the acceptance request.');
            }
            $guard->setRequest($request);

            return $callback();
        } finally {
            Auth::forgetGuards();
            if ($hadPrevious) {
                app()->instance('request', $previous);
            } else {
                app()->forgetInstance('request');
            }
        }
    }
}
