<?php

namespace App\Modules\Identity\Application;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

final class AuthSecurityEvents
{
    public function emit(string $event, Request $request, ?string $subjectId = null, string $result = 'success'): void
    {
        Log::channel('structured')->info('auth.security', array_filter([
            'event' => $event,
            'request_id' => $request->attributes->get('request_id'),
            'subject_id' => $subjectId,
            'result' => $result,
            'route' => $request->route()?->uri() ?? 'unmatched',
            'method' => $request->method(),
        ], static fn ($value) => $value !== null));
    }
}
