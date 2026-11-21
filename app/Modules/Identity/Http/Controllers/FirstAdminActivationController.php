<?php

namespace App\Modules\Identity\Http\Controllers;

use App\Modules\Identity\Application\FirstAdminActivationService;
use App\Modules\Identity\Domain\EmailAddressNormalizer;
use App\Modules\Identity\Domain\TenantHostContext;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use InvalidArgumentException;

final class FirstAdminActivationController
{
    public function __invoke(Request $request, EmailAddressNormalizer $emails, FirstAdminActivationService $activation): JsonResponse
    {
        // CORE-01 G2 security stop. Preserve the implementation for review,
        // but deny authority while SQL tenant identity is not actor-bound.
        abort(503, 'CORE01_SECURITY_GATE_CLOSED');

        $input = $request->validate([
            'email' => ['required', 'string', 'max:1024'],
            'initial_password' => ['required', 'string', 'max:1024'],
            'new_password' => ['required', 'string', 'min:12', 'max:1024'],
        ]);
        if (hash_equals($input['initial_password'], $input['new_password'])) {
            throw ValidationException::withMessages(['new_password' => ['Choose a different password.']]);
        }
        try {
            $email = $emails->normalize($input['email']);
        } catch (InvalidArgumentException) {
            throw ValidationException::withMessages(['email' => ['The email address is invalid.']]);
        }
        $host = $request->attributes->get('tenant_host_context');
        if (! $host instanceof TenantHostContext) {
            abort(404);
        }
        $activation->activate($host, $email, $input['initial_password'], $input['new_password'],
            (string) $request->attributes->get('request_id'));

        return response()->json(['data' => ['status' => 'activated'],
            'meta' => ['request_id' => $request->attributes->get('request_id')]]);
    }
}
