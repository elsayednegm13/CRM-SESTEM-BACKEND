<?php

namespace App\Modules\Identity\Http\Controllers;

use App\Modules\Identity\Application\FirstAdminActivationAuthorityService;
use App\Modules\Identity\Domain\EmailAddressNormalizer;
use App\Modules\Identity\Domain\TenantHostContext;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use InvalidArgumentException;

/**
 * Actor-bound first-admin activation endpoint (CORE-01, migration 058).
 *
 * Gated closed by default: FirstAdminActivationAuthorityService::activate()
 * aborts 503 unless CORE01_ACTIVATION_AUTHORITY_ENABLED is set. The old
 * FirstAdminActivationController stays permanently 503; this is a separate path.
 */
final class FirstAdminActivationAuthorityController
{
    public function __invoke(Request $request, EmailAddressNormalizer $emails,
        FirstAdminActivationAuthorityService $activation): JsonResponse
    {
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
        $activation->activate($request, $host, $email, $input['initial_password'], $input['new_password'],
            (string) $request->attributes->get('request_id'));

        // Renew the session after a successful credential rotation (condition 5).
        $request->session()->regenerate();

        return response()->json(['data' => ['status' => 'activated'],
            'meta' => ['request_id' => $request->attributes->get('request_id')]]);
    }
}
