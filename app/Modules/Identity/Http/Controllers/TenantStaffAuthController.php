<?php

namespace App\Modules\Identity\Http\Controllers;

use App\Modules\Identity\Application\TenantStaffLoginService;
use App\Modules\Identity\Domain\EmailAddressNormalizer;
use App\Modules\Identity\Domain\TenantStaffContext;
use App\Modules\Identity\Infrastructure\Persistence\TenantStaffUser;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use InvalidArgumentException;

final class TenantStaffAuthController
{
    public function login(Request $request, EmailAddressNormalizer $emails, TenantStaffLoginService $login): JsonResponse
    {
        $retryKey = $request->headers->get('Idempotency-Key');
        if (! is_string($retryKey)
            || preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/D', $retryKey) !== 1) {
            throw ValidationException::withMessages([
                'idempotency_key' => ['A new cryptographically random UUIDv4 is required for each sign-in attempt.'],
            ]);
        }
        $input = $request->validate([
            'email' => ['required', 'string', 'max:1024'],
            'password' => ['required', 'string'],
        ]);
        if (strlen($input['password']) > 1024) {
            throw ValidationException::withMessages(['password' => ['The password may not exceed 1024 bytes.']]);
        }

        try {
            $email = $emails->normalize($input['email']);
        } catch (InvalidArgumentException) {
            throw ValidationException::withMessages(['email' => ['The email address is invalid.']]);
        }

        $host = $request->attributes->get('tenant_host_context');
        if (! $host instanceof \App\Modules\Identity\Domain\TenantHostContext) {
            throw new AuthenticationException;
        }
        $user = $login->authenticate($host, $email, $input['password'], $retryKey, $request);

        return response()->json([
            'data' => ['id' => $user->getKey(), 'email' => $user->display_email, 'name' => $user->display_name],
            'meta' => ['request_id' => $request->attributes->get('request_id')],
        ]);
    }

    public function me(Request $request): JsonResponse
    {
        $user = $request->user('tenant_staff');
        $context = $request->attributes->get('tenant_staff_context');
        if (! $user instanceof TenantStaffUser || ! $context instanceof TenantStaffContext) {
            throw new AuthenticationException;
        }

        return response()->json([
            'data' => ['id' => $user->getKey(), 'email' => $user->display_email, 'name' => $user->display_name],
            'meta' => ['request_id' => $request->attributes->get('request_id')],
        ]);
    }

    public function logout(Request $request): JsonResponse
    {
        // Middleware performs the durable revoke and local session destruction only
        // after the runtime transaction has committed, avoiding a self-wait.
        $request->attributes->set('tenant_staff_logout_requested', true);

        return response()->json([
            'data' => ['status' => 'logged_out'],
            'meta' => ['request_id' => $request->attributes->get('request_id')],
        ]);
    }
}
