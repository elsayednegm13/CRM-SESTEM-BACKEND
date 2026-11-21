<?php

namespace App\Modules\Identity\Http\Controllers;

use App\Modules\Identity\Application\AuthSecurityEvents;
use App\Modules\Identity\Application\LoginService;
use App\Modules\Identity\Domain\EmailAddressNormalizer;
use App\Modules\Identity\Domain\Exceptions\InvalidCredentialsException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\ValidationException;
use InvalidArgumentException;

final class AuthController
{
    public function login(Request $request, EmailAddressNormalizer $emails, LoginService $login): JsonResponse
    {
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

        $user = $login->authenticate($email, $input['password'], $request);

        return response()->json([
            'data' => ['id' => $user->getKey(), 'email' => $user->email, 'email_verified_at' => $user->email_verified_at],
            'meta' => ['request_id' => $request->attributes->get('request_id')],
        ]);
    }

    public function logout(Request $request, AuthSecurityEvents $events): JsonResponse
    {
        $user = $request->user();
        Auth::guard('web')->logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();
        $events->emit('Logout', $request, $user?->getAuthIdentifier());
        return response()->json([
            'data' => ['status' => 'logged_out'],
            'meta' => ['request_id' => $request->attributes->get('request_id')],
        ]);
    }

    public function me(Request $request): JsonResponse
    {
        $user = $request->user();

        return response()->json([
            'data' => ['id' => $user->getKey(), 'email' => $user->email, 'email_verified_at' => $user->email_verified_at],
            'meta' => ['request_id' => $request->attributes->get('request_id')],
        ]);
    }
}
