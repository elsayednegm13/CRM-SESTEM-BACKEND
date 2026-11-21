<?php

namespace App\Modules\Identity\Http\Controllers;

use App\Modules\Identity\Application\AuthRateLimiter;
use App\Modules\Identity\Application\AuthSecurityEvents;
use App\Modules\Identity\Domain\EmailAddressNormalizer;
use App\Modules\Identity\Domain\Enums\UserStatus;
use App\Modules\Identity\Domain\Exceptions\AuthRateLimitedException;
use App\Modules\Identity\Infrastructure\Persistence\User;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Illuminate\Validation\ValidationException;
use InvalidArgumentException;

final class PasswordController
{
    public function forgot(Request $request, EmailAddressNormalizer $emails, AuthRateLimiter $limits, AuthSecurityEvents $events): JsonResponse
    {
        $input = $request->validate(['email' => ['required', 'string', 'max:1024']]);
        $email = $this->canonicalEmail($emails, $input['email']);
        $limits->assertForgotAllowed($email, $request);

        $user = User::query()->where('email', $email)->first();
        if ($user && $user->status === UserStatus::ACTIVE) {
            Password::broker()->sendResetLink(['email' => $email]);
        }
        $events->emit('PasswordResetRequested', $request, $user?->getKey(), 'accepted');

        return response()->json([
            'data' => ['code' => 'AUTH_PASSWORD_RESET_ACCEPTED', 'message' => 'If the account is eligible, password reset instructions will be sent.'],
            'meta' => ['request_id' => $request->attributes->get('request_id')],
        ], 202);
    }

    public function reset(Request $request, EmailAddressNormalizer $emails, AuthRateLimiter $limits, AuthSecurityEvents $events): JsonResponse
    {
        $input = $request->validate([
            'email' => ['required', 'string', 'max:1024'],
            'token' => ['required', 'string', 'max:512'],
            'password' => ['required', 'string', 'min:12'],
            'password_confirmation' => ['required', 'string'],
        ]);
        if (strlen($input['password']) > 1024 || $input['password'] !== $input['password_confirmation']) {
            throw ValidationException::withMessages(['password' => ['The password confirmation is invalid.']]);
        }
        $email = $this->canonicalEmail($emails, $input['email']);
        $limits->assertResetAllowed($email, $request);

        $status = DB::transaction(fn () => Password::broker()->reset(
            ['email' => $email, 'token' => $input['token'], 'password' => $input['password'], 'password_confirmation' => $input['password_confirmation']],
            function (User $user, string $password) use ($request, $events): void {
                $locked = User::query()->whereKey($user->getKey())->lockForUpdate()->firstOrFail();
                $locked->forceFill([
                    'password' => Hash::make($password),
                    'auth_version' => $locked->auth_version + 1,
                ])->save();
                event(new PasswordReset($locked));
                $events->emit('PasswordResetCompleted', $request, $locked->getKey());
            },
        ));

        if ($status !== Password::PASSWORD_RESET) {
            return response()->json([
                'error' => ['code' => 'AUTH_PASSWORD_RESET_INVALID', 'message' => 'The password reset request is invalid or expired.'],
                'meta' => ['request_id' => $request->attributes->get('request_id')],
            ], 422);
        }

        return response()->json([
            'data' => ['message' => 'Password reset completed. Please sign in again.'],
            'meta' => ['request_id' => $request->attributes->get('request_id')],
        ]);
    }

    private function canonicalEmail(EmailAddressNormalizer $emails, string $value): string
    {
        try {
            return $emails->normalize($value);
        } catch (InvalidArgumentException) {
            throw ValidationException::withMessages(['email' => ['The email address is invalid.']]);
        }
    }
}
