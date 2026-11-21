<?php

namespace App\Modules\Identity\Http\Controllers;

use App\Modules\Identity\Application\AuthRateLimiter;
use App\Modules\Identity\Application\AuthSecurityEvents;
use App\Modules\Identity\Domain\Exceptions\InvalidVerificationLinkException;
use App\Modules\Identity\Infrastructure\Persistence\User;
use Illuminate\Auth\Events\Verified;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\URL;

final class EmailVerificationController
{
    public function verify(Request $request, string $id, string $hash, AuthSecurityEvents $events): JsonResponse
    {
        /** @var User|null $user */
        $user = $request->user();
        if (! $user || ! hash_equals(sha1($user->getEmailForVerification()), $hash) || ! hash_equals((string) $user->getKey(), $id)) {
            throw new InvalidVerificationLinkException;
        }

        if (! $user->hasVerifiedEmail()) {
            $user->markEmailAsVerified();
            event(new Verified($user));
            $events->emit('EmailVerified', $request, $user->getKey());
        }

        return response()->json([
            'data' => ['email_verified_at' => $user->fresh()->email_verified_at],
            'meta' => ['request_id' => $request->attributes->get('request_id')],
        ]);
    }

    public function resend(Request $request, AuthRateLimiter $limits, AuthSecurityEvents $events): JsonResponse
    {
        /** @var User $user */
        $user = $request->user();
        if (! $user->hasVerifiedEmail()) {
            $limits->assertVerificationResendAllowed((string) $user->getKey(), $request);
            $user->sendEmailVerificationNotification();
            $events->emit('EmailVerificationRequested', $request, $user->getKey(), 'accepted');
        }

        return response()->json([
            'data' => ['message' => 'If verification is still needed, instructions will be sent.'],
            'meta' => ['request_id' => $request->attributes->get('request_id')],
        ], 202);
    }

    public static function signedUrl(User $user): string
    {
        return URL::temporarySignedRoute('verification.verify', now()->addMinutes((int) config('identity.verification.expire_minutes', 60)), [
            'id' => $user->getKey(),
            'hash' => sha1($user->getEmailForVerification()),
        ]);
    }
}
