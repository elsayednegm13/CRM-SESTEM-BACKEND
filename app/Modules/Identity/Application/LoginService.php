<?php

namespace App\Modules\Identity\Application;

use App\Modules\Identity\Domain\Enums\UserStatus;
use App\Modules\Identity\Domain\Exceptions\InvalidCredentialsException;
use App\Modules\Identity\Infrastructure\Persistence\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

final class LoginService
{
    public function __construct(
        private readonly AuthRateLimiter $rateLimiter,
        private readonly AuthSecurityEvents $events,
    ) {
    }

    public function authenticate(string $email, string $password, Request $request): User
    {
        $this->rateLimiter->assertLoginAllowed($email, $request);
        $user = User::query()->where('email', $email)->first();
        $hash = $user?->password ?? config('identity.dummy_password_hash');
        $passwordMatches = is_string($hash) && Hash::check($password, $hash);

        if (! $user || ! $passwordMatches || $user->status !== UserStatus::ACTIVE) {
            $this->rateLimiter->recordLoginFailure($email, $request);
            $this->events->emit('LoginFailed', $request, $user?->getKey(), 'invalid_credentials');
            throw new InvalidCredentialsException;
        }

        $this->rateLimiter->clearLoginIdentityFailures($email, $request);

        if (config('hashing.rehash_on_login', true) && Hash::needsRehash($user->password)) {
            $user->forceFill(['password' => Hash::make($password)])->save();
        }

        $user->forceFill(['last_login_at' => now()])->save();
        Auth::guard('web')->login($user);
        $request->session()->regenerate();
        $request->session()->put('identity.auth_version', $user->auth_version);
        $request->session()->put('identity.authenticated_at', now()->timestamp);

        $this->events->emit('LoginSucceeded', $request, $user->getKey());

        return $user->refresh();
    }
}
