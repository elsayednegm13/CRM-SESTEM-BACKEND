<?php

namespace App\Modules\Provider\Http\Controllers;

use App\Modules\Provider\Application\ProviderAuthenticationService;
use App\Modules\Provider\Application\ProviderAuthorizationService;
use App\Modules\Provider\Domain\ProviderContext;
use App\Modules\Provider\Infrastructure\Persistence\ProviderUser;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class ProviderAuthController
{
    public function login(Request $request, ProviderAuthenticationService $auth): JsonResponse
    {
        $input = $request->validate(['email' => ['required', 'string', 'max:1024'],
            'password' => ['required', 'string', 'max:1024']]);
        return $this->respond($request, ['state' => $auth->login($request, $input['email'], $input['password'])]);
    }

    public function enrollStart(Request $request, ProviderAuthenticationService $auth): JsonResponse
    {
        return $this->respond($request, $auth->startEnrollment($request));
    }

    public function enrollConfirm(Request $request, ProviderAuthenticationService $auth): JsonResponse
    {
        $input = $request->validate(['code' => ['required', 'string', 'max:64']]);
        return $this->respond($request, ['state' => 'AUTHENTICATED',
            'recovery_codes' => $auth->confirmEnrollment($request, $input['code'])]);
    }

    public function verify(Request $request, ProviderAuthenticationService $auth): JsonResponse
    {
        $input = $request->validate(['code' => ['required', 'string', 'max:64']]);
        $auth->verify($request, $input['code']);
        return $this->respond($request, ['state' => 'AUTHENTICATED']);
    }

    public function mfaStatus(Request $request): JsonResponse
    {
        $context = $this->context($request);
        $user = ProviderUser::query()->whereKey($context->providerUserId)->firstOrFail(['id', 'mfa_enrolled_at']);
        return $this->respond($request, ['state' => $user->mfa_enrolled_at === null ? 'NOT_ENROLLED' : 'ENROLLED']);
    }

    public function settingsEnrollStart(Request $request, ProviderAuthenticationService $auth): JsonResponse
    {
        $input = $request->validate(['password' => ['required', 'string', 'max:1024']]);
        return $this->respond($request, $auth->startSettingsEnrollment($request, $this->context($request), $input['password']));
    }

    public function settingsEnrollConfirm(Request $request, ProviderAuthenticationService $auth): JsonResponse
    {
        $input = $request->validate(['code' => ['required', 'string', 'max:64']]);
        return $this->respond($request, ['state' => 'REAUTHENTICATION_REQUIRED',
            'recovery_codes' => $auth->confirmSettingsEnrollment($request, $this->context($request), $input['code'])]);
    }

    public function stepUp(Request $request, ProviderAuthenticationService $auth): JsonResponse
    {
        $input = $request->validate(['password' => ['required', 'string', 'max:1024'],
            'code' => ['required', 'string', 'max:64']]);
        $auth->stepUp($request, $this->context($request), $input['password'], $input['code']);
        return $this->respond($request, ['status' => 'verified',
            'expires_at' => now('UTC')->addSeconds((int) config('provider.step_up_seconds'))->toIso8601String()]);
    }

    public function logout(Request $request, ProviderAuthenticationService $auth): JsonResponse
    {
        $auth->logout($request);
        return $this->respond($request, ['status' => 'logged_out']);
    }

    public function me(Request $request): JsonResponse
    {
        $context = $this->context($request);
        $user = ProviderUser::query()->whereKey($context->providerUserId)->firstOrFail();
        $step = $request->session()->get('provider.step_up');
        return $this->respond($request, [
            'id' => $user->getKey(), 'email' => $user->email, 'status' => $user->status,
            'mfa_enrolled' => $user->mfa_enrolled_at !== null,
            'authenticated_at' => date(DATE_ATOM, $context->authenticatedAt),
            'absolute_expires_at' => date(DATE_ATOM,
                $context->authenticatedAt + (int) config('provider.absolute_session_seconds')),
            'step_up_valid' => $context->stepUpVerifiedAt !== null,
            'step_up_expires_at' => $context->stepUpVerifiedAt !== null && is_array($step)
                ? date(DATE_ATOM, (int) $step['expires_at']) : null,
            'authorization_version' => $context->authorizationVersion,
        ]);
    }

    public function authorization(Request $request, ProviderAuthorizationService $authorization): JsonResponse
    {
        return $this->respond($request, ['capabilities' => $authorization->capabilities($this->context($request))]);
    }

    private function context(Request $request): ProviderContext
    {
        return $request->attributes->get('provider_context');
    }

    private function respond(Request $request, array $data): JsonResponse
    {
        return response()->json(['data' => $data,
            'meta' => ['request_id' => $request->attributes->get('request_id')]])
            ->withHeaders(['Cache-Control' => 'private, no-store', 'Pragma' => 'no-cache']);
    }
}
