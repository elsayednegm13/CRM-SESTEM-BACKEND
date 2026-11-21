<?php

namespace App\Modules\Provider\Http\Controllers;

use App\Modules\Provider\Application\ProviderControlOperationService;
use App\Modules\Provider\Domain\ProviderContext;
use App\Modules\Provider\Domain\ProviderAccessException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\ValidationException;

final class ProviderControlController
{
    public function provision(Request $request, ProviderControlOperationService $service): JsonResponse
    {
        $context = $this->context($request);
        $input = $request->validate(['display_name' => ['required','string','max:160'],
            'slug' => ['required','string','max:100'], 'timezone' => ['required','timezone'],
            'first_admin_email' => ['required','email','max:254'],
            'first_admin_display_name' => ['required','string','max:160'],
            'reason' => ['required','string','max:500'],
            'ticket_reference' => ['required','string','max:100']]);
        $key = (string) $request->header('Idempotency-Key', '');
        return response()->json(['data' => $service->createProvision($context, $input, $key),
            'meta' => ['request_id' => $context->requestId]], 202)->header('Cache-Control', 'no-store');
    }

    public function execute(Request $request, string $operation, ProviderControlOperationService $service): JsonResponse
    {
        $context = $this->context($request);
        $input = $request->validate(['initial_password' => ['required','string','min:12','max:1024']]);
        return response()->json(['data' => $service->executeProvision($context, $operation, $input['initial_password']),
            'meta' => ['request_id' => $context->requestId]])->header('Cache-Control', 'no-store');
    }

    public function edit(Request $request, string $operation, ProviderControlOperationService $service): JsonResponse
    {
        $context = $this->context($request);
        $allowed = ['expected_revision', 'display_name', 'slug', 'timezone',
            'first_admin_email', 'first_admin_display_name', 'edit_reason'];
        if (array_diff(array_keys($request->all()), $allowed) !== []) {
            throw ValidationException::withMessages(['operation' => ['The provisioning edit contains unsupported fields.']]);
        }
        $input = $request->validate([
            'expected_revision' => ['required', 'integer', 'min:1'],
            'display_name' => ['required', 'string', 'max:160'],
            'slug' => ['required', 'string', 'max:100'],
            'timezone' => ['required', 'timezone'],
            'first_admin_email' => ['required', 'email', 'max:254'],
            'first_admin_display_name' => ['required', 'string', 'max:160'],
            'edit_reason' => ['sometimes', 'nullable', 'string', 'max:500'],
        ]);
        return response()->json(['data' => $service->editProvision($context, $operation, $input),
            'meta' => ['request_id' => $context->requestId]])->header('Cache-Control', 'no-store');
    }

    public function revisions(Request $request, string $operation, ProviderControlOperationService $service): JsonResponse
    {
        $context = $this->context($request);
        if (array_diff(array_keys($request->query->all()), ['limit', 'before_revision']) !== []) {
            throw ValidationException::withMessages(['history' => ['The revision history query is invalid.']]);
        }
        $input = $request->validate([
            'limit' => ['sometimes', 'integer', 'min:1', 'max:50'],
            'before_revision' => ['sometimes', 'integer', 'min:1'],
        ]);

        return response()->json(['data' => $service->provisionRevisionHistory($context, $operation,
            (int) ($input['limit'] ?? 50), isset($input['before_revision']) ? (int) $input['before_revision'] : null),
            'meta' => ['request_id' => $context->requestId]])->header('Cache-Control', 'no-store');
    }

    public function lifecycle(Request $request, ProviderControlOperationService $service): JsonResponse
    {
        $context = $this->context($request);
        $input = $request->validate(['tenant_id' => ['required', 'uuid'],
            'action' => ['required', 'string', 'in:SUSPEND,RESUME,ARCHIVE'],
            'reason' => ['required', 'string', 'max:500'],
            'ticket_reference' => ['required', 'string', 'max:100']]);
        $key = (string) $request->header('Idempotency-Key', '');
        return response()->json(['data' => $service->createLifecycleChange($context, $input, $key),
            'meta' => ['request_id' => $context->requestId]], 202)->header('Cache-Control', 'no-store');
    }

    public function executeLifecycle(Request $request, string $operation,
        ProviderControlOperationService $service): JsonResponse
    {
        $context = $this->context($request);
        return response()->json(['data' => $service->executeLifecycleChange($context, $operation),
            'meta' => ['request_id' => $context->requestId]])->header('Cache-Control', 'no-store');
    }

    public function recover(Request $request): JsonResponse
    {
        $this->context($request);
        throw ProviderAccessException::approvalUnusable();
    }

    public function executeRecovery(Request $request, string $operation): JsonResponse
    {
        $this->context($request);
        throw ProviderAccessException::approvalUnusable();
    }

    public function review(Request $request, string $approval, string $decision,
        ProviderControlOperationService $service): JsonResponse
    {
        $context = $this->context($request);
        $input = $request->validate(['reason' => ['required','string','max:500'],
            'ticket_reference' => ['required','string','max:100'],
            'expected_revision' => ['sometimes', 'integer', 'min:1']]);
        $status = $service->review($context, $approval, strtoupper($decision), $input['reason'],
            $input['ticket_reference'], $input['expected_revision'] ?? null);
        return response()->json(['data' => ['id' => $approval, 'status' => $status],
            'meta' => ['request_id' => $context->requestId]])->header('Cache-Control', 'no-store');
    }

    public function founderAccept(Request $request, string $invitation,
        ProviderControlOperationService $service): JsonResponse
    {
        $input = $request->validate(['token' => ['required','string','min:40','max:128'],
            'password' => ['nullable','string','min:12','max:1024','confirmed'],
            'password_confirmation' => ['required_with:password','string','min:12','max:1024']]);
        $user = Auth::guard('sanctum')->user();
        $result = $service->approveFounder($invitation, $input['token'], $user?->getAuthIdentifier(),
            $input['password'] ?? null, $input['password_confirmation'] ?? null);
        return response()->json(['data' => $result,
            'meta' => ['request_id' => $request->attributes->get('request_id')]])->header('Cache-Control', 'no-store');
    }

    private function context(Request $request): ProviderContext
    {
        $context = $request->attributes->get('provider_context');
        abort_unless($context instanceof ProviderContext, 401);
        return $context;
    }
}
