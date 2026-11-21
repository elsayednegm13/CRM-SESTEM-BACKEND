<?php

namespace App\Modules\Provider\Http\Controllers;

use App\Modules\Provider\Application\ProviderAuthorizationService;
use App\Modules\Provider\Domain\ProviderContext;
use App\Modules\Provider\Domain\ProviderAccessException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

final class ProviderApprovalController
{
    public function index(Request $request, ProviderAuthorizationService $authorization): JsonResponse
    {
        $context = $request->attributes->get('provider_context');
        if (! $context instanceof ProviderContext) {
            abort(401);
        }
        $authorization->assertCapability($context, 'provider.approval.review');
        if (array_diff(array_keys($request->query->all()), ['page']) !== []) {
            throw ProviderAccessException::approvalUnusable();
        }
        $page = max(1, min(100, (int) $request->query('page', 1)));
        $rows = DB::connection('pgsql_provider')->table('provider_approval_requests as approval')
            ->leftJoin('provider_control_operations as operation', 'operation.id', '=', 'approval.operation_id')
            ->whereIn('approval.action_key', ['company.provision', 'company.lifecycle.manage'])
            ->where(static function ($query): void {
                $query->whereNull('approval.operation_id')
                    ->orWhereIn('operation.action_key', ['company.provision', 'company.lifecycle.manage']);
            })
            ->orderByDesc('approval.created_at')->orderByDesc('approval.id')
            ->offset(($page - 1) * 25)->limit(25)
            ->get(['approval.id', 'approval.requester_provider_user_id', 'approval.action_key',
                'approval.target_kind', 'approval.target_id', 'approval.reason', 'approval.ticket_reference',
                'approval.required_approvals', 'approval.expires_at', 'approval.status', 'approval.created_at',
                'operation.status as operation_status', 'operation.current_revision',
                'operation.intent_digest', 'operation.display_name', 'operation.canonical_slug as slug',
                'operation.timezone', 'operation.founder_email as first_admin_email',
                'operation.first_admin_display_name', 'operation.lifecycle_action']);
        return response()->json(['data' => $rows,
            'meta' => ['request_id' => $request->attributes->get('request_id'), 'page' => $page]])
            ->withHeaders(['Cache-Control' => 'private, no-store', 'Pragma' => 'no-cache']);
    }
}
