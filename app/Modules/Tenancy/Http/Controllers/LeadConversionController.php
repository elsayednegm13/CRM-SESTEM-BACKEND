<?php

declare(strict_types=1);

namespace App\Modules\Tenancy\Http\Controllers;

use App\Modules\Identity\Domain\TenantStaffContext;
use App\Modules\Tenancy\Application\CustomerService;
use App\Modules\Tenancy\Domain\TenantAccessException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class LeadConversionController
{
    public function __invoke(Request $request, string $lead, CustomerService $service): JsonResponse
    {
        $input = $request->validate([
            'customer' => ['required', 'array'], 'customer.type' => ['required', 'in:PERSON,ORGANIZATION'], 'customer.display_name' => ['required', 'string', 'max:160'], 'customer.legal_name' => ['sometimes', 'nullable', 'string', 'max:200'], 'customer.email' => ['sometimes', 'nullable', 'email', 'max:254'], 'customer.phone' => ['sometimes', 'nullable', 'string', 'max:32'], 'customer.country_code' => ['sometimes', 'nullable', 'string', 'size:2'],
            'contact' => ['sometimes', 'nullable', 'array'], 'contact.display_name' => ['required_with:contact', 'string', 'max:160'], 'contact.email' => ['sometimes', 'nullable', 'email', 'max:254'], 'contact.phone' => ['sometimes', 'nullable', 'string', 'max:32'], 'contact.job_title' => ['sometimes', 'nullable', 'string', 'max:120'], 'contact.note' => ['sometimes', 'nullable', 'string', 'max:1000'], 'contact.is_primary' => ['sometimes', 'boolean'],
        ]);
        $context = $request->attributes->get('tenant_staff_context');
        if (! $context instanceof TenantStaffContext) throw TenantAccessException::contextRequired();
        return response()->json(['data' => $service->convertLead($context, $lead, $input), 'meta' => ['request_id' => $request->attributes->get('request_id')]], 201);
    }
}
