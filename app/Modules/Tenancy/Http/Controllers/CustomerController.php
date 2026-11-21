<?php

declare(strict_types=1);

namespace App\Modules\Tenancy\Http\Controllers;

use App\Modules\Identity\Domain\TenantStaffContext;
use App\Modules\Tenancy\Application\CustomerService;
use App\Modules\Tenancy\Domain\TenantAccessException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class CustomerController
{
    public function index(Request $request, CustomerService $service): JsonResponse
    {
        $input = $request->validate(['search' => ['sometimes', 'nullable', 'string', 'max:100'], 'status' => ['sometimes', 'nullable', 'in:ACTIVE,INACTIVE'], 'page' => ['sometimes', 'integer', 'min:1'], 'per_page' => ['sometimes', 'integer', 'min:1', 'max:100']]);
        $result = $service->list($this->context($request), trim((string) ($input['search'] ?? '')), $input['status'] ?? null, (int) ($input['page'] ?? 1), (int) ($input['per_page'] ?? 25));
        return response()->json(['data' => $result['data'], 'meta' => [...$result['meta'], 'request_id' => $request->attributes->get('request_id')]]);
    }

    public function store(Request $request, CustomerService $service): JsonResponse { return $this->respond($request, $service->create($this->context($request), $request->validate($this->customerRules())), 201); }
    public function show(Request $request, string $customer, CustomerService $service): JsonResponse { return $this->respond($request, $service->show($this->context($request), $customer)); }
    public function update(Request $request, string $customer, CustomerService $service): JsonResponse { return $this->respond($request, $service->update($this->context($request), $customer, $request->validate($this->customerRules(false)))); }
    public function addContact(Request $request, string $customer, CustomerService $service): JsonResponse { return $this->respond($request, $service->addContact($this->context($request), $customer, $request->validate($this->contactRules())), 201); }
    public function contacts(Request $request, string $customer, CustomerService $service): JsonResponse { return $this->respond($request, $service->listContacts($this->context($request), $customer)); }
    public function updateContact(Request $request, string $customer, string $contact, CustomerService $service): JsonResponse { return $this->respond($request, $service->updateContact($this->context($request), $customer, $contact, $request->validate($this->contactRules(false)))); }
    public function addresses(Request $request, string $customer, CustomerService $service): JsonResponse { return $this->respond($request, $service->listAddresses($this->context($request), $customer)); }
    public function addAddress(Request $request, string $customer, CustomerService $service): JsonResponse { return $this->respond($request, $service->addAddress($this->context($request), $customer, $request->validate($this->addressRules())), 201); }
    public function updateAddress(Request $request, string $customer, string $address, CustomerService $service): JsonResponse { return $this->respond($request, $service->updateAddress($this->context($request), $customer, $address, $request->validate($this->addressRules(false)))); }

    /** @return array<string,list<mixed>> */
    private function customerRules(bool $required = true): array
    {
        $presence = $required ? 'required' : 'sometimes';
        return ['type' => [$presence, 'in:PERSON,ORGANIZATION'], 'display_name' => [$presence, 'string', 'max:160'], 'legal_name' => ['sometimes', 'nullable', 'string', 'max:200'], 'email' => ['sometimes', 'nullable', 'email', 'max:254'], 'phone' => ['sometimes', 'nullable', 'string', 'max:32'], 'country_code' => ['sometimes', 'nullable', 'string', 'size:2'], 'status' => ['sometimes', 'in:ACTIVE,INACTIVE']];
    }
    /** @return array<string,list<mixed>> */
    private function contactRules(bool $required = true): array { $presence = $required ? 'required' : 'sometimes'; return ['display_name' => [$presence, 'string', 'max:160'], 'email' => ['sometimes', 'nullable', 'email', 'max:254'], 'phone' => ['sometimes', 'nullable', 'string', 'max:32'], 'job_title' => ['sometimes', 'nullable', 'string', 'max:120'], 'note' => ['sometimes', 'nullable', 'string', 'max:1000'], 'is_primary' => ['sometimes', 'boolean']]; }
    /** @return array<string,list<mixed>> */
    private function addressRules(bool $required = true): array { $presence = $required ? 'required' : 'sometimes'; return ['kind' => ['sometimes', 'in:GENERAL,BILLING,SHIPPING'], 'line1' => [$presence, 'string', 'max:200'], 'line2' => ['sometimes', 'nullable', 'string', 'max:200'], 'city' => ['sometimes', 'nullable', 'string', 'max:100'], 'region' => ['sometimes', 'nullable', 'string', 'max:100'], 'postal_code' => ['sometimes', 'nullable', 'string', 'max:32'], 'country_code' => ['sometimes', 'nullable', 'string', 'size:2']]; }
    /** @param array<string,mixed> $data */
    private function respond(Request $request, array $data, int $status = 200): JsonResponse { return response()->json(['data' => $data, 'meta' => ['request_id' => $request->attributes->get('request_id')]], $status); }
    private function context(Request $request): TenantStaffContext { $context = $request->attributes->get('tenant_staff_context'); if (! $context instanceof TenantStaffContext) throw TenantAccessException::contextRequired(); return $context; }
}
