<?php

declare(strict_types=1);

namespace App\Modules\Tenancy\Application;

use App\Modules\Identity\Application\TenantStaffAuthorizationService;
use App\Modules\Identity\Domain\TenantStaffContext;
use App\Modules\Tenancy\Domain\AuthorizationDeniedException;
use App\Modules\Tenancy\Domain\LeadConversionConflictException;
use App\Modules\Tenancy\Domain\TenantAccessException;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

/** Tenant-first customers, contacts, and conversion runtime service. */
final class CustomerService
{
    private const CONNECTION = 'pgsql_tenant_runtime';

    public function __construct(private readonly TenantStaffAuthorizationService $authorization) {}

    /** @return array{data:list<array<string,mixed>>,meta:array<string,int>} */
    public function list(TenantStaffContext $actor, string $search, ?string $status, int $page, int $perPage): array
    {
        $this->require($actor, 'customers.view');
        $query = DB::connection(self::CONNECTION)->table('customers')->where('tenant_id', $actor->tenantId);
        if ($status !== null) $query->where('status', $status);
        if ($search !== '') {
            $escaped = str_replace(['\\', '%', '_'], ['\\\\', '\\%', '\\_'], mb_strtolower($search));
            $query->whereRaw("(lower(display_name) LIKE ? ESCAPE '\\' OR lower(coalesce(email,'')) LIKE ? ESCAPE '\\' OR coalesce(phone,'') LIKE ? ESCAPE '\\')", ["%{$escaped}%", "%{$escaped}%", "%{$escaped}%"]);
        }
        $total = (clone $query)->count();
        $rows = $query->orderByDesc('created_at')->forPage($page, $perPage)->get();
        return ['data' => $rows->map(fn (object $row) => $this->presentCustomer($row))->all(),
            'meta' => ['page' => $page, 'per_page' => $perPage, 'total' => $total]];
    }

    /** @param array<string,mixed> $input @return array<string,mixed> */
    public function create(TenantStaffContext $actor, array $input): array
    {
        $this->require($actor, 'customers.manage');
        $customer = CustomerInput::normalizeCustomer($input);
        return $this->withinTransaction(DB::connection(self::CONNECTION), function (ConnectionInterface $db) use ($actor, $customer): array {
            $this->throwIfDuplicate($db, $actor->tenantId, $customer['email'], $customer['phone']);
            $id = (string) Str::uuid7(); $now = now('UTC');
            $db->table('customers')->insert(['id' => $id, 'tenant_id' => $actor->tenantId, ...$customer,
                'source_lead_id' => null, 'created_by_membership_id' => $actor->membershipId, 'created_at' => $now, 'updated_at' => $now]);
            return $this->presentCustomer($db->table('customers')->where('tenant_id', $actor->tenantId)->where('id', $id)->first());
        });
    }

    /** @return array<string,mixed> */
    public function show(TenantStaffContext $actor, string $id): array
    {
        $this->require($actor, 'customers.view');
        $row = DB::connection(self::CONNECTION)->table('customers')->where('tenant_id', $actor->tenantId)->where('id', $id)->first();
        if ($row === null) throw TenantAccessException::objectNotFound();
        $customer = $this->presentCustomer($row);
        $customer['contacts'] = DB::connection(self::CONNECTION)->table('customer_contacts')->where('tenant_id', $actor->tenantId)->where('customer_id', $id)->orderByDesc('is_primary')->orderBy('display_name')->get()->map(fn (object $contact) => $this->presentContact($contact))->all();
        $customer['addresses'] = DB::connection(self::CONNECTION)->table('customer_addresses')->where('tenant_id', $actor->tenantId)->where('customer_id', $id)->orderBy('kind')->get()->map(fn (object $address) => $this->presentAddress($address))->all();
        return $customer;
    }

    /** @param array<string,mixed> $input @return array<string,mixed> */
    public function update(TenantStaffContext $actor, string $id, array $input): array
    {
        $this->require($actor, 'customers.manage');
        return $this->withinTransaction(DB::connection(self::CONNECTION), function (ConnectionInterface $db) use ($actor, $id, $input): array {
            $current = $this->customerForUpdate($actor, $id);
            $normalized = CustomerInput::normalizeCustomer([...$this->presentCustomer($current), ...$input]);
            $this->throwIfDuplicate($db, $actor->tenantId, $normalized['email'], $normalized['phone'], $id);
            $db->table('customers')->where('tenant_id', $actor->tenantId)->where('id', $id)->update([...$normalized, 'updated_at' => now('UTC')]);
            return $this->presentCustomer($db->table('customers')->where('tenant_id', $actor->tenantId)->where('id', $id)->first());
        });
    }

    /** @param array<string,mixed> $input @return array<string,mixed> */
    public function addContact(TenantStaffContext $actor, string $customerId, array $input): array
    {
        $this->require($actor, 'customers.manage');
        $contact = CustomerInput::normalizeContact($input);
        return $this->withinTransaction(DB::connection(self::CONNECTION), function (ConnectionInterface $db) use ($actor, $customerId, $contact): array {
            $this->assertCustomerExists($db, $actor->tenantId, $customerId, true);
            if ($contact['is_primary']) $db->table('customer_contacts')->where('tenant_id', $actor->tenantId)->where('customer_id', $customerId)->update(['is_primary' => false, 'updated_at' => now('UTC')]);
            $id = (string) Str::uuid7(); $now = now('UTC');
            $db->table('customer_contacts')->insert(['id' => $id, 'tenant_id' => $actor->tenantId, 'customer_id' => $customerId, ...$contact, 'created_at' => $now, 'updated_at' => $now]);
            return $this->presentContact($db->table('customer_contacts')->where('tenant_id', $actor->tenantId)->where('id', $id)->first());
        });
    }

    /** @return list<array<string,mixed>> */
    public function listContacts(TenantStaffContext $actor, string $customerId): array
    {
        $this->require($actor, 'customers.view');
        $db = DB::connection(self::CONNECTION);
        $this->assertCustomerExists($db, $actor->tenantId, $customerId, false);

        return $db->table('customer_contacts')->where('tenant_id', $actor->tenantId)
            ->where('customer_id', $customerId)->orderByDesc('is_primary')->orderBy('display_name')
            ->get()->map(fn (object $contact) => $this->presentContact($contact))->all();
    }

    /** @param array<string,mixed> $input @return array<string,mixed> */
    public function updateContact(TenantStaffContext $actor, string $customerId, string $contactId, array $input): array
    {
        $this->require($actor, 'customers.manage');

        return $this->withinTransaction(DB::connection(self::CONNECTION), function (ConnectionInterface $db) use ($actor, $customerId, $contactId, $input): array {
            $this->assertCustomerExists($db, $actor->tenantId, $customerId, true);
            $current = $db->table('customer_contacts')->where('tenant_id', $actor->tenantId)
                ->where('customer_id', $customerId)->where('id', $contactId)->lockForUpdate()->first();
            if ($current === null) throw TenantAccessException::objectNotFound();
            $contact = CustomerInput::normalizeContact([...$this->presentContact($current), ...$input]);
            if ($contact['is_primary']) {
                $db->table('customer_contacts')->where('tenant_id', $actor->tenantId)->where('customer_id', $customerId)
                    ->where('id', '<>', $contactId)->update(['is_primary' => false, 'updated_at' => now('UTC')]);
            }
            $db->table('customer_contacts')->where('tenant_id', $actor->tenantId)->where('customer_id', $customerId)
                ->where('id', $contactId)->update([...$contact, 'updated_at' => now('UTC')]);

            return $this->presentContact($db->table('customer_contacts')->where('tenant_id', $actor->tenantId)->where('id', $contactId)->first());
        });
    }

    /** @return list<array<string,mixed>> */
    public function listAddresses(TenantStaffContext $actor, string $customerId): array
    {
        $this->require($actor, 'customers.view');
        $db = DB::connection(self::CONNECTION);
        $this->assertCustomerExists($db, $actor->tenantId, $customerId, false);

        return $db->table('customer_addresses')->where('tenant_id', $actor->tenantId)
            ->where('customer_id', $customerId)->orderBy('kind')->get()
            ->map(fn (object $address) => $this->presentAddress($address))->all();
    }

    /** @param array<string,mixed> $input @return array<string,mixed> */
    public function addAddress(TenantStaffContext $actor, string $customerId, array $input): array
    {
        $this->require($actor, 'customers.manage');
        $address = CustomerInput::normalizeAddress($input);

        return $this->withinTransaction(DB::connection(self::CONNECTION), function (ConnectionInterface $db) use ($actor, $customerId, $address): array {
            $this->assertCustomerExists($db, $actor->tenantId, $customerId, true);
            $id = (string) Str::uuid7(); $now = now('UTC');
            $db->table('customer_addresses')->insert(['id' => $id, 'tenant_id' => $actor->tenantId, 'customer_id' => $customerId,
                ...$address, 'created_at' => $now, 'updated_at' => $now]);

            return $this->presentAddress($db->table('customer_addresses')->where('tenant_id', $actor->tenantId)->where('id', $id)->first());
        });
    }

    /** @param array<string,mixed> $input @return array<string,mixed> */
    public function updateAddress(TenantStaffContext $actor, string $customerId, string $addressId, array $input): array
    {
        $this->require($actor, 'customers.manage');

        return $this->withinTransaction(DB::connection(self::CONNECTION), function (ConnectionInterface $db) use ($actor, $customerId, $addressId, $input): array {
            $this->assertCustomerExists($db, $actor->tenantId, $customerId, true);
            $current = $db->table('customer_addresses')->where('tenant_id', $actor->tenantId)
                ->where('customer_id', $customerId)->where('id', $addressId)->lockForUpdate()->first();
            if ($current === null) throw TenantAccessException::objectNotFound();
            $address = CustomerInput::normalizeAddress([...$this->presentAddress($current), ...$input]);
            $db->table('customer_addresses')->where('tenant_id', $actor->tenantId)->where('customer_id', $customerId)
                ->where('id', $addressId)->update([...$address, 'updated_at' => now('UTC')]);

            return $this->presentAddress($db->table('customer_addresses')->where('tenant_id', $actor->tenantId)->where('id', $addressId)->first());
        });
    }

    /** @param array<string,mixed> $input @return array<string,mixed> */
    public function convertLead(TenantStaffContext $actor, string $leadId, array $input): array
    {
        $this->require($actor, 'leads.convert');
        $this->require($actor, 'customers.manage');
        $customer = CustomerInput::normalizeCustomer($input['customer'] ?? []);
        $contact = isset($input['contact']) && is_array($input['contact']) ? CustomerInput::normalizeContact($input['contact']) : null;
        $fingerprint = CustomerInput::conversionFingerprint($customer, $contact);
        return $this->withinTransaction(DB::connection(self::CONNECTION), function (ConnectionInterface $db) use ($actor, $leadId, $customer, $contact, $fingerprint): array {
            $lead = $db->table('leads')->where('tenant_id', $actor->tenantId)->where('id', $leadId)->lockForUpdate()->first();
            if ($lead === null) throw TenantAccessException::objectNotFound();
            $existing = $db->table('lead_conversions')->where('tenant_id', $actor->tenantId)->where('lead_id', $leadId)->lockForUpdate()->first();
            if ($existing !== null) {
                if (!hash_equals($existing->payload_hash, $fingerprint)) throw new LeadConversionConflictException('Conversion intent conflicts with existing result.');
                return $this->presentConversion($db, $actor->tenantId, $existing);
            }
            $this->throwIfDuplicate($db, $actor->tenantId, $customer['email'], $customer['phone']);
            $customerId = (string) Str::uuid7(); $now = now('UTC');
            $db->table('customers')->insert(['id' => $customerId, 'tenant_id' => $actor->tenantId, ...$customer,
                'source_lead_id' => $leadId, 'created_by_membership_id' => $actor->membershipId, 'created_at' => $now, 'updated_at' => $now]);
            $contactId = null;
            if ($contact !== null) { $contactId = (string) Str::uuid7(); $db->table('customer_contacts')->insert(['id' => $contactId, 'tenant_id' => $actor->tenantId, 'customer_id' => $customerId, ...$contact, 'created_at' => $now, 'updated_at' => $now]); }
            $conversionId = (string) Str::uuid7();
            $db->table('lead_conversions')->insert(['id' => $conversionId, 'tenant_id' => $actor->tenantId, 'lead_id' => $leadId, 'customer_id' => $customerId, 'contact_id' => $contactId, 'payload_hash' => $fingerprint, 'converted_by_membership_id' => $actor->membershipId, 'converted_at' => $now]);
            return $this->presentConversion($db, $actor->tenantId, (object) ['id' => $conversionId, 'lead_id' => $leadId, 'customer_id' => $customerId, 'contact_id' => $contactId, 'converted_at' => $now]);
        });
    }

    private function require(TenantStaffContext $actor, string $permission): void { if (!in_array(null, $this->authorization->effectiveGrants($actor)[$permission] ?? [], true)) throw new AuthorizationDeniedException; }
    private function withinTransaction(ConnectionInterface $db, \Closure $operation): mixed { try { return $db->transaction(fn () => $operation($db)); } catch (QueryException $exception) { if (($exception->errorInfo[0] ?? $exception->getCode()) === '23505') throw new LeadConversionConflictException('A concurrent duplicate or conversion exists.'); throw $exception; } }
    private function customerForUpdate(TenantStaffContext $actor, string $id): object { $row = DB::connection(self::CONNECTION)->table('customers')->where('tenant_id', $actor->tenantId)->where('id', $id)->lockForUpdate()->first(); if ($row === null) throw TenantAccessException::objectNotFound(); return $row; }
    private function assertCustomerExists(ConnectionInterface $db, string $tenantId, string $id, bool $lock): void { $query=$db->table('customers')->where('tenant_id',$tenantId)->where('id',$id); if($lock) $query->lockForUpdate(); if($query->first()===null) throw TenantAccessException::objectNotFound(); }
    private function throwIfDuplicate(ConnectionInterface $db, string $tenantId, ?string $email, ?string $phone, ?string $exceptId = null): void { if($email===null && $phone===null)return; $query=$db->table('customers')->where('tenant_id',$tenantId)->where(function($q) use($email,$phone):void { if($email!==null)$q->orWhere('email',$email);if($phone!==null)$q->orWhere('phone',$phone);});if($exceptId!==null)$query->where('id','<>',$exceptId);if($query->lockForUpdate()->exists())throw new LeadConversionConflictException('A duplicate customer candidate exists.'); }
    /** @return array<string,mixed> */ private function presentCustomer(object $row): array { return ['id'=>$row->id,'type'=>$row->type,'display_name'=>$row->display_name,'legal_name'=>$row->legal_name,'email'=>$row->email,'phone'=>$row->phone,'country_code'=>$row->country_code,'status'=>$row->status,'source_lead_id'=>$row->source_lead_id,'created_at'=>$row->created_at,'updated_at'=>$row->updated_at]; }
    /** @return array<string,mixed> */ private function presentContact(object $row): array { return ['id'=>$row->id,'customer_id'=>$row->customer_id,'display_name'=>$row->display_name,'email'=>$row->email,'phone'=>$row->phone,'job_title'=>$row->job_title,'note'=>$row->note,'is_primary'=>(bool)$row->is_primary]; }
    /** @return array<string,mixed> */ private function presentAddress(object $row): array { return ['id'=>$row->id,'customer_id'=>$row->customer_id,'kind'=>$row->kind,'line1'=>$row->line1,'line2'=>$row->line2,'city'=>$row->city,'region'=>$row->region,'postal_code'=>$row->postal_code,'country_code'=>$row->country_code]; }
    /** @return array<string,mixed> */ private function presentConversion(ConnectionInterface $db,string $tenantId,object $conversion): array { $customer=$db->table('customers')->where('tenant_id',$tenantId)->where('id',$conversion->customer_id)->first();return ['id'=>$conversion->id,'lead_id'=>$conversion->lead_id,'customer'=>$this->presentCustomer($customer),'contact_id'=>$conversion->contact_id,'converted_at'=>$conversion->converted_at]; }
}
