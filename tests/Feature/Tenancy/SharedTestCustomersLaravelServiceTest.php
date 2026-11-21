<?php

declare(strict_types=1);

namespace Tests\Feature\Tenancy;

use App\Modules\Identity\Application\TenantStaffAuthorizationService;
use App\Modules\Identity\Domain\TenantStaffContext;
use App\Modules\Tenancy\Application\CustomerService;
use App\Modules\Tenancy\Domain\AuthorizationDeniedException;
use App\Modules\Tenancy\Domain\CustomerInputException;
use App\Modules\Tenancy\Domain\LeadConversionConflictException;
use App\Modules\Tenancy\Domain\TenantAccessException;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

/** Functional-slice only: it is deliberately not an HTTP or signed-authority test. */
final class SharedTestCustomersLaravelServiceTest extends TestCase
{
    private const A = '11111111-1111-1111-1111-111111111111';
    private const B = '22222222-2222-2222-2222-222222222222';

    protected function setUp(): void
    {
        parent::setUp();
        self::assertSame('1', getenv('DCRM_SHARED_TEST_SERVICE_RUNNER'));
        self::assertSame('customer_service_functional_v1', getenv('DCRM_SHARED_TEST_SUITE'));
    }

    public function test_laravel_pdo_is_the_limited_runtime_role_and_manage_flow_uses_real_services(): void
    {
        $this->tenant(self::A);
        $db = DB::connection('pgsql_tenant_runtime');
        $identity = $db->selectOne('select current_database() database, current_user current_user, session_user session_user, r.rolsuper, r.rolbypassrls from pg_roles r where r.rolname = current_user');
        self::assertSame((string) getenv('TENANT_RUNTIME_DB_DATABASE'), $identity->database);
        self::assertSame('dcrm_shared_runtime', $identity->current_user);
        self::assertSame('dcrm_shared_runtime', $identity->session_user);
        self::assertFalse((bool) $identity->rolsuper);
        self::assertFalse((bool) $identity->rolbypassrls);

        $service = app(CustomerService::class); $actor = $this->actor(self::A, '33333333-3333-3333-3333-333333333333');
        $grants = app(TenantStaffAuthorizationService::class)->effectiveGrants($actor);
        self::assertArrayHasKey('customers.manage', $grants); self::assertArrayHasKey('leads.convert', $grants);
        $created = $service->create($actor, ['display_name' => 'Laravel A', 'email' => 'laravel.a@example.test', 'phone' => '+20123456789', 'country_code' => 'EG']);
        self::assertSame('ACTIVE', $created['status']);
        self::assertSame(1, $service->list($actor, 'laravel a', null, 1, 20)['meta']['total']);
        self::assertSame(1, $service->list($actor, '', 'ACTIVE', 1, 20)['meta']['total']);
        $changed = $service->update($actor, $created['id'], ['display_name' => 'Laravel A Updated', 'email' => 'laravel.a@example.test', 'phone' => '+20123456789', 'status' => 'INACTIVE']);
        self::assertSame('INACTIVE', $changed['status']);
        self::assertSame('ACTIVE', $service->update($actor, $created['id'], ['display_name' => 'Laravel A Updated', 'email' => 'laravel.a@example.test', 'phone' => '+20123456789', 'status' => 'ACTIVE'])['status']);
        $contact = $service->addContact($actor, $created['id'], ['display_name' => 'Contact A', 'email' => 'contact.a@example.test', 'is_primary' => true]);
        self::assertCount(1, $service->listContacts($actor, $created['id']));
        self::assertSame('Contact A+', $service->updateContact($actor, $created['id'], $contact['id'], ['display_name' => 'Contact A+', 'email' => 'contact.a@example.test', 'is_primary' => true])['display_name']);
        $address = $service->addAddress($actor, $created['id'], ['kind' => 'GENERAL', 'line1' => '1 Laravel Way', 'city' => 'Cairo', 'country_code' => 'EG']);
        self::assertCount(1, $service->listAddresses($actor, $created['id']));
        self::assertSame('2 Laravel Way', $service->updateAddress($actor, $created['id'], $address['id'], ['kind' => 'GENERAL', 'line1' => '2 Laravel Way', 'city' => 'Cairo', 'country_code' => 'EG'])['line1']);
        $conversion = $service->convertLead($actor, 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', ['customer' => ['display_name' => 'Converted A', 'email' => 'converted.a@example.test'], 'contact' => ['display_name' => 'Converted contact']]);
        self::assertSame('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', $conversion['lead_id']);
        self::assertSame($conversion['id'], $service->convertLead($actor, 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', ['customer' => ['display_name' => 'Converted A', 'email' => 'converted.a@example.test'], 'contact' => ['display_name' => 'Converted contact']])['id']);
        $this->expectException(LeadConversionConflictException::class);
        $service->create($actor, ['display_name' => 'Duplicate', 'email' => 'laravel.a@example.test']);
    }

    public function test_invalid_and_authorization_denials_are_enforced_by_the_real_services(): void
    {
        $this->tenant(self::A); $service = app(CustomerService::class);
        $this->expectException(CustomerInputException::class);
        $service->create($this->actor(self::A, '33333333-3333-3333-3333-333333333333'), ['display_name' => '']);
    }

    public function test_view_only_no_grant_and_ab_functional_isolation_are_enforced(): void
    {
        $service = app(CustomerService::class);
        $this->tenant(self::A); $viewOnly = $this->actor(self::A, '55555555-5555-5555-5555-555555555555');
        self::assertArrayHasKey('customers.view', app(TenantStaffAuthorizationService::class)->effectiveGrants($viewOnly));
        try { $service->create($viewOnly, ['display_name' => 'Denied']); self::fail('view-only must not write'); } catch (AuthorizationDeniedException) { self::addToAssertionCount(1); }
        try { $service->list($this->actor(self::A, '66666666-6666-6666-6666-666666666666'), '', null, 1, 10); self::fail('no-grant must not read'); } catch (AuthorizationDeniedException) { self::addToAssertionCount(1); }
        $this->tenant(self::B); $b = $service->create($this->actor(self::B, '77777777-7777-7777-7777-777777777777'), ['display_name' => 'Tenant B only', 'email' => 'b.only@example.test']);
        $this->tenant(self::A); self::assertSame([], $service->list($this->actor(self::A, '33333333-3333-3333-3333-333333333333'), 'tenant b only', null, 1, 10)['data']);
        $this->expectException(TenantAccessException::class);
        $service->show($this->actor(self::A, '33333333-3333-3333-3333-333333333333'), $b['id']);
    }

    private function tenant(string $id): void { DB::connection('pgsql_tenant_runtime')->selectOne("select set_config('app.tenant_id', ?, false)", [$id]); }
    private function actor(string $tenant, string $membership): TenantStaffContext { return new TenantStaffContext($tenant, $tenant === self::A ? 'a.test' : 'b.test', 'aaaaaaaa-0000-0000-0000-000000000000', $membership, 1, 1); }
}
