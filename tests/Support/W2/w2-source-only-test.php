<?php

declare(strict_types=1);

use App\Modules\Tenancy\Application\CustomerInput;
use App\Modules\Tenancy\Domain\CustomerInputException;

require_once __DIR__.'/../../../vendor/autoload.php';

/** @param array<string,mixed> $input */
function customer(array $input): array { return CustomerInput::normalizeCustomer($input); }
/** @param callable():void $callback */
function rejects(callable $callback): void { try { $callback(); } catch (CustomerInputException) { return; } throw new RuntimeException('Expected validation rejection.'); }

$person = customer(['type' => 'PERSON', 'display_name' => 'Ada Example', 'email' => 'ADA@Example.Test', 'phone' => '+20 100 000 0000', 'country_code' => 'eg']);
if ($person['email'] !== 'ada@example.test' || $person['country_code'] !== 'EG' || $person['legal_name'] !== null) throw new RuntimeException('Person normalization failed.');
$organization = customer(['type' => 'ORGANIZATION', 'display_name' => 'Example Co', 'legal_name' => 'Example Company LLC']);
if ($organization['type'] !== 'ORGANIZATION') throw new RuntimeException('Organization normalization failed.');
rejects(fn () => customer(['type' => 'ORGANIZATION', 'display_name' => 'Example Co']));
rejects(fn () => customer(['type' => 'PERSON', 'display_name' => 'Ada', 'country_code' => 'EGY']));
rejects(fn () => customer(['type' => 'PERSON', 'display_name' => 'Ada', 'email' => 'not-an-email']));
$contact = CustomerInput::normalizeContact(['display_name' => 'Ada Example', 'email' => 'ada@example.test', 'is_primary' => true]);
$address = CustomerInput::normalizeAddress(['kind' => 'BILLING', 'line1' => '42 Example Street', 'country_code' => 'eg']);
if ($address['kind'] !== 'BILLING' || $address['country_code'] !== 'EG') throw new RuntimeException('Address normalization failed.');
rejects(fn () => CustomerInput::normalizeAddress(['kind' => 'UNTRUSTED', 'line1' => 'Example']));
rejects(fn () => CustomerInput::normalizeAddress(['kind' => 'GENERAL']));
$first = CustomerInput::conversionFingerprint($person, $contact); $same = CustomerInput::conversionFingerprint($person, $contact); $changed = CustomerInput::conversionFingerprint([...$person, 'display_name' => 'Different'], $contact);
if (!hash_equals($first, $same) || hash_equals($first, $changed)) throw new RuntimeException('Conversion fingerprint contract failed.');
$root = dirname(__DIR__, 3);
$routes = file_get_contents($root.'/routes/api.php');
$migration = file_get_contents($root.'/database/migrations/2026_11_06_000066_create_customers_contacts_and_lead_conversions.php');
$followUpMigration = file_get_contents($root.'/database/migrations/2026_11_06_000067_extend_customer_contact_and_address_runtime_grants.php');
$hardeningMigration = file_get_contents($root.'/database/migrations/2026_11_06_000068_harden_w2_address_and_conversion_constraints.php');
$customerService = file_get_contents($root.'/app/Modules/Tenancy/Application/CustomerService.php');
foreach (["Route::post('/leads/{lead}/convert'", "Route::get('/customers'", "Route::post('/customers/{customer}/contacts'", "Route::patch('/customers/{customer}/contacts/{contact}'", "Route::post('/customers/{customer}/addresses'", "Route::patch('/customers/{customer}/addresses/{address}'"] as $needle) if (!str_contains((string) $routes, $needle)) throw new RuntimeException('Missing W2 route contract.');
foreach (['FORCE ROW LEVEL SECURITY', 'customers_tenant_source_lead_unique', 'conversions_tenant_lead_unique', 'customers_tenant_email_unique', 'REVOKE ALL ON TABLE'] as $needle) if (!str_contains((string) $migration, $needle)) throw new RuntimeException('Missing W2 schema safety contract.');
foreach (['GRANT UPDATE (display_name, email, phone, job_title, note, is_primary, updated_at)', 'GRANT INSERT (id, tenant_id, customer_id, kind, line1', 'GRANT UPDATE (kind, line1, line2, city, region, postal_code, country_code, updated_at)'] as $needle) if (!str_contains((string) $followUpMigration, $needle)) throw new RuntimeException('Missing W2 runtime-grant contract.');
foreach (['presentAddress($address)', 'contacts_tenant_customer_id_unique', 'conversions_contact_customer_tenant_fk', 'REVOKE SELECT ON TABLE public.customer_addresses', 'GRANT SELECT (id, tenant_id, customer_id, kind, line1'] as $needle) if (!str_contains((string) $hardeningMigration.$customerService, $needle)) throw new RuntimeException('Missing W2 stabilization contract.');
foreach (['?string $status', "if (\$status !== null) \$query->where('status', \$status)"] as $needle) if (!str_contains((string) $customerService, $needle)) throw new RuntimeException('Missing W2 lifecycle filter contract.');
echo "W2_SOURCE_ONLY_TEST=PASS\n";
