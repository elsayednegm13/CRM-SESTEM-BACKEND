<?php

declare(strict_types=1);

use Tests\Support\W1Fixture\W1FixturePrerequisiteManifest;
use Tests\Support\W1Fixture\W1FixturePrerequisiteValidator;
use Tests\Support\W1Fixture\W1FixturePrerequisiteViolation;

require_once __DIR__.'/W1FixturePrerequisiteManifest.php';
require_once __DIR__.'/W1FixturePrerequisiteViolation.php';
require_once __DIR__.'/W1FixturePrerequisiteValidator.php';

/** @return array<string, mixed> */
function validFacts(): array
{
    return [
        'app_env' => 'testing',
        'owned_environment_attested' => true,
        'postgres_system_identifier' => '7704999912345678901',
        'database_transport' => 'isolated-container-network',
        'database_host' => 'w1-fixture-pg.test.invalid',
        'database_name' => 'w1_fixture_sourceonly',
        'fixture_run_id' => 'w1fixture-sourceonly202611',
        'duplicate_fixture_exists' => false,
        'tenant_slug' => 'fixture-a',
        'tenant_host' => 'fixture-a.test.invalid',
        'keys' => [
            'sql_signing' => str_repeat('a', 64),
            'provider_proof' => str_repeat('b', 64),
            'session_binding_present' => 'present',
        ],
        'roles' => [
            'dl_provider' => true,
            'dl_provider_ctl' => true,
            'dl_provider_issuer' => true,
            'daleel_core01_authority_definer' => true,
            'daleel_tenant_auth_lookup' => true,
        ],
        'provider_authority_enabled' => true,
        'activation_authority_enabled' => true,
    ];
}

/** @param array<string, mixed> $facts */
function expectReject(array $facts, string $expectedCode): void
{
    try {
        W1FixturePrerequisiteValidator::validateDryRun($facts);
    } catch (W1FixturePrerequisiteViolation $error) {
        if ($error->getMessage() !== $expectedCode) {
            throw new RuntimeException("Expected {$expectedCode}, got {$error->getMessage()}");
        }
        return;
    }

    throw new RuntimeException("Expected rejection {$expectedCode}");
}

$manifest = W1FixturePrerequisiteManifest::definition();
if (($manifest['execution']['forbids_database_or_network_in_dry_run'] ?? false) !== true
    || count($manifest['migration_order'] ?? []) < 9) {
    throw new RuntimeException('Manifest safety contract is incomplete.');
}

$positive = W1FixturePrerequisiteValidator::validateDryRun(validFacts());
if ($positive['status'] !== 'DRY_RUN_PREREQUISITES_VALID' || count($positive['checked']) !== 10) {
    throw new RuntimeException('Positive source-only validation failed.');
}

$facts = validFacts(); $facts['app_env'] = 'production'; expectReject($facts, 'APP_ENV_NOT_TESTING');
$facts = validFacts(); $facts['owned_environment_attested'] = false; expectReject($facts, 'OWNERSHIP_ATTESTATION_REQUIRED');
$facts = validFacts(); $facts['postgres_system_identifier'] = '7703536724085506088'; expectReject($facts, 'UNSAFE_DATABASE_IDENTITY');
$facts = validFacts(); $facts['database_host'] = '127.0.0.1'; expectReject($facts, 'UNSAFE_DATABASE_HOST');
$facts = validFacts(); $facts['duplicate_fixture_exists'] = true; expectReject($facts, 'FIXTURE_UNIQUENESS_REQUIRED');
$facts = validFacts(); $facts['tenant_host'] = 'fixture-b.test.invalid'; expectReject($facts, 'TENANT_SCOPE_ATTESTATION_REQUIRED');
$facts = validFacts(); $facts['keys']['provider_proof'] = 'invalid'; expectReject($facts, 'INVALID_OR_MISSING_SECRET_PREREQUISITE');
$facts = validFacts(); $facts['roles']['dl_provider_issuer'] = false; expectReject($facts, 'ROLE_ATTESTATION_REQUIRED');
$facts = validFacts(); $facts['activation_authority_enabled'] = false; expectReject($facts, 'AUTHORITY_FEATURE_ATTESTATION_REQUIRED');

echo "W1_FIXTURE_SOURCE_ONLY_TEST=PASS\n";
