<?php

declare(strict_types=1);

namespace Tests\Support\W1Fixture;

/**
 * Source-only contract for a future, isolated W1 acceptance fixture.
 *
 * This is deliberately data only: it neither bootstraps Laravel nor opens a
 * database connection. A future runtime supervisor must attest every value
 * against its owned environment before it may call the real application
 * services listed below.
 */
final class W1FixturePrerequisiteManifest
{
    /** @return array<string, mixed> */
    public static function definition(): array
    {
        return [
            'schema_version' => 1,
            'kind' => 'SOURCE_ONLY_TEST_FIXTURE_PREREQUISITES',
            'execution' => [
                'app_env' => 'testing',
                'requires_owned_environment_attestation' => true,
                'forbids_database_or_network_in_dry_run' => true,
                'forbids_protected_system_identifiers' => [
                    '7702918948384706599', // G2
                    '7703536724085506088', // G3
                ],
            ],
            'secrets' => [
                'CORE01_SQL_SIGNING_KEY' => ['format' => 'lowercase-hex-64', 'source' => 'config/core_sql.php:8'],
                'CORE01_PROVIDER_PROOF_KEY' => ['format' => 'lowercase-hex-64', 'source' => 'config/core_sql.php:10'],
                'CORE01_SESSION_BINDING_KEY' => ['format' => 'external-secret-required', 'source' => 'config/core_sql.php:11-13'],
            ],
            'sql_principals' => [
                'dl_provider' => 'config/database.php:102-115',
                'dl_provider_ctl' => 'config/database.php:117-129',
                'dl_provider_issuer' => 'config/database.php:130-141',
                'daleel_core01_authority_definer' => 'database/migrations/2026_10_29_000059_tenant_authority_definer_owner.php',
                'daleel_tenant_auth_lookup' => 'database/migrations/2026_10_12_000026_create_tenant_staff_authentication_access.php',
            ],
            'synthetic_fixture_scope' => [
                'provider_user' => 'unique synthetic provider identity; seed only in an owned attested run',
                'tenant' => 'unique tenant slug and canonical host under test.invalid',
                'first_admin' => 'unique pending activation identity; activation only via authority service',
                'lead' => 'unique tenant-bound lead for post-login acceptance',
                'duplicate_precondition' => 'external attestation must state that this run identifier has no existing fixture rows',
                'source' => 'app/Modules/Provider/Domain/CanonicalTenantHost.php; tests/Support/Provider/Eng06ProviderActorFixtureSeeder.php:62-116',
            ],
            'migration_order' => [
                '2026_10_17_000028_version_provider_provision_approvals.php',
                '2026_10_28_000039_require_trusted_tenant_sql_login.php',
                '2026_10_28_000049_core01_fresh_install_runtime_lockdown.php',
                '2026_10_28_000049_signed_tenant_sql_boundary.php',
                '2026_10_28_000051_provider_v1_bound_proof.php',
                '2026_10_28_000056_provider_authority_sessions_and_receipts.php',
                '2026_10_29_000059_tenant_authority_definer_owner.php',
                '2026_10_31_000064_core01_first_admin_activation_authority.php',
                '2026_11_04_000065_revoke_public_active_signing_generation.php',
            ],
            'real_runtime_path' => [
                'provider_login_mfa_step_up' => 'app/Modules/Provider/Application/ProviderAuthenticationService.php:27-162',
                'provider_authority_receipt' => 'app/Modules/Provider/Application/ProviderAuthorityService.php:37-97',
                'direct_company_provision' => 'app/Modules/Provider/Application/ProviderDirectProvisionService.php:18-120',
                'first_admin_activation' => 'app/Modules/Identity/Application/FirstAdminActivationAuthorityService.php:23-110',
                'tenant_leads' => 'routes/api.php:94-103',
            ],
            'forbidden_shortcuts' => [
                'No HTTP fixture endpoint.',
                'No direct creation of runtime session, step-up, authority receipt, or tenant authority.',
                'No use of provider:bootstrap-root: it is a one-time root command, not a fixture API.',
                'No direct invocation of Eng06ProviderActorFixtureSeeder outside an owned, attested database run.',
            ],
        ];
    }
}
