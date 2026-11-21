<?php

declare(strict_types=1);

namespace Tests\Support\W1Fixture;

/** Pure validator; it has no Laravel, PDO, filesystem, or network dependency. */
final class W1FixturePrerequisiteValidator
{
    /** @var list<string> */
    private const PROTECTED_SYSTEM_IDENTIFIERS = ['7702918948384706599', '7703536724085506088'];

    /** @var list<string> */
    private const REQUIRED_ROLES = [
        'dl_provider', 'dl_provider_ctl', 'dl_provider_issuer',
        'daleel_core01_authority_definer', 'daleel_tenant_auth_lookup',
    ];

    /**
     * Validates supplied attestation metadata only. It never discovers or
     * connects to a database; a future runner must obtain these facts through
     * its separately reviewed trusted execution boundary.
     *
     * @param array<string, mixed> $facts
     * @return array{status:string,checked:list<string>}
     */
    public static function validateDryRun(array $facts): array
    {
        self::requiredString($facts, 'app_env', 'APP_ENV');
        if ($facts['app_env'] !== 'testing') {
            self::reject('APP_ENV_NOT_TESTING');
        }

        if (($facts['owned_environment_attested'] ?? false) !== true) {
            self::reject('OWNERSHIP_ATTESTATION_REQUIRED');
        }

        $systemIdentifier = self::requiredString($facts, 'postgres_system_identifier', 'POSTGRES_SYSTEM_IDENTIFIER');
        if (!preg_match('/^[1-9][0-9]{5,}$/D', $systemIdentifier) || in_array($systemIdentifier, self::PROTECTED_SYSTEM_IDENTIFIERS, true)) {
            self::reject('UNSAFE_DATABASE_IDENTITY');
        }

        $transport = self::requiredString($facts, 'database_transport', 'DATABASE_TRANSPORT');
        if ($transport !== 'isolated-container-network') {
            self::reject('UNSAFE_DATABASE_TRANSPORT');
        }

        $host = strtolower(self::requiredString($facts, 'database_host', 'DATABASE_HOST'));
        if (in_array($host, ['localhost', '127.0.0.1', '::1', 'host.docker.internal'], true)
            || !preg_match('/^[a-z0-9][a-z0-9.-]*\.test\.invalid$/D', $host)) {
            self::reject('UNSAFE_DATABASE_HOST');
        }

        $databaseName = self::requiredString($facts, 'database_name', 'DATABASE_NAME');
        if (preg_match('/^(g2_accept01|g3_accept_isolated)$/D', $databaseName) === 1
            || preg_match('/^w1_fixture_[a-z0-9_]+$/D', $databaseName) !== 1) {
            self::reject('UNSAFE_DATABASE_NAME');
        }

        $runId = self::requiredString($facts, 'fixture_run_id', 'FIXTURE_RUN_ID');
        if (preg_match('/^w1fixture-[a-z0-9]{10,48}$/D', $runId) !== 1
            || ($facts['duplicate_fixture_exists'] ?? null) !== false) {
            self::reject('FIXTURE_UNIQUENESS_REQUIRED');
        }

        $tenantSlug = self::requiredString($facts, 'tenant_slug', 'TENANT_SLUG');
        $tenantHost = strtolower(self::requiredString($facts, 'tenant_host', 'TENANT_HOST'));
        if (preg_match('/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/D', $tenantSlug) !== 1
            || $tenantHost !== $tenantSlug.'.test.invalid') {
            self::reject('TENANT_SCOPE_ATTESTATION_REQUIRED');
        }

        $keys = $facts['keys'] ?? null;
        if (!is_array($keys)
            || !self::isLowerHex64($keys['sql_signing'] ?? null)
            || !self::isLowerHex64($keys['provider_proof'] ?? null)
            || !is_string($keys['session_binding_present'] ?? null)
            || $keys['session_binding_present'] !== 'present') {
            self::reject('INVALID_OR_MISSING_SECRET_PREREQUISITE');
        }

        $roles = $facts['roles'] ?? null;
        if (!is_array($roles)) {
            self::reject('ROLE_ATTESTATION_REQUIRED');
        }
        foreach (self::REQUIRED_ROLES as $role) {
            if (($roles[$role] ?? false) !== true) {
                self::reject('ROLE_ATTESTATION_REQUIRED');
            }
        }

        if (($facts['provider_authority_enabled'] ?? false) !== true
            || ($facts['activation_authority_enabled'] ?? false) !== true) {
            self::reject('AUTHORITY_FEATURE_ATTESTATION_REQUIRED');
        }

        return [
            'status' => 'DRY_RUN_PREREQUISITES_VALID',
            'checked' => [
                'testing_environment', 'owned_environment_attestation', 'non_protected_database_identity',
                'isolated_transport', 'safe_database_host_and_name', 'secret_formats_without_disclosure',
                'fixture_uniqueness', 'tenant_scope', 'required_roles', 'authority_feature_flags',
            ],
        ];
    }

    private static function requiredString(array $facts, string $key, string $code): string
    {
        $value = $facts[$key] ?? null;
        if (!is_string($value) || $value === '') {
            self::reject($code.'_REQUIRED');
        }

        return $value;
    }

    private static function isLowerHex64(mixed $value): bool
    {
        return is_string($value) && preg_match('/^[a-f0-9]{64}$/D', $value) === 1;
    }

    private static function reject(string $code): never
    {
        throw new W1FixturePrerequisiteViolation($code);
    }
}
