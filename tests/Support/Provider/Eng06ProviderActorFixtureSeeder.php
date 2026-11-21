<?php

declare(strict_types=1);

namespace Tests\Support\Provider;

use App\Modules\Provider\Infrastructure\Persistence\ProviderUser;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use OTPHP\TOTP;
use PDOException;
use RuntimeException;
use Throwable;

/** Explicit, opt-in initializer for exactly the two current ENG-06 synthetic Provider actors. */
final class Eng06ProviderActorFixtureSeeder
{
    private const PROVIDER_CONNECTION = 'pgsql_provider';

    private const PROVIDER_CONTROL_CONNECTION = 'pgsql_provider_control';

    private const REQUESTER_CAPABILITY = 'company.provision';

    private const REVIEWER_CAPABILITY = 'provider.approval.review';

    /**
     * @return array{
     *     tag:string,
     *     run_prefix:string,
     *     requester_provider_user_id:string,
     *     reviewer_provider_user_id:string,
     *     capabilities:array{requester:string,reviewer:string},
     *     completed_stages:list<string>,
     *     aggregate_counts:array{provider_users:int,provider_mfa_totp:int,provider_user_capabilities:int}
     * }
     */
    public static function initialize(Eng06ProviderActorFixtureInput $input): array
    {
        $stage = 'S00_INPUT';

        try {
            self::validateRuntimeAndInput($input);

            $stage = 'S10_CONNECTION_ALIASES';
            $provider = DB::connection(self::PROVIDER_CONNECTION);
            $control = DB::connection(self::PROVIDER_CONTROL_CONNECTION);

            if ($provider->getDriverName() !== 'pgsql' || $control->getDriverName() !== 'pgsql'
                || $provider->transactionLevel() !== 0 || $control->transactionLevel() !== 0) {
                self::refuse($stage, 'ROLE_POLICY');
            }

            $providerFacts = self::connectionFacts($provider);
            $controlFacts = self::connectionFacts($control);
            self::assertConnectionFacts($input, $providerFacts, $controlFacts);

            $stage = 'S20_PROVIDER_PRIVILEGES';
            self::assertProviderTablePrivileges($provider);

            $stage = 'S30_VIRGIN_STATE_AND_CATALOG';
            self::assertVirginProviderState($provider);
            self::assertRequiredCapabilities($provider);

            $stage = 'S40_REQUESTER';
            $now = now('UTC');
            if (! $now instanceof Carbon) {
                self::refuse($stage, 'UNKNOWN');
            }

            $requesterId = '';
            $reviewerId = '';
            $provider->transaction(function () use ($input, $provider, $now, &$stage, &$requesterId, &$reviewerId): void {
                $stage = 'S30_VIRGIN_STATE_AND_CATALOG';
                self::assertVirginProviderState($provider);
                self::assertRequiredCapabilities($provider);

                $stage = 'S40_REQUESTER';
                $requester = self::createActor(
                    'requester.'.$input->tag().'.eng06@example.invalid',
                    $input->requesterPassword(),
                    $now,
                    'S40_REQUESTER',
                );
                $requesterId = (string) $requester->getKey();

                $stage = 'S41_REVIEWER';
                $reviewer = self::createActor(
                    'reviewer.'.$input->tag().'.eng06@example.invalid',
                    $input->reviewerPassword(),
                    $now,
                    'S41_REVIEWER',
                );
                $reviewerId = (string) $reviewer->getKey();
                if ($requesterId === '' || $reviewerId === '' || $requesterId === $reviewerId) {
                    self::refuse($stage, 'UNKNOWN');
                }

                $stage = 'S50_MFA_REQUESTER';
                self::persistTotp($provider, $requesterId, $input->requesterTotpSecret(), $now, 'S50_MFA_REQUESTER');

                $stage = 'S51_MFA_REVIEWER';
                self::persistTotp($provider, $reviewerId, $input->reviewerTotpSecret(), $now, 'S51_MFA_REVIEWER');

                $stage = 'S60_GRANT_REQUESTER';
                self::grantCapability($provider, $requesterId, self::REQUESTER_CAPABILITY, $now, 'S60_GRANT_REQUESTER');

                $stage = 'S61_GRANT_REVIEWER';
                self::grantCapability($provider, $reviewerId, self::REVIEWER_CAPABILITY, $now, 'S61_GRANT_REVIEWER');

                $stage = 'S70_VERIFY';
                self::verifyCreatedActors($provider, $requesterId, $reviewerId);

                $stage = 'S80_COMMIT';
            });

            return [
                'tag' => $input->tag(),
                'run_prefix' => $input->runPrefix(),
                'requester_provider_user_id' => $requesterId,
                'reviewer_provider_user_id' => $reviewerId,
                'capabilities' => [
                    'requester' => self::REQUESTER_CAPABILITY,
                    'reviewer' => self::REVIEWER_CAPABILITY,
                ],
                'completed_stages' => [
                    'S00_INPUT', 'S10_CONNECTION_ALIASES', 'S20_PROVIDER_PRIVILEGES',
                    'S30_VIRGIN_STATE_AND_CATALOG', 'S40_REQUESTER', 'S41_REVIEWER',
                    'S50_MFA_REQUESTER', 'S51_MFA_REVIEWER',
                    'S60_GRANT_REQUESTER', 'S61_GRANT_REVIEWER', 'S70_VERIFY', 'S80_COMMIT',
                ],
                'aggregate_counts' => [
                    'provider_users' => 2,
                    'provider_mfa_totp' => 2,
                    'provider_user_capabilities' => 2,
                ],
            ];
        } catch (Eng06ProviderActorFixtureFailure $failure) {
            throw $failure;
        } catch (Throwable $failure) {
            $category = $failure instanceof PDOException ? 'DATABASE_EXCEPTION' : 'UNKNOWN';
            throw new Eng06ProviderActorFixtureFailure($stage, $category, self::sqlState($failure));
        }
    }

    private static function validateRuntimeAndInput(Eng06ProviderActorFixtureInput $input): void
    {
        if (! app()->environment('testing') || ini_get('zend.exception_ignore_args') !== '1'
            || ! is_string(config('app.key')) || config('app.key') === '') {
            self::refuse('S00_INPUT', 'TARGET_GUARD');
        }

        $tag = $input->tag();
        $prefix = $input->runPrefix();
        if (! in_array($tag, ['a', 'b', 'c'], true)
            || preg_match('/^eng06a_20261017_[a-f0-9]{8}$/D', $prefix) !== 1
            || $input->databaseName() !== $prefix.'_'.$tag
            || ! self::positiveDecimal($input->databaseOid())
            || ! self::positiveDecimal($input->clusterSystemIdentifier())) {
            self::refuse('S00_INPUT', 'INVALID_INPUT');
        }

        foreach ([$input->requesterPassword(), $input->reviewerPassword()] as $password) {
            if ($password === '' || trim($password) !== $password) {
                self::refuse('S00_INPUT', 'INVALID_INPUT');
            }
        }

        $requesterSecret = $input->requesterTotpSecret();
        $reviewerSecret = $input->reviewerTotpSecret();
        foreach ([$requesterSecret, $reviewerSecret] as $secret) {
            if ($secret === '' || trim($secret) !== $secret) {
                self::refuse('S00_INPUT', 'INVALID_INPUT');
            }

            try {
                TOTP::createFromSecret($secret);
            } catch (\InvalidArgumentException) {
                self::refuse('S00_INPUT', 'INVALID_INPUT');
            }
        }

        if (hash_equals($requesterSecret, $reviewerSecret)) {
            self::refuse('S00_INPUT', 'INVALID_INPUT');
        }
    }

    private static function positiveDecimal(string $value): bool
    {
        return ctype_digit($value) && ltrim($value, '0') !== '';
    }

    private static function connectionFacts(ConnectionInterface $connection): ?object
    {
        return $connection->selectOne(<<<'SQL'
            SELECT current_database() AS database_name,
                   (SELECT oid::text FROM pg_database WHERE datname = current_database()) AS database_oid,
                   current_schema() AS schema_name,
                   current_user AS role_name,
                   session_user AS session_role_name,
                   r.rolcanlogin AS can_login,
                   r.rolsuper AS is_superuser,
                   r.rolbypassrls AS bypasses_rls,
                   r.rolcreatedb AS can_create_database,
                   r.rolcreaterole AS can_create_role,
                   has_schema_privilege(current_user, 'public', 'CREATE') AS can_create_public_schema
            FROM pg_roles AS r
            WHERE r.rolname = current_user
        SQL);
    }

    private static function assertConnectionFacts(
        Eng06ProviderActorFixtureInput $input,
        ?object $provider,
        ?object $control,
    ): void {
        if ($provider === null || $control === null
            || $provider->database_name !== $input->databaseName()
            || $control->database_name !== $input->databaseName()
            || $provider->database_oid !== $input->databaseOid()
            || $control->database_oid !== $input->databaseOid()
            || $provider->schema_name !== 'public' || $control->schema_name !== 'public'
            || $provider->role_name === $control->role_name
            || ! self::restrictedLoginRole($provider) || ! self::restrictedLoginRole($control)) {
            self::refuse('S10_CONNECTION_ALIASES', 'ROLE_POLICY');
        }
    }

    private static function restrictedLoginRole(object $facts): bool
    {
        return $facts->role_name === $facts->session_role_name
            && self::databaseBoolean($facts->can_login) === true
            && self::databaseBoolean($facts->is_superuser) === false
            && self::databaseBoolean($facts->bypasses_rls) === false
            && self::databaseBoolean($facts->can_create_database) === false
            && self::databaseBoolean($facts->can_create_role) === false
            && self::databaseBoolean($facts->can_create_public_schema) === false;
    }

    private static function assertProviderTablePrivileges(ConnectionInterface $connection): void
    {
        $rows = $connection->select(<<<'SQL'
            WITH required_relations AS (
                SELECT 'provider_users'::text AS relation_name
                UNION ALL SELECT 'provider_mfa_totp'
                UNION ALL SELECT 'provider_capabilities'
                UNION ALL SELECT 'provider_user_capabilities'
            )
            SELECT required.relation_name,
                   tbl.oid IS NOT NULL AS relation_exists,
                   tbl.relkind = 'r' AS is_table,
                   to_regclass(required.relation_name)::oid = tbl.oid AS resolves_to_public,
                   tbl.relrowsecurity AS rls_enabled,
                   pg_has_role(current_user, tbl.relowner, 'USAGE') AS owner_role_member,
                   has_table_privilege(current_user, tbl.oid, 'SELECT') AS can_select,
                   has_table_privilege(current_user, tbl.oid, 'INSERT') AS can_insert,
                   has_table_privilege(current_user, tbl.oid, 'UPDATE') AS can_update,
                   has_table_privilege(current_user, tbl.oid, 'DELETE') AS can_delete,
                   has_table_privilege(current_user, tbl.oid, 'TRUNCATE') AS can_truncate,
                   has_table_privilege(current_user, tbl.oid, 'REFERENCES') AS can_reference,
                   has_table_privilege(current_user, tbl.oid, 'TRIGGER') AS can_trigger
            FROM required_relations AS required
            LEFT JOIN pg_class AS tbl ON tbl.relname = required.relation_name
            LEFT JOIN pg_namespace AS ns ON ns.oid = tbl.relnamespace
                AND ns.nspname = 'public'
            WHERE tbl.oid IS NULL OR tbl.relnamespace = ns.oid
            ORDER BY required.relation_name
        SQL);

        if (count($rows) !== 4) {
            self::refuse('S20_PROVIDER_PRIVILEGES', 'PRIVILEGE_UNAVAILABLE');
        }

        $required = [
            'provider_users' => ['insert' => true, 'update' => true],
            'provider_mfa_totp' => ['insert' => true, 'update' => true],
            'provider_capabilities' => ['insert' => false, 'update' => false],
            'provider_user_capabilities' => ['insert' => true, 'update' => false],
        ];

        foreach ($rows as $row) {
            $needed = $required[$row->relation_name] ?? null;
            if ($needed === null
                || self::databaseBoolean($row->relation_exists) !== true
                || self::databaseBoolean($row->is_table) !== true
                || self::databaseBoolean($row->resolves_to_public) !== true
                || self::databaseBoolean($row->rls_enabled) !== false
                || self::databaseBoolean($row->owner_role_member) !== false
                || self::databaseBoolean($row->can_select) !== true
                || self::databaseBoolean($row->can_insert) !== $needed['insert']
                || self::databaseBoolean($row->can_update) !== $needed['update']
                || self::databaseBoolean($row->can_delete) !== false
                || self::databaseBoolean($row->can_truncate) !== false
                || self::databaseBoolean($row->can_reference) !== false
                || self::databaseBoolean($row->can_trigger) !== false) {
                self::refuse('S20_PROVIDER_PRIVILEGES', 'PRIVILEGE_UNAVAILABLE');
            }
        }
    }

    private static function assertVirginProviderState(ConnectionInterface $connection): void
    {
        $counts = [
            $connection->table('provider_users')->count(),
            $connection->table('provider_mfa_totp')->count(),
            $connection->table('provider_user_capabilities')->count(),
        ];

        if ($counts !== [0, 0, 0]) {
            self::refuse('S30_VIRGIN_STATE_AND_CATALOG', 'NON_VIRGIN_STATE');
        }
    }

    private static function assertRequiredCapabilities(ConnectionInterface $connection): void
    {
        $active = $connection->table('provider_capabilities')
            ->whereIn('key', [self::REQUESTER_CAPABILITY, self::REVIEWER_CAPABILITY])
            ->where('status', 'ACTIVE')
            ->orderBy('key')
            ->pluck('key')
            ->map(static fn (mixed $key): string => (string) $key)
            ->all();

        $expected = [self::REQUESTER_CAPABILITY, self::REVIEWER_CAPABILITY];
        sort($expected);
        if ($active !== $expected) {
            self::refuse('S30_VIRGIN_STATE_AND_CATALOG', 'CAPABILITY_UNAVAILABLE');
        }
    }

    private static function createActor(string $email, string $password, Carbon $now, string $stage): ProviderUser
    {
        $user = new ProviderUser();
        $user->setConnection(self::PROVIDER_CONNECTION);
        $user->forceFill([
            'email' => $email,
            'password' => $password,
            'status' => 'ACTIVE',
            'email_verified_at' => $now,
            'mfa_enrolled_at' => $now,
        ]);

        if (! $user->save()) {
            self::refuse($stage, 'UNKNOWN');
        }

        return $user;
    }

    private static function persistTotp(
        ConnectionInterface $connection,
        string $providerUserId,
        string $secret,
        Carbon $now,
        string $stage,
    ): void {
        $inserted = $connection->table('provider_mfa_totp')->insert([
            'provider_user_id' => $providerUserId,
            'secret_ciphertext' => Crypt::encryptString($secret),
            'confirmed_at' => $now,
            'created_at' => $now,
            'updated_at' => $now,
        ]);

        if (! $inserted) {
            self::refuse($stage, 'UNKNOWN');
        }
    }

    private static function grantCapability(
        ConnectionInterface $connection,
        string $providerUserId,
        string $capability,
        Carbon $now,
        string $stage,
    ): void {
        $inserted = $connection->table('provider_user_capabilities')->insert([
            'provider_user_id' => $providerUserId,
            'capability_key' => $capability,
            'granted_at' => $now,
            'expires_at' => null,
        ]);

        if (! $inserted
            || $connection->table('provider_users')->where('id', $providerUserId)
                ->increment('authorization_version') !== 1) {
            self::refuse($stage, 'UNKNOWN');
        }
    }

    private static function verifyCreatedActors(
        ConnectionInterface $connection,
        string $requesterId,
        string $reviewerId,
    ): void {
        $ids = [$requesterId, $reviewerId];
        $users = $connection->table('provider_users')->whereIn('id', $ids)
            ->get(['id', 'status', 'email_verified_at', 'mfa_enrolled_at', 'auth_version', 'authorization_version']);

        if ($users->count() !== 2 || $users->contains(static fn (object $user): bool =>
            $user->status !== 'ACTIVE' || $user->email_verified_at === null || $user->mfa_enrolled_at === null
            || (int) $user->auth_version !== 1 || (int) $user->authorization_version !== 2)) {
            self::refuse('S70_VERIFY', 'UNKNOWN');
        }

        $totpCount = $connection->table('provider_mfa_totp')->whereIn('provider_user_id', $ids)
            ->whereNotNull('secret_ciphertext')->whereNotNull('confirmed_at')->count();
        $requesterGrant = $connection->table('provider_user_capabilities')
            ->where('provider_user_id', $requesterId)->where('capability_key', self::REQUESTER_CAPABILITY)
            ->whereNull('expires_at')->exists();
        $reviewerGrant = $connection->table('provider_user_capabilities')
            ->where('provider_user_id', $reviewerId)->where('capability_key', self::REVIEWER_CAPABILITY)
            ->whereNull('expires_at')->exists();
        $grantCount = $connection->table('provider_user_capabilities')->whereIn('provider_user_id', $ids)
            ->whereNull('expires_at')->count();

        if ($totpCount !== 2 || ! $requesterGrant || ! $reviewerGrant || $grantCount !== 2) {
            self::refuse('S70_VERIFY', 'UNKNOWN');
        }
    }

    private static function databaseBoolean(mixed $value): ?bool
    {
        if (is_bool($value)) {
            return $value;
        }

        if ($value === 1 || $value === '1' || $value === 't' || $value === 'true') {
            return true;
        }

        if ($value === 0 || $value === '0' || $value === 'f' || $value === 'false') {
            return false;
        }

        return null;
    }

    private static function sqlState(Throwable $failure): ?string
    {
        $candidate = $failure instanceof PDOException ? (string) $failure->getCode() : '';

        return preg_match('/^[0-9A-Z]{5}$/D', $candidate) === 1 ? $candidate : null;
    }

    private static function refuse(string $stage, string $category): never
    {
        throw new Eng06ProviderActorFixtureFailure($stage, $category, null);
    }
}

/** Safe structured failure; raw database/crypto exceptions are never retained as a previous cause. */
final class Eng06ProviderActorFixtureFailure extends RuntimeException
{
    private const STAGES = [
        'S00_INPUT', 'S10_CONNECTION_ALIASES', 'S20_PROVIDER_PRIVILEGES', 'S30_VIRGIN_STATE_AND_CATALOG',
        'S40_REQUESTER', 'S41_REVIEWER', 'S50_MFA_REQUESTER', 'S51_MFA_REVIEWER',
        'S60_GRANT_REQUESTER', 'S61_GRANT_REVIEWER', 'S70_VERIFY', 'S80_COMMIT',
    ];

    private const CATEGORIES = [
        'INVALID_INPUT', 'TARGET_GUARD', 'ROLE_POLICY', 'PRIVILEGE_UNAVAILABLE', 'NON_VIRGIN_STATE',
        'CAPABILITY_UNAVAILABLE', 'DATABASE_EXCEPTION', 'UNKNOWN',
    ];

    public readonly string $stageId;

    public readonly string $category;

    public readonly ?string $sqlState;

    public function __construct(string $stageId, string $category, ?string $sqlState)
    {
        $this->stageId = in_array($stageId, self::STAGES, true) ? $stageId : 'S00_INPUT';
        $this->category = in_array($category, self::CATEGORIES, true) ? $category : 'UNKNOWN';
        $this->sqlState = $sqlState !== null && preg_match('/^[0-9A-Z]{5}$/D', $sqlState) === 1
            ? $sqlState : null;

        parent::__construct('ENG-06 Provider test fixture initialization failed.');
    }

    /** @return array{stage_id:string,category:string,sqlstate:?string} */
    public function __debugInfo(): array
    {
        return ['stage_id' => $this->stageId, 'category' => $this->category, 'sqlstate' => $this->sqlState];
    }

    /** @return array{stage_id:string,category:string,sqlstate:?string} */
    public function __serialize(): array
    {
        return ['stage_id' => $this->stageId, 'category' => $this->category, 'sqlstate' => $this->sqlState];
    }
}
