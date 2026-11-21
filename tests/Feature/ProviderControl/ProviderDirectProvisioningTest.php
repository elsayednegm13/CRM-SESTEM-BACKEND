<?php

namespace Tests\Feature\ProviderControl;

use App\Modules\Identity\Domain\EffectivePermissions;
use App\Modules\Provider\Application\ProviderControlOperationService;
use App\Modules\Provider\Domain\ProviderContext;
use App\Modules\Provider\Domain\ProviderAccessException;
use App\Modules\Provider\Infrastructure\Persistence\ProviderControlDatabaseContext;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
use RuntimeException;
use Tests\TestCase;

final class ProviderDirectProvisioningTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->assertPinnedDisposableTarget();
    }

    public function test_approved_provider_operation_creates_one_direct_tenant_admin_under_rls(): void
    {
        [$requester, $reviewer, $requesterContext, $reviewerContext] = $this->providerActors();
        $email = 'first-admin-'.Str::lower(Str::random(12)).'@example.invalid';
        $displayName = 'Synthetic Administrator';
        $input = [
            'display_name' => 'Synthetic Company '.Str::upper(Str::random(6)),
            'slug' => 'c'.Str::lower(Str::random(20)),
            'timezone' => 'Africa/Cairo',
            'first_admin_email' => $email,
            'first_admin_display_name' => $displayName,
            'reason' => 'FND-ID-03 isolated acceptance fixture',
            'ticket_reference' => 'FNDID03-'.Str::upper(Str::random(12)),
        ];
        $idempotencyKey = 'FNDID03-'.Str::random(32);
        $service = app(ProviderControlOperationService::class);
        $operation = $service->createProvision($requesterContext, $input, $idempotencyKey);

        self::assertSame('PENDING_APPROVAL', $operation['status']);
        self::assertSame($operation['id'], $service->createProvision($requesterContext, $input, $idempotencyKey)['id']);
        self::assertSame('APPROVED', $service->review($reviewerContext, $operation['approval_request_id'],
            'APPROVE', 'Independent synthetic review', 'FNDID03-REVIEW-'.Str::upper(Str::random(8)), 1));

        $password = 'T3st-'.Str::random(36).'!Aa';
        $result = $service->executeProvision($requesterContext, $operation['id'], $password);
        self::assertSame('SUCCEEDED', $result['status']);
        self::assertArrayNotHasKey('initial_password', $result);
        self::assertArrayNotHasKey('password_hash', $result);
        self::assertSame($input['slug'], $result['slug']);
        self::assertSame($input['slug'].'.'.config('tenancy.base_domain'), $result['hostname']);

        $facts = app(ProviderControlDatabaseContext::class)->run(
            $requester->id,
            $requesterContext->authVersion,
            (int) $requesterContext->stepUpVerifiedAt,
            'company.provision',
            'PROVIDER_CONTROL',
            function ($db) use ($operation, $input, $requester, $password): array {
                $op = $db->table('provider_control_operations')->where('id', $operation['id'])->first();
                $tenant = $db->table('tenants')->where('id', $op->target_tenant_id)
                    ->first(['id', 'slug', 'status']);
                $staff = $db->table('tenant_staff_users')->where('tenant_id', $op->target_tenant_id)
                    ->where('canonical_email', $input['first_admin_email'])->first([
                        'id', 'tenant_id', 'canonical_email', 'display_name', 'status', 'auth_version',
                    ]);
                $membership = $staff ? $db->table('tenant_staff_memberships')->where('tenant_id', $op->target_tenant_id)
                    ->where('staff_user_id', $staff->id)->first([
                        'id', 'tenant_id', 'staff_user_id', 'status', 'created_by_provider_operation_id',
                    ]) : null;
                $assignment = $membership ? $db->table('tenant_staff_membership_roles')->where('tenant_id', $op->target_tenant_id)
                    ->where('membership_id', $membership->id)->whereNull('revoked_at')->first([
                        'id', 'tenant_id', 'membership_id', 'role_id', 'assigned_by_provider_operation_id', 'revoked_at',
                    ]) : null;
                $hostname = $db->table('tenant_hostnames')->where('tenant_id', $op->target_tenant_id)->value('hostname');
                $adminGrant = $assignment ? $db->table('role_permissions')->where('tenant_id', $op->target_tenant_id)
                    ->where('role_id', $assignment->role_id)->where('permission_key', 'company.administer')
                    ->where('scope', 'ALL_TENANT')->value('permission_key') === 'company.administer' : false;
                $effective = $assignment ? $this->resolveEffectiveRole($db, $op->target_tenant_id,
                    $assignment->role_id) : null;

                return [
                    'tenant_status' => $tenant?->status,
                    'tenant_id' => $op->target_tenant_id,
                    'operation_status' => $op->status,
                    'operation_first_admin_name' => $op->first_admin_display_name,
                    'staff' => $staff,
                    'membership' => $membership,
                    'assignment' => $assignment,
                    'hostname' => $hostname,
                    'admin_grant' => $adminGrant,
                    'effective_permissions' => $effective,
                    'password_echoed' => str_contains(json_encode($op, JSON_THROW_ON_ERROR), $password),
                ];
            },
            $operation['id'],
            $operation['approval_request_id'],
            $result['tenant_id'],
            'company.provision',
        );

        self::assertSame('ACTIVE', $facts['tenant_status']);
        self::assertSame('SUCCEEDED', $facts['operation_status']);
        self::assertSame($displayName, $facts['operation_first_admin_name']);
        self::assertSame($input['first_admin_email'], $facts['staff']->canonical_email);
        self::assertSame('ACTIVE', $facts['staff']->status);
        self::assertSame(1, $facts['staff']->auth_version);
        self::assertSame('ACTIVE', $facts['membership']->status);
        self::assertSame($operation['id'], $facts['membership']->created_by_provider_operation_id);
        self::assertSame($operation['id'], $facts['assignment']->assigned_by_provider_operation_id);
        self::assertTrue($facts['admin_grant']);
        self::assertArrayHasKey('company.administer', $facts['effective_permissions']);
        self::assertSame(['ALL_TENANT'], $facts['effective_permissions']['company.administer']);
        self::assertSame($result['hostname'], $facts['hostname']);
        self::assertFalse($facts['password_echoed']);

        self::assertSame($result, $service->executeProvision($requesterContext, $operation['id'], $password));

        $secondInput = $input;
        $secondInput['display_name'] .= ' Independent';
        $secondInput['slug'] = 'd'.Str::lower(Str::random(20));
        $secondInput['first_admin_email'] = Str::upper($email);
        $secondInput['ticket_reference'] = 'FNDID03-'.Str::upper(Str::random(12));
        $secondOperation = $service->createProvision($requesterContext, $secondInput,
            'FNDID03-'.Str::random(32));
        self::assertSame('APPROVED', $service->review($reviewerContext,
            $secondOperation['approval_request_id'], 'APPROVE', 'Independent synthetic review',
            'FNDID03-REVIEW-'.Str::upper(Str::random(8)), 1));
        $secondPassword = 'T3st-'.Str::random(36).'!Aa';
        $secondResult = $service->executeProvision($requesterContext, $secondOperation['id'], $secondPassword);
        self::assertNotSame($result['tenant_id'], $secondResult['tenant_id']);
        $secondStaff = app(ProviderControlDatabaseContext::class)->run(
            $requester->id,
            $requesterContext->authVersion,
            (int) $requesterContext->stepUpVerifiedAt,
            'company.provision',
            'PROVIDER_CONTROL',
            fn ($db) => $db->table('tenant_staff_users')->where('tenant_id', $secondResult['tenant_id'])
                ->where('canonical_email', $email)->first(['id', 'tenant_id']),
            $secondOperation['id'],
            $secondOperation['approval_request_id'],
            $secondResult['tenant_id'],
            'company.provision',
        );
        self::assertNotNull($secondStaff);
        self::assertNotSame($facts['staff']->id, $secondStaff->id);
        self::assertSame($secondResult['tenant_id'], $secondStaff->tenant_id);

        $this->assertSame('', (string) (DB::connection('pgsql_provider_control')
            ->selectOne("SELECT COALESCE(current_setting('app.context_mode', true), '') AS mode")->mode));
        $this->assertProviderControlConnectionIsRestricted();
    }

    public function test_invalid_initial_password_rolls_back_the_entire_approved_bootstrap(): void
    {
        [$requester, , $requesterContext, $reviewerContext] = $this->providerActors();
        $input = [
            'display_name' => 'Rollback Company '.Str::upper(Str::random(6)),
            'slug' => 'r'.Str::lower(Str::random(20)),
            'timezone' => 'Africa/Cairo',
            'first_admin_email' => 'rollback-'.Str::lower(Str::random(12)).'@example.invalid',
            'first_admin_display_name' => 'Rollback Administrator',
            'reason' => 'FND-ID-03 rollback probe',
            'ticket_reference' => 'FNDID03-ROLLBACK-'.Str::upper(Str::random(6)),
        ];
        $service = app(ProviderControlOperationService::class);
        $operation = $service->createProvision($requesterContext, $input, 'FNDID03-'.Str::random(32));
        self::assertSame('APPROVED', $service->review($reviewerContext, $operation['approval_request_id'],
            'APPROVE', 'Independent synthetic review', 'FNDID03-REVIEW-'.Str::upper(Str::random(8)), 1));

        try {
            $service->executeProvision($requesterContext, $operation['id'], 'too-short');
            self::fail('The invalid password was accepted.');
        } catch (ValidationException $exception) {
            self::assertArrayHasKey('initial_password', $exception->errors());
        }

        $state = app(ProviderControlDatabaseContext::class)->run(
            $requester->id,
            $requesterContext->authVersion,
            (int) $requesterContext->stepUpVerifiedAt,
            'company.provision',
            'PROVIDER_CONTROL',
            function ($db) use ($operation): array {
                $op = $db->table('provider_control_operations')->where('id', $operation['id'])->first();
                return [
                    'operation_status' => $op->status,
                    'tenant_count' => $db->table('tenants')->where('id', $op->target_tenant_id)->count(),
                    'hostname_count' => $db->table('tenant_hostnames')->where('tenant_id', $op->target_tenant_id)->count(),
                    'staff_count' => $db->table('tenant_staff_users')->where('tenant_id', $op->target_tenant_id)->count(),
                ];
            },
            $operation['id'],
            $operation['approval_request_id'],
            null,
            'company.provision',
        );

        self::assertSame('READY', $state['operation_status']);
        self::assertSame(0, $state['tenant_count']);
        self::assertSame(0, $state['hostname_count']);
        self::assertSame(0, $state['staff_count']);
        self::assertSame('', (string) (DB::connection('pgsql_provider_control')
            ->selectOne("SELECT COALESCE(current_setting('app.context_mode', true), '') AS mode")->mode));
    }

    public function test_forged_provider_context_cannot_insert_an_active_tenant_or_read_staff_rows(): void
    {
        $runtime = DB::connection('pgsql_provider_control');
        $candidate = (string) Str::uuid7();
        self::assertTrue((bool) $runtime->selectOne(
            "SELECT has_column_privilege(current_user, 'public.tenants', 'id', 'INSERT') AS allowed",
        )->allowed);
        self::assertSame(0, (int) $runtime->table('tenants')->where('id', $candidate)->count('id'));
        self::assertSame(0, (int) $runtime->table('tenant_staff_users')->where('tenant_id', $candidate)->count('id'));

        try {
            $runtime->transaction(function () use ($runtime, $candidate): void {
                foreach ([
                    'app.context_mode' => 'PROVIDER_CONTROL',
                    'app.provider_user_id' => (string) Str::uuid7(),
                    'app.provider_auth_version' => '1',
                    'app.provider_step_up_at' => now('UTC')->toIso8601String(),
                    'app.provider_capability' => 'company.provision',
                    'app.provider_operation_id' => (string) Str::uuid7(),
                    'app.provider_approval_id' => (string) Str::uuid7(),
                    'app.provider_target_tenant_id' => $candidate,
                    'app.provider_action' => 'company.provision',
                ] as $key => $value) {
                    $runtime->selectOne('SELECT set_config(?, ?, true)', [$key, $value]);
                }
                $runtime->table('tenants')->insert([
                    'id' => $candidate, 'display_name' => 'Forged Active Tenant', 'legal_name' => null,
                    'slug' => 'forged-'.Str::lower(Str::random(16)), 'status' => 'ACTIVE',
                    'timezone' => 'UTC', 'default_locale' => 'en', 'archived_at' => null,
                    'created_at' => now('UTC'), 'updated_at' => now('UTC'),
                ]);
            });
            self::fail('Forged custom PostgreSQL settings authorized an ACTIVE tenant insert.');
        } catch (QueryException $exception) {
            $previous = $exception->getPrevious();
            $sqlState = is_object($previous) && isset($previous->errorInfo[0])
                ? (string) $previous->errorInfo[0] : (string) $exception->getCode();
            self::assertSame('42501', $sqlState);
        }

        self::assertSame('', (string) ($runtime->selectOne(
            "SELECT COALESCE(current_setting('app.context_mode', true), '') AS mode",
        )->mode));
        self::assertSame(0, (int) $runtime->table('tenants')->where('id', $candidate)->count('id'));
        self::assertSame(0, (int) $runtime->table('tenant_staff_users')->where('tenant_id', $candidate)->count('id'));
        $this->assertProviderControlConnectionIsRestricted();
    }

    /** @return array{0: object, 1: object, 2: ProviderContext, 3: ProviderContext} */
    public function test_pending_revision_edit_noop_stale_review_and_owner_withdrawal(): void
    {
        [$requester, , $requesterContext, $reviewerContext] = $this->providerActors();
        $service = app(ProviderControlOperationService::class);
        $input = [
            'display_name' => 'Revision Company '.Str::upper(Str::random(6)),
            'slug' => 'v'.Str::lower(Str::random(20)),
            'timezone' => 'Africa/Cairo',
            'first_admin_email' => 'revision-'.Str::lower(Str::random(12)).'@example.invalid',
            'first_admin_display_name' => 'Revision Administrator',
            'reason' => 'FND-ID-03 revision probe',
            'ticket_reference' => 'ENG05D-'.Str::upper(Str::random(12)),
        ];
        $op = $service->createProvision($requesterContext, $input, 'ENG05D-'.Str::random(32));
        self::assertSame(1, $op['revision']);
        $input['display_name'] .= ' Edited';
        $edit = $service->editProvision($requesterContext, $op['id'], $input + ['expected_revision' => 1]);
        self::assertSame(2, $edit['revision']);
        self::assertSame($input['display_name'], $edit['display_name']);
        self::assertSame($edit, $service->editProvision($requesterContext, $op['id'],
            $input + ['expected_revision' => 2]));
        try {
            $service->review($reviewerContext, $op['approval_request_id'], 'APPROVE',
                'Stale review', 'ENG05D-STALE-001', 1);
            self::fail('Stale reviewer revision was accepted.');
        } catch (ProviderAccessException $exception) {
            self::assertSame(409, $exception->status);
        }
        $state = app(ProviderControlDatabaseContext::class)->run(
            $requester->id, $requesterContext->authVersion, (int) $requesterContext->stepUpVerifiedAt,
            'company.provision', 'PROVIDER_CONTROL', function ($db) use ($op): array {
                $operation = $db->table('provider_control_operations')->where('id', $op['id'])->first();
                $approval = $db->table('provider_approval_requests')->where('id', $op['approval_request_id'])->first();
                return ['operation' => $operation, 'approval' => $approval,
                    'revisions' => $db->table('provider_provision_revisions')->where('operation_id', $op['id'])->count()];
            }, $op['id'], $op['approval_request_id'], null, 'company.provision');
        self::assertSame(2, $state['revisions']);
        self::assertSame(2, (int) $state['operation']->current_revision);
        self::assertSame(2, (int) $state['approval']->review_revision);
        self::assertSame($state['operation']->intent_digest, $state['approval']->intent_digest);
        self::assertSame('REVOKED', $service->review($requesterContext, $op['approval_request_id'],
            'REVOKE', 'Requester withdrawal', 'ENG05D-WITHDRAW-001'));
        try {
            $service->executeProvision($requesterContext, $op['id'], 'T3st-'.Str::random(36).'!Aa');
            self::fail('Withdrawn provision was executed.');
        } catch (ProviderAccessException $exception) {
            self::assertSame(403, $exception->status);
        }
    }

    private function providerActors(): array
    {
        $requesterId = getenv('FND_ID03_CONTROL01_REQUESTER_ID');
        $reviewerId = getenv('FND_ID03_CONTROL01_REVIEWER_ID');
        if (! is_string($requesterId) || ! Str::isUuid($requesterId)
            || ! is_string($reviewerId) || ! Str::isUuid($reviewerId)
            || $requesterId === $reviewerId) {
            throw new RuntimeException('Two distinct synthetic Provider fixture identities are required.');
        }
        $providerDb = DB::connection('pgsql_provider');
        $requester = $providerDb->table('provider_users')->where('id', $requesterId)->first([
            'id', 'status', 'email_verified_at', 'mfa_enrolled_at', 'auth_version', 'authorization_version',
        ]);
        $reviewer = $providerDb->table('provider_users')->where('id', $reviewerId)->first([
            'id', 'status', 'email_verified_at', 'mfa_enrolled_at', 'auth_version', 'authorization_version',
        ]);
        if (! $requester || ! $reviewer || $requester->status !== 'ACTIVE' || $reviewer->status !== 'ACTIVE'
            || $requester->email_verified_at === null || $reviewer->email_verified_at === null
            || $requester->mfa_enrolled_at === null || $reviewer->mfa_enrolled_at === null) {
            throw new RuntimeException('The synthetic Provider fixtures must be active, verified, and MFA enrolled.');
        }
        $now = now('UTC')->timestamp;
        $requesterContext = new ProviderContext($requesterId, (int) $requester->auth_version,
            (int) $requester->authorization_version, (string) Str::uuid7(), $now, $now);
        $reviewerContext = new ProviderContext($reviewerId, (int) $reviewer->auth_version,
            (int) $reviewer->authorization_version, (string) Str::uuid7(), $now, $now);
        app(\App\Modules\Provider\Application\ProviderAuthorizationService::class)
            ->assertCapability($requesterContext, 'company.provision');
        app(\App\Modules\Provider\Application\ProviderAuthorizationService::class)
            ->assertCapability($reviewerContext, 'provider.approval.review');

        return [
            (object) ['id' => $requesterId],
            (object) ['id' => $reviewerId],
            $requesterContext,
            $reviewerContext,
        ];
    }

    private function resolveEffectiveRole($db, string $tenantId, string $roleId): ?array
    {
        $grants = $db->table('role_permissions')->where('tenant_id', $tenantId)->where('role_id', $roleId)
            ->get(['permission_key', 'scope'])->map(static fn ($grant): array => [
                'permission_key' => $grant->permission_key,
                'scope' => $grant->scope,
            ])->all();
        $keys = array_values(array_unique(array_column($grants, 'permission_key')));
        $catalog = $db->table('permissions')->whereIn('key', $keys)
            ->get(['key', 'status', 'scopeable', 'allowed_scopes', 'delegable'])
            ->mapWithKeys(static fn ($permission): array => [$permission->key => [
                'status' => $permission->status,
                'scopeable' => (bool) $permission->scopeable,
                'allowed_scopes' => is_array($permission->allowed_scopes)
                    ? $permission->allowed_scopes
                    : json_decode((string) $permission->allowed_scopes, true, flags: JSON_THROW_ON_ERROR),
                'delegable' => (bool) $permission->delegable,
            ]])->all();

        return app(EffectivePermissions::class)->resolve($grants, [], $catalog);
    }

    private function assertPinnedDisposableTarget(): void
    {
        if (app()->environment() !== 'testing'
            || getenv('FND_ID03_CONTROL01_SYSTEM_ID') === false
            || getenv('FND_ID03_CONTROL01_DB_OID') === false
            || getenv('FND_ID03_CONTROL01_DB_NAME') === false
            || getenv('FND_ID03_CONTROL01_REQUESTER_ID') === false
            || getenv('FND_ID03_CONTROL01_REVIEWER_ID') === false
            || getenv('FND_ID03_CONTROL01_TEST_RUN') !== 'DALEEL_CRM_FND_ID_03_CONTROL_01_PROVIDER_DIRECT_COMPANY_FIRST_ADMIN_PROVISIONING') {
            throw new RuntimeException('Refusing Provider provisioning tests outside the pinned FND-ID-03 isolated target.');
        }
        $baseDomain = (string) config('tenancy.base_domain');
        if (! str_ends_with($baseDomain, '.localhost')
            || config('tenancy.allow_localhost_base_domain') !== true
            || config('tenancy.local_test_base_domain') !== $baseDomain) {
            throw new RuntimeException('The acceptance target must use the exact LOCAL_TEST .localhost domain.');
        }
        $target = DB::connection('pgsql')->selectOne(<<<'SQL'
            SELECT current_database() AS database_name,
                   (SELECT oid::text FROM pg_database WHERE datname = current_database()) AS database_oid,
                   inet_server_port() AS server_port,
                   current_user AS current_user,
                   session_user AS session_user,
                   r.rolsuper AS is_superuser,
                   r.rolbypassrls AS bypasses_rls,
                   r.rolcreaterole AS can_create_roles,
                   r.rolcreatedb AS can_create_databases,
                   has_schema_privilege(current_user, 'public', 'CREATE') AS can_create_schema,
                   EXISTS (
                       SELECT 1 FROM pg_class relation
                       WHERE relation.oid = ANY(ARRAY[
                           'public.tenants'::regclass, 'public.tenant_staff_users'::regclass,
                           'public.tenant_staff_memberships'::regclass, 'public.roles'::regclass,
                           'public.role_permissions'::regclass
                       ])
                         AND (relation.relowner = current_user::regrole
                              OR pg_has_role(current_user, relation.relowner, 'USAGE'))
                   ) AS owns_protected_relations
            FROM pg_roles r WHERE r.rolname = current_user
        SQL);
        if ($target->database_name !== getenv('FND_ID03_CONTROL01_DB_NAME')
            || $target->database_oid !== getenv('FND_ID03_CONTROL01_DB_OID')
            || (int) $target->server_port !== 5432
            || $target->current_user !== $target->session_user
            || $target->is_superuser || $target->bypasses_rls || $target->can_create_roles
            || $target->can_create_databases || $target->can_create_schema || $target->owns_protected_relations) {
            throw new RuntimeException('The active database identity does not match the pinned non-bypass disposable target.');
        }
        $this->assertRestrictedConnectionIsPinned('pgsql_provider');
        $this->assertRestrictedConnectionIsPinned('pgsql_hostname_resolver');
        $this->assertRestrictedConnectionIsPinned('pgsql_tenant_auth');
        $this->assertRestrictedConnectionIsPinned('pgsql_tenant_runtime');
        $this->assertProviderControlConnectionIsRestricted();
    }

    private function assertRestrictedConnectionIsPinned(string $connectionName): void
    {
        $role = DB::connection($connectionName)->selectOne(<<<'SQL'
            SELECT current_database() AS database_name,
                   (SELECT oid::text FROM pg_database WHERE datname = current_database()) AS database_oid,
                   inet_server_port() AS server_port,
                   current_user AS current_user,
                   session_user AS session_user,
                   r.rolsuper AS is_superuser,
                   r.rolbypassrls AS bypasses_rls,
                   r.rolcreaterole AS can_create_roles,
                   r.rolcreatedb AS can_create_databases,
                   has_schema_privilege(current_user, 'public', 'CREATE') AS can_create_schema
            FROM pg_roles r WHERE r.rolname = current_user
        SQL);
        if ($role->database_name !== getenv('FND_ID03_CONTROL01_DB_NAME')
            || $role->database_oid !== getenv('FND_ID03_CONTROL01_DB_OID')
            || (int) $role->server_port !== 5432
            || $role->current_user !== $role->session_user
            || $role->is_superuser || $role->bypasses_rls || $role->can_create_roles
            || $role->can_create_databases || $role->can_create_schema) {
            throw new RuntimeException("The {$connectionName} connection is not pinned to a restricted disposable role.");
        }
    }

    private function assertProviderControlConnectionIsRestricted(): void
    {
        $this->assertRestrictedConnectionIsPinned('pgsql_provider_control');
        $role = DB::connection('pgsql_provider_control')->selectOne(<<<'SQL'
            SELECT pg_has_role(current_user, 'daleel_provider_first_admin_writer', 'MEMBER') AS has_first_admin_role,
                   pg_has_role(current_user, 'daleel_provider_registry_writer', 'MEMBER') AS has_registry_role
        SQL);
        if (! $role->has_first_admin_role || ! $role->has_registry_role) {
            throw new RuntimeException('The Provider control test connection lacks its two scoped operational roles.');
        }
    }
}
