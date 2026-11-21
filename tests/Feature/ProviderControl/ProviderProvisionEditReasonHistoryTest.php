<?php

namespace Tests\Feature\ProviderControl;

use App\Modules\Provider\Application\ProviderAuthorizationService;
use App\Modules\Provider\Application\ProviderControlOperationService;
use App\Modules\Provider\Domain\ProviderAccessException;
use App\Modules\Provider\Domain\ProviderContext;
use App\Modules\Provider\Infrastructure\Persistence\ProviderControlDatabaseContext;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use RuntimeException;
use Tests\TestCase;

final class ProviderProvisionEditReasonHistoryTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->assertPinnedDisposableTarget();
    }

    public function test_material_edit_reason_is_encrypted_and_visible_only_in_authorized_revision_history(): void
    {
        [$requester, $reviewer, $requesterContext, $reviewerContext] = $this->providerActors();
        $service = app(ProviderControlOperationService::class);
        $input = $this->intent();
        $operation = $service->createProvision($requesterContext, $input, 'ENG05E-'.Str::random(32));
        $reason = 'مراجعة شركة '.Str::random(32);
        $input['display_name'] .= ' Updated';
        $input['expected_revision'] = 1;
        $input['edit_reason'] = $reason;

        $edited = $service->editProvision($requesterContext, $operation['id'], $input);
        self::assertSame(2, $edited['revision']);
        self::assertArrayNotHasKey('edit_reason', $edited);

        $ownerHistory = $service->provisionRevisionHistory($requesterContext, $operation['id']);
        self::assertSame($reason, $ownerHistory['revisions'][1]['edit_reason']);
        self::assertSame([1, 2], array_column($ownerHistory['revisions'], 'revision'));
        self::assertSame(['revision', 'created_at', 'actor_provider_user_id', 'changed_fields', 'edit_reason'],
            array_keys($ownerHistory['revisions'][1]));
        self::assertContains('display_name', $ownerHistory['revisions'][1]['changed_fields']);

        $reviewerHistory = $service->provisionRevisionHistory($reviewerContext, $operation['id']);
        self::assertSame($reason, $reviewerHistory['revisions'][1]['edit_reason']);
        self::assertSame($ownerHistory['revisions'], $reviewerHistory['revisions']);

        $ciphertext = app(ProviderControlDatabaseContext::class)->run(
            $requester->id, $requesterContext->authVersion, (int) $requesterContext->stepUpVerifiedAt,
            'company.provision', 'PROVIDER_CONTROL',
            fn ($db) => $db->table('provider_provision_revisions')->where('operation_id', $operation['id'])
                ->where('revision', 2)->value('edit_reason_ciphertext'),
            $operation['id'], null, null, 'company.provision',
        );
        self::assertIsString($ciphertext);
        self::assertStringStartsWith('eyJpdiI6I', $ciphertext);
        self::assertStringNotContainsString($reason, $ciphertext);

        $noopReason = 'no-op annotation '.Str::random(24);
        $input['expected_revision'] = 2;
        $input['edit_reason'] = $noopReason;
        $noop = $service->editProvision($requesterContext, $operation['id'], $input);
        self::assertSame(2, $noop['revision']);
        self::assertSame($reason, $service->provisionRevisionHistory($requesterContext,
            $operation['id'])['revisions'][1]['edit_reason']);
        $revisionCount = app(ProviderControlDatabaseContext::class)->run(
            $requester->id, $requesterContext->authVersion, (int) $requesterContext->stepUpVerifiedAt,
            'company.provision', 'PROVIDER_CONTROL',
            fn ($db) => $db->table('provider_provision_revisions')->where('operation_id', $operation['id'])->count(),
            $operation['id'], null, null, 'company.provision',
        );
        self::assertSame(2, $revisionCount);

        $input['expected_revision'] = 2;
        $input['display_name'] .= ' Without note';
        unset($input['edit_reason']);
        self::assertSame(3, $service->editProvision($requesterContext, $operation['id'], $input)['revision']);
        $history = $service->provisionRevisionHistory($reviewerContext, $operation['id']);
        self::assertNull($history['revisions'][2]['edit_reason']);
        self::assertSame($reason, $history['revisions'][1]['edit_reason']);
        self::assertSame($requester->id, $history['revisions'][1]['actor_provider_user_id']);
        self::assertNotSame($requester->id, $reviewer->id);
    }

    public function test_encryption_failure_rolls_back_business_revision_and_history_insert(): void
    {
        [, , $requesterContext] = $this->providerActors();
        $service = app(ProviderControlOperationService::class);
        $input = $this->intent();
        $operation = $service->createProvision($requesterContext, $input, 'ENG05E-'.Str::random(32));
        $input['display_name'] .= ' First edit';
        $input['expected_revision'] = 1;
        $beforeFailure = $service->editProvision($requesterContext, $operation['id'], $input);
        self::assertSame(2, $beforeFailure['revision']);

        $input['display_name'] .= ' Failed second edit';
        $input['expected_revision'] = 2;
        $input['edit_reason'] = 'volatile '.Str::random(24);
        Crypt::shouldReceive('encryptString')->once()->andThrow(new RuntimeException('synthetic crypto failure'));
        try {
            $service->editProvision($requesterContext, $operation['id'], $input);
            self::fail('The edit committed without encryption.');
        } catch (ProviderAccessException $exception) {
            self::assertSame(503, $exception->status);
            self::assertSame('PROVIDER_REVISION_HISTORY_UNAVAILABLE', $exception->safeCode);
        }

        $state = app(ProviderControlDatabaseContext::class)->run(
            $requesterContext->providerUserId, $requesterContext->authVersion,
            (int) $requesterContext->stepUpVerifiedAt, 'company.provision', 'PROVIDER_CONTROL',
            function ($db) use ($operation): array {
                $current = $db->table('provider_control_operations')->where('id', $operation['id'])
                    ->first(['display_name', 'current_revision', 'intent_digest']);
                return ['current' => $current, 'history_count' => $db->table('provider_provision_revisions')
                    ->where('operation_id', $operation['id'])->count()];
            }, $operation['id'], null, null, 'company.provision',
        );
        self::assertSame(2, (int) $state['current']->current_revision);
        self::assertSame($beforeFailure['display_name'], $state['current']->display_name);
        self::assertSame(2, $state['history_count']);
        self::assertSame('', (string) DB::connection('pgsql_provider_control')
            ->selectOne("SELECT COALESCE(current_setting('app.context_mode', true), '') AS mode")->mode);
    }

    private function intent(): array
    {
        $suffix = Str::lower(Str::random(18));
        return ['display_name' => 'ENG05E Company '.$suffix, 'slug' => 'eng05e-'.$suffix,
            'timezone' => 'Africa/Cairo', 'first_admin_email' => 'owner-'.$suffix.'@example.invalid',
            'first_admin_display_name' => 'ENG05E Administrator', 'reason' => 'ENG05E isolated fixture',
            'ticket_reference' => 'ENG05E-'.Str::upper(Str::random(10))];
    }

    private function providerActors(): array
    {
        $requesterId = getenv('ENG05E_REQUESTER_ID');
        $reviewerId = getenv('ENG05E_REVIEWER_ID');
        if (! is_string($requesterId) || ! Str::isUuid($requesterId)
            || ! is_string($reviewerId) || ! Str::isUuid($reviewerId) || $requesterId === $reviewerId) {
            throw new RuntimeException('Two distinct ENG-05E Provider fixture identities are required.');
        }
        $providerDb = DB::connection('pgsql_provider');
        $requester = $providerDb->table('provider_users')->where('id', $requesterId)->first([
            'id', 'status', 'email_verified_at', 'mfa_enrolled_at', 'auth_version', 'authorization_version']);
        $reviewer = $providerDb->table('provider_users')->where('id', $reviewerId)->first([
            'id', 'status', 'email_verified_at', 'mfa_enrolled_at', 'auth_version', 'authorization_version']);
        if (! $requester || ! $reviewer || $requester->status !== 'ACTIVE' || $reviewer->status !== 'ACTIVE'
            || $requester->email_verified_at === null || $reviewer->email_verified_at === null
            || $requester->mfa_enrolled_at === null || $reviewer->mfa_enrolled_at === null) {
            throw new RuntimeException('ENG-05E synthetic Provider actors must be active, verified and MFA enrolled.');
        }
        $now = now('UTC')->timestamp;
        $requesterContext = new ProviderContext($requesterId, (int) $requester->auth_version,
            (int) $requester->authorization_version, (string) Str::uuid7(), $now, $now);
        $reviewerContext = new ProviderContext($reviewerId, (int) $reviewer->auth_version,
            (int) $reviewer->authorization_version, (string) Str::uuid7(), $now, $now);
        $authorization = app(ProviderAuthorizationService::class);
        $authorization->assertCapability($requesterContext, 'company.provision');
        $authorization->assertCapability($reviewerContext, 'provider.approval.review');

        return [(object) ['id' => $requesterId], (object) ['id' => $reviewerId],
            $requesterContext, $reviewerContext];
    }

    private function assertPinnedDisposableTarget(): void
    {
        $name = getenv('ENG05E_DB_NAME');
        $oid = getenv('ENG05E_DB_OID');
        $system = getenv('ENG05E_SYSTEM_ID');
        if (app()->environment() !== 'testing' || getenv('ENG05E_TEST_RUN') !== 'DALEEL_ENG_05E_OPTIONAL_EDIT_REASON_SECURE_HISTORY'
            || ! is_string($name) || ! preg_match('/^eng05e_20261017_c73a295e_[ab]$/D', $name)
            || ! is_string($oid) || ! ctype_digit($oid) || ! is_string($system) || ! ctype_digit($system)) {
            throw new RuntimeException('Refusing ENG-05E tests outside the exact private disposable target.');
        }
        foreach (['pgsql', 'pgsql_provider', 'pgsql_provider_control'] as $connectionName) {
            $connection = DB::connection($connectionName);
            $facts = $connection->selectOne(<<<'SQL'
                SELECT current_database() AS db, (SELECT oid::text FROM pg_database WHERE datname=current_database()) AS oid,
                       current_user AS usr, session_user AS sess, r.rolsuper AS super, r.rolbypassrls AS bypass,
                       r.rolcreatedb AS createdb, r.rolcreaterole AS createrole,
                       has_schema_privilege(current_user, 'public', 'CREATE') AS schema_create
                FROM pg_roles r WHERE r.rolname=current_user
            SQL);
            if ($facts->db !== $name || $facts->oid !== $oid || $facts->usr !== $facts->sess
                || $facts->super || $facts->bypass || $facts->createdb || $facts->createrole || $facts->schema_create) {
                throw new RuntimeException("{$connectionName} is not a pinned non-bypass ENG-05E runtime role.");
            }
        }
    }
}
