<?php

declare(strict_types=1);

namespace Tests\Feature\Identity;

use Illuminate\Cookie\CookieValuePrefix;
use Illuminate\Encryption\Encrypter;
use PDO;
use PDOException;
use PHPUnit\Framework\TestCase;
use Ramsey\Uuid\Uuid;
use Tests\Support\Eng06CompanyHttpClient;
use OTPHP\TOTP;
use RuntimeException;

/**
 * Real HTTP acceptance against one pinned, newly migrated ENG-06 database.
 * This intentionally does not bootstrap Laravel's RefreshDatabase trait.
 */
final class Eng06CompanyContextAuthorizationTest extends TestCase
{
    private string $tag;
    private string $prefix;
    private string $dbName;
    private string $runId;
    private string $serverIp;
    private string $sessionCookie;
    private array $actors = [];
    private array $cases = [];

    protected function setUp(): void
    {
        parent::setUp();
        $this->tag = (string) getenv('ENG06_DB_TAG');
        $this->prefix = (string) getenv('ENG06_PREFIX');
        $this->dbName = (string) getenv('ENG06_DB_NAME');
        self::assertContains($this->tag, ['a', 'b', 'c'], 'Refusing an unpinned ENG-06A database.');
        self::assertMatchesRegularExpression('/^eng06a_20261017_[a-f0-9]{8}$/D', $this->prefix);
        self::assertSame($this->prefix.'_'.$this->tag, $this->dbName);
        self::assertSame($this->dbName, getenv('DB_DATABASE'));
        self::assertSame('1', (string) ini_get('zend.exception_ignore_args'),
            'Refusing to run with PHP exception arguments enabled.');

        $this->runId = bin2hex(random_bytes(5));
        $container = $this->prefix.'_http_'.$this->tag;
        $this->serverIp = gethostbyname($container);
        self::assertNotSame($container, $this->serverIp, 'Refusing an unresolved private HTTP target.');
        $this->sessionCookie = (string) getenv('ENG06_SESSION_COOKIE');
        self::assertNotSame('', $this->sessionCookie);
        $this->actors = json_decode(
            trim((string) file_get_contents('/fixture/'.$this->tag.'_actor_ids.json')),
            true,
            flags: JSON_THROW_ON_ERROR,
        );
        $this->checkDatabaseIdentity('migrator');
    }

    public function test_company_context_authorization_and_provider_regression_over_real_http(): void
    {
        $requester = $this->loginProvider('requester');
        $reviewer = $this->loginProvider('reviewer');

        $sharedAdminEmail = "eng06.shared.admin.{$this->tag}.{$this->runId}@example.invalid";
        $companyA = $this->provisionCompany($requester, $reviewer, 'a', $sharedAdminEmail);
        $companyB = $this->provisionCompany($requester, $reviewer, 'b', $sharedAdminEmail);
        self::assertNotSame($companyA['tenant_id'], $companyB['tenant_id']);
        self::assertNotSame($companyA['hostname'], $companyB['hostname']);

        $adminA = $this->loginTenant($companyA['hostname'], $sharedAdminEmail, $this->secret('admin_a_password'));
        $adminB = $this->loginTenant($companyB['hostname'], $sharedAdminEmail, $this->secret('admin_b_password'));
        $contextAResponse = $adminA->request('GET', '/api/v1/company/context');
        $contextBResponse = $adminB->request('GET', '/api/v1/company/context');
        $this->expectHttp('C01_CONTEXT_A', $contextAResponse, 200);
        $this->expectHttp('C02_CONTEXT_B_SAME_EMAIL', $contextBResponse, 200);
        $contextA = $contextAResponse['data'] ?? [];
        $contextB = $contextBResponse['data'] ?? [];
        $contextFieldNames = array_keys($contextA);
        $staffFieldNames = array_keys($contextA['staff'] ?? []);
        $membershipFieldNames = array_keys($contextA['membership'] ?? []);
        sort($contextFieldNames);
        sort($staffFieldNames);
        sort($membershipFieldNames);
        $this->check('C01_CONTEXT_A_SAFE_SHAPE', ($contextA['company'] ?? []) === [
            'id' => $companyA['tenant_id'], 'slug' => $companyA['slug'], 'status' => 'ACTIVE',
        ] && ($contextA['staff']['email'] ?? null) === $sharedAdminEmail
            && ($contextA['staff']['status'] ?? null) === 'ACTIVE'
            && ($contextA['membership']['status'] ?? null) === 'ACTIVE'
            && $contextFieldNames === ['company', 'membership', 'staff']
            && $staffFieldNames === ['email', 'id', 'name', 'status']
            && $membershipFieldNames === ['authorization_version', 'id', 'status']
            && isset($contextA['membership']['authorization_version'])
            && ! array_key_exists('display_name', $contextA['company'] ?? [])
            && ! array_key_exists('password_hash', $contextA['staff'] ?? []));
        $this->check('C02_CONTEXT_B_HOST_AND_IDENTITY_BOUND', ($contextB['company']['id'] ?? null) === $companyB['tenant_id']
            && ($contextB['company']['slug'] ?? null) === $companyB['slug']
            && ($contextB['staff']['id'] ?? null) !== ($contextA['staff']['id'] ?? null)
            && ($contextB['membership']['id'] ?? null) !== ($contextA['membership']['id'] ?? null));
        $this->check('SUCCESS_ENVELOPE_REQUEST_ID', is_string($contextAResponse['meta']['request_id'] ?? null)
            && $contextAResponse['meta']['request_id'] !== '');

        $authorizationBBeforeCrossHostDenials = $adminB->request('GET', '/api/v1/company/authorization');
        $this->expectHttp('R04_AUTHORIZATION_B_BEFORE_CROSS_HOST_DENIALS', $authorizationBBeforeCrossHostDenials, 200);

        $providerOnly = $requester->cookieHeader();
        $providerSession = $this->client($companyA['hostname'], 'http://localhost:3001')
            ->request('GET', '/api/v1/company/context', null, ['Cookie' => $providerOnly]);
        $this->expectHttp('C04_PROVIDER_ONLY_SESSION_DENIED', $providerSession, 401, 'AUTH_UNAUTHENTICATED');
        $unauthenticated = $this->client($companyA['hostname'], 'http://localhost:3001')
            ->request('GET', '/api/v1/company/context');
        $this->expectHttp('C04_UNAUTHENTICATED_DENIED', $unauthenticated, 401, 'AUTH_UNAUTHENTICATED');

        $crossAToB = $this->client($companyB['hostname'], 'http://localhost:3001')->request(
            'GET',
            '/api/v1/company/context',
            null,
            ['Cookie' => $adminA->cookieHeader()],
        );
        $crossBToA = $this->client($companyA['hostname'], 'http://localhost:3001')->request(
            'GET',
            '/api/v1/company/authorization',
            null,
            ['Cookie' => $adminB->cookieHeader()],
        );
        $this->expectHttp('C03_COOKIE_A_ON_B_HOST_DENIED', $crossAToB, 401, 'AUTH_UNAUTHENTICATED');
        $this->expectHttp('C03_COOKIE_B_ON_A_HOST_DENIED', $crossBToA, 401, 'AUTH_UNAUTHENTICATED');
        $this->check('C03_NO_CROSS_COMPANY_DETAILS', ! str_contains($crossAToB['raw_body'], $companyB['tenant_id'])
            && ! str_contains($crossAToB['raw_body'], $contextA['staff']['id'])
            && ! str_contains($crossBToA['raw_body'], $companyA['tenant_id'])
            && ! str_contains($crossBToA['raw_body'], $contextB['staff']['id']));

        $authorizationBAfterCrossHostDenials = $adminB->request('GET', '/api/v1/company/authorization');
        $this->check('R04_B_STATE_AFTER_CROSS_HOST_DENIALS_CAPTURED', is_int($authorizationBAfterCrossHostDenials['status']), [
            'actual_status' => $authorizationBAfterCrossHostDenials['status'],
            'actual_error_code' => $authorizationBAfterCrossHostDenials['error_code'],
        ]);

        $unknownHost = $this->client('unmapped-'.$this->runId.'.crm.localhost', 'http://localhost:3001')
            ->request('GET', '/api/v1/company/context');
        $malformedHost = $this->client('wrong-prefix.invalid', 'http://localhost:3001')
            ->request('GET', '/api/v1/company/context');
        $this->expectHttp('C05_UNKNOWN_TENANT_HOST', $unknownHost, 404, 'RESOURCE_NOT_FOUND');
        $this->expectHttp('C05_UNTRUSTED_HOST', $malformedHost, 404, 'RESOURCE_NOT_FOUND');

        // The deliberate A-cookie-on-B negative can clear the shared session file; use a fresh A session for the remaining authenticated probes.
        $adminA = $this->loginTenant($companyA['hostname'], $sharedAdminEmail, $this->secret('admin_a_password'));
        $reauthenticatedContextA = $adminA->request('GET', '/api/v1/company/context');
        $this->expectHttp('C03_A_SESSION_REAUTHENTICATED_AFTER_CROSS_HOST_DENIAL', $reauthenticatedContextA, 200);
        $adminB = $this->loginTenant($companyB['hostname'], $sharedAdminEmail, $this->secret('admin_b_password'));
        $reauthenticatedContextB = $adminB->request('GET', '/api/v1/company/context');
        $this->expectHttp('C03_B_SESSION_REAUTHENTICATED_AFTER_CROSS_HOST_DENIAL', $reauthenticatedContextB, 200);

        $headerSelector = $adminA->request('GET', '/api/v1/company/context', null, [
            'X-Tenant-ID' => $companyB['tenant_id'],
        ]);
        $this->expectHttp('C05_X_TENANT_ID_REJECTED', $headerSelector, 400, 'TENANT_SELECTOR_NOT_ALLOWED');
        foreach ([
            ['tenant_id', $companyB['tenant_id']],
            ['member_id', $contextB['staff']['id']],
            ['role_id', '00000000-0000-4000-8000-000000000001'],
            ['capabilities', 'member.manage'],
        ] as [$field, $value]) {
            $response = $adminA->request('GET', '/api/v1/company/authorization?'.rawurlencode($field).'='.rawurlencode($value));
            $this->expectHttp('C05_QUERY_SELECTOR_'.$field, $response, 422, 'VALIDATION_FAILED');
            $this->check('C05_QUERY_SELECTOR_VALUE_NOT_ECHOED_'.$field,
                ! str_contains($response['raw_body'], (string) $value));
        }
        $bodySelector = $adminA->request('GET', '/api/v1/company/context', ['filters' => [
            'company_id' => $companyB['tenant_id'],
        ]]);
        $this->expectHttp('C05_BODY_SELECTOR_REJECTED', $bodySelector, 422, 'VALIDATION_FAILED');
        $this->check('C05_BODY_SELECTOR_VALUE_NOT_ECHOED', ! str_contains($bodySelector['raw_body'], $companyB['tenant_id']));
        $wrongOrigin = $this->client($companyA['hostname'], 'https://evil.invalid')->request(
            'GET',
            '/api/v1/company/context',
            null,
            ['Cookie' => $adminA->cookieHeader()],
        );
        $this->expectHttp('C05_ORIGIN_REJECTED', $wrongOrigin, 403, 'PERMISSION_DENIED');
        $wrongMethod = $adminA->request('POST', '/api/v1/company/context', []);
        $this->expectHttp('C05_UNSUPPORTED_METHOD', $wrongMethod, 405);
        $csrfProbe = $this->client($companyA['hostname'], 'http://localhost:3001');
        $this->expectHttp('CSRF_COOKIE_ISSUED', $csrfProbe->request('GET', '/sanctum/csrf-cookie'), 204);
        $missingCsrf = $csrfProbe->request('POST', '/api/v1/auth/login', [
            'email' => $sharedAdminEmail, 'password' => $this->secret('admin_a_password'),
        ], [], false);
        $this->expectHttp('CSRF_INVALID_DENIED', $missingCsrf, 419, 'AUTH_CSRF_INVALID');

        $authorizationA = $adminA->request('GET', '/api/v1/company/authorization');
        $authorizationB = $adminB->request('GET', '/api/v1/company/authorization');
        $this->expectHttp('R04_AUTHORIZATION_A_NON_501', $authorizationA, 200);
        $this->expectHttp('R04_AUTHORIZATION_B_NON_501', $authorizationB, 200);
        $expectedAdminKeys = [
            'company.administer', 'member.manage', 'member.view', 'role.manage', 'role.view',
        ];
        $adminPermissionsA = $authorizationA['data']['permissions'] ?? [];
        $adminPermissionsB = $authorizationB['data']['permissions'] ?? [];
        $authorizationFields = array_keys($authorizationA['data'] ?? []);
        sort($authorizationFields);
        $this->check('A01_REAL_ADMIN_CATALOG_UNION_A',
            array_column($adminPermissionsA, 'key') === $expectedAdminKeys
            && $this->permissionFieldsAreAllowlisted($adminPermissionsA)
            && $authorizationFields === ['authorization_version', 'membership_id', 'permissions']
            && ($authorizationA['data']['membership_id'] ?? null) === $contextA['membership']['id']
            && ($authorizationA['data']['authorization_version'] ?? null) === 1);
        $this->check('A01_REAL_ADMIN_CATALOG_UNION_B',
            array_column($adminPermissionsB, 'key') === $expectedAdminKeys
            && $this->permissionFieldsAreAllowlisted($adminPermissionsB)
            && ($authorizationB['data']['membership_id'] ?? null) === $contextB['membership']['id']);
        $adminPermissionMap = [];
        foreach ($adminPermissionsA as $permission) {
            $adminPermissionMap[$permission['key']] = $permission;
        }
        $this->check('A06_NONDELEGABLE_ADMIN_AND_SCOPE_METADATA',
            ($adminPermissionMap['company.administer']['scopes'] ?? null) === ['ALL_TENANT']
            && ($adminPermissionMap['company.administer']['scopeable'] ?? null) === true
            && ($adminPermissionMap['company.administer']['delegable'] ?? null) === false
            && is_array($adminPermissionMap['role.view'] ?? null)
            && array_key_exists('scopes', $adminPermissionMap['role.view'])
            && $adminPermissionMap['role.view']['scopes'] === null
            && ($adminPermissionMap['role.view']['scopeable'] ?? null) === false);
        $this->captureWarmHttpSamples($adminA);

        $staff = $this->seedNonAdminStaff($companyA, $companyB, $contextA, $contextB);
        $sharedStaffA = $this->loginTenant($companyA['hostname'], $staff['email'], $this->secret('shared_a_password'));
        $sharedStaffB = $this->loginTenant($companyB['hostname'], $staff['email'], $this->secret('shared_b_password'));
        $sharedContextA = $sharedStaffA->request('GET', '/api/v1/company/context');
        $sharedContextB = $sharedStaffB->request('GET', '/api/v1/company/context');
        $this->expectHttp('C02_SHARED_STAFF_A_LOGIN', $sharedContextA, 200);
        $this->expectHttp('C02_SHARED_STAFF_B_LOGIN', $sharedContextB, 200);
        $this->check('C02_SHARED_EMAIL_SEPARATE_STAFF_IDENTITIES',
            ($sharedContextA['data']['staff']['email'] ?? null) === $staff['email']
            && ($sharedContextB['data']['staff']['email'] ?? null) === $staff['email']
            && ($sharedContextA['data']['staff']['id'] ?? null) !== ($sharedContextB['data']['staff']['id'] ?? null));

        $staffAuthA = $sharedStaffA->request('GET', '/api/v1/company/authorization');
        $staffAuthB = $sharedStaffB->request('GET', '/api/v1/company/authorization');
        $this->expectHttp('A02_NONADMIN_AUTHORIZATION_A', $staffAuthA, 200);
        $this->expectHttp('A02_NONADMIN_AUTHORIZATION_B', $staffAuthB, 200);
        $staffPermissionsA = $staffAuthA['data']['permissions'] ?? [];
        $staffPermissionsB = $staffAuthB['data']['permissions'] ?? [];
        $this->check('A03_ROLE_DIRECT_UNION_DEDUP_AND_SCOPE',
            array_column($staffPermissionsA, 'key') === ['member.view', 'role.view']
            && count($staffPermissionsA) === 2
            && ($staffPermissionsA[0]['scopes'] ?? 'missing') === null
            && ($staffPermissionsA[1]['scopes'] ?? 'missing') === null);
        $this->check('A04_TENANT_A_PERMISSION_NOT_IN_B',
            array_column($staffPermissionsB, 'key') === ['member.manage']
            && ! in_array('member.view', array_column($staffPermissionsB, 'key'), true)
            && ! in_array('role.view', array_column($staffPermissionsB, 'key'), true));
        $forgedMemberAuth = $sharedStaffA->request('GET', '/api/v1/company/authorization?member_id='
            .rawurlencode($contextA['membership']['id']));
        $forgedRoleAuth = $sharedStaffA->request('GET', '/api/v1/company/authorization?role_id='
            .rawurlencode($staff['a']['role_id']));
        $this->expectHttp('A07_OTHER_MEMBER_AUTHORIZATION_SELECTOR_REJECTED', $forgedMemberAuth, 422, 'VALIDATION_FAILED');
        $this->expectHttp('A07_ROLE_SELECTOR_REJECTED', $forgedRoleAuth, 422, 'VALIDATION_FAILED');
        $this->check('A07_NO_OTHER_MEMBER_AUTHORIZATION_RETURNED',
            ! str_contains($forgedMemberAuth['raw_body'], $contextA['membership']['id'])
            && ! isset($forgedMemberAuth['data']['permissions']));

        $revocation = $this->revokeStaffAuthorization($companyA, $contextA, $staff['a']);
        $this->check('A05_ROLE_AND_DIRECT_REVOCATION_WRITES',
            $revocation['role_rows'] === 1 && $revocation['grant_rows'] === 1);
        $afterRoleRevocation = $sharedStaffA->request('GET', '/api/v1/company/authorization');
        $this->expectHttp('A05_PERMISSION_SNAPSHOT_AFTER_ROLE_REVOKE', $afterRoleRevocation, 200);
        $this->check('A05_ROLE_REVOCATION_IMMEDIATE', array_column(
            $afterRoleRevocation['data']['permissions'] ?? [], 'key',
        ) === ['member.view']);
        $this->revokeStaffDirectGrant($companyA, $contextA, $staff['a']);
        $afterDirectRevocation = $sharedStaffA->request('GET', '/api/v1/company/authorization');
        $this->expectHttp('A05_PERMISSION_SNAPSHOT_AFTER_DIRECT_REVOKE', $afterDirectRevocation, 200);
        $this->check('A05_DIRECT_REVOCATION_IMMEDIATE', ($afterDirectRevocation['data']['permissions'] ?? []) === []);

        $this->checkDatabaseRlsAndAcl($companyA['tenant_id'], $companyB['tenant_id'], $contextA['staff']['id']);
        $this->checkNoInvitationPath($adminA);

        $companyInviteRoute = $adminA->request('GET', '/api/v1/company/invitations');
        $this->expectHttp('R03_NO_V1_COMPANY_INVITATION_ROUTE', $companyInviteRoute, 404, 'RESOURCE_NOT_FOUND');

        $this->checkProviderEditRevokeRegression($requester, $reviewer, $adminA, $sharedAdminEmail);

        $sequentialA = $adminA->request('GET', '/api/v1/company/context');
        $sequentialB = $adminB->request('GET', '/api/v1/company/context');
        $sequentialUnauth = $this->client($companyA['hostname'], 'http://localhost:3001')
            ->request('GET', '/api/v1/company/context');
        $this->expectHttp('C07_SEQUENTIAL_A_CONTEXT', $sequentialA, 200);
        $this->expectHttp('C07_SEQUENTIAL_B_CONTEXT', $sequentialB, 200);
        $this->expectHttp('C07_SEQUENTIAL_UNAUTH_DENIED', $sequentialUnauth, 401, 'AUTH_UNAUTHENTICATED');
        $this->check('C07_NO_STICKY_CONTEXT', ($sequentialA['data']['company']['id'] ?? null) === $companyA['tenant_id']
            && ($sequentialB['data']['company']['id'] ?? null) === $companyB['tenant_id']
            && ! str_contains($sequentialUnauth['raw_body'], $companyA['tenant_id'])
            && ! str_contains($sequentialUnauth['raw_body'], $companyB['tenant_id']));

        $expiredAdmin = $this->loginTenant($companyA['hostname'], $sharedAdminEmail, $this->secret('admin_a_password'));
        $expiredSessionChanged = $this->expireTenantSession($expiredAdmin);
        $expiredResponse = $expiredAdmin->request('GET', '/api/v1/company/context');
        $this->expectHttp('C06_ABSOLUTE_SESSION_EXPIRY', $expiredResponse, 401, 'AUTH_SESSION_EXPIRED');
        $this->check('C06_SESSION_EXPIRY_FIXTURE_WAS_OLD', $expiredSessionChanged);

        $this->updateStaffStatus($companyA, $contextA, $staff['a']['user_id'], 'DISABLED');
        $disabledResponse = $sharedStaffA->request('GET', '/api/v1/company/context');
        $this->expectHttp('C06_DISABLED_STAFF_DENIED', $disabledResponse, 401, 'AUTH_UNAUTHENTICATED');
        $this->check('C06_DISABLED_ACCOUNT_NO_IDENTITY_LEAK',
            ! str_contains($disabledResponse['raw_body'], $staff['a']['user_id']));

        $this->updateMembershipStatus($companyB, $contextB, $staff['b']['membership_id'], 'SUSPENDED');
        $suspendedMembership = $sharedStaffB->request('GET', '/api/v1/company/context');
        $this->expectHttp('C06_SUSPENDED_MEMBERSHIP_DENIED', $suspendedMembership, 401, 'AUTH_UNAUTHENTICATED');
        $this->bumpStaffAuthVersion($companyB, $contextB, $contextB['staff']['id']);
        $revokedSession = $adminB->request('GET', '/api/v1/company/context');
        $this->expectHttp('C06_REVOKED_AUTH_VERSION_DENIED', $revokedSession, 401, 'AUTH_UNAUTHENTICATED');

        $activeAdminA = $this->loginTenant($companyA['hostname'], $sharedAdminEmail, $this->secret('admin_a_password'));
        $this->suspendCompany($companyA, $contextA);
        $suspendedCompany = $activeAdminA->request('GET', '/api/v1/company/context');
        $this->expectHttp('C06_SUSPENDED_COMPANY_DENIED', $suspendedCompany, 401, 'AUTH_UNAUTHENTICATED');

        file_put_contents('/report/ENG06_HTTP_CASES_'.strtoupper($this->tag).'.json',
            json_encode(['database' => $this->dbName, 'cases' => $this->cases], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES).PHP_EOL);
        fwrite(STDOUT, json_encode([
            'database_tag' => $this->tag,
            'case_count' => count($this->cases),
            'company_a_id' => $companyA['tenant_id'],
            'company_b_id' => $companyB['tenant_id'],
            'same_email_different_staff_ids' => true,
            'report' => 'ENG06_HTTP_CASES_'.strtoupper($this->tag).'.json',
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES).PHP_EOL);
    }

    #[\PHPUnit\Framework\Attributes\Group('eng06a-canary')]
    public function test_provider_execute_exception_redacts_canary_before_reporting(): void
    {
        self::assertSame('c', $this->tag, 'The intentional RLS canary runs only on isolated database C.');

        $requester = $this->loginProvider('requester');
        $reviewer = $this->loginProvider('reviewer');
        $slug = 'eng06a-canary-'.$this->tag.'-'.$this->runId;
        $intent = [
            'display_name' => 'ENG-06A redaction probe',
            'slug' => $slug,
            'timezone' => 'UTC',
            'first_admin_email' => 'eng06a.canary.'.$this->tag.'.'.$this->runId.'@example.invalid',
            'first_admin_display_name' => 'ENG-06A canary first administrator',
            'reason' => 'Private ENG-06A exception redaction probe',
            'ticket_reference' => 'ENG06A-CANARY-'.$this->tag.'-001',
        ];
        $created = $requester->request('POST', '/api/v1/super/provisioning-operations', $intent, [
            'Idempotency-Key' => 'ENG06A-CANARY-'.$this->tag.'-'.$this->runId,
        ]);
        $this->expectHttp('ENG06A_CANARY_CREATE', $created, 202);
        $operationId = (string) ($created['data']['id'] ?? '');
        $approvalId = (string) ($created['data']['approval_request_id'] ?? '');
        $approved = $reviewer->request('POST', '/api/v1/super/approvals/'.$approvalId.'/approve', [
            'reason' => 'ENG-06A independent canary review',
            'ticket_reference' => 'ENG06A-CANARY-REVIEW-'.$this->runId,
            'expected_revision' => 1,
        ]);
        $this->expectHttp('ENG06A_CANARY_APPROVE', $approved, 200);

        $executed = $requester->request('POST',
            '/api/v1/super/provisioning-operations/'.$operationId.'/execute', [
                'initial_password' => $this->secret('eng06a_canary_password'),
            ]);
        $this->expectHttp('ENG06A_CANARY_EXPECTED_RLS_FAILURE', $executed, 500, 'INTERNAL_ERROR');
        $secretAbsent = ($executed['canary_secret_present'] ?? true) === false;
        $diagnosticPresent = ($executed['safe_provider_diagnostic_present'] ?? false) === true;
        $surfaceCount = (int) ($executed['canary_surfaces_scanned'] ?? 0);
        $this->check('ENG06A_CANARY_SECRET_ABSENT', $secretAbsent);
        $this->check('ENG06A_SAFE_EXCEPTION_DIAGNOSTIC_PRESENT', $diagnosticPresent);
        $this->check('ENG06A_CANARY_SURFACES_SCANNED', $surfaceCount >= 4, ['surface_count' => $surfaceCount]);

        $result = [
            'database_tag' => $this->tag,
            'http_status' => $executed['status'],
            'safe_error_code' => $executed['error_code'],
            'canary_secret_present' => false,
            'surfaces_scanned_after_execute' => $surfaceCount,
            'safe_exception_diagnostic_present' => $diagnosticPresent,
        ];
        file_put_contents('/report/ENG06A_REDACTION_CANARY_C.json',
            json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR).PHP_EOL);
        fwrite(STDOUT, json_encode($result, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES).PHP_EOL);
    }

    private function loginProvider(string $actor): Eng06CompanyHttpClient
    {
        $email = $actor.'.'.$this->tag.'.eng06@example.invalid';
        $password = $this->secret($actor.'_password');

        $missingXsrfClient = $this->client('api.crm.localhost', 'http://localhost:3002');
        $this->expectHttp('R01_PROVIDER_MISSING_XSRF_CSRF_COOKIE_'.$actor,
            $missingXsrfClient->request('GET', '/sanctum/csrf-cookie'), 204);
        $missingXsrfLogin = $missingXsrfClient->request('POST', '/api/v1/super/auth/login', [
            'email' => $email,
            'password' => $password,
        ], [], false);
        $this->expectHttp('R01_PROVIDER_MISSING_XSRF_DENIED_'.$actor, $missingXsrfLogin, 419);
        $this->check('R01_PROVIDER_MISSING_XSRF_NO_CREDENTIAL_ECHO_'.$actor,
            ! str_contains($missingXsrfLogin['raw_body'], $email)
            && ! str_contains($missingXsrfLogin['raw_body'], $password)
            && $missingXsrfLogin['data'] === null);
        $missingXsrfMe = $missingXsrfClient->request('GET', '/api/v1/super/auth/me');
        $this->expectHttp('R01_PROVIDER_MISSING_XSRF_NO_SESSION_'.$actor, $missingXsrfMe, 401);

        $untrustedOriginClient = $this->client('api.crm.localhost', 'http://localhost:3002');
        $this->expectHttp('R01_PROVIDER_UNTRUSTED_ORIGIN_CSRF_COOKIE_'.$actor,
            $untrustedOriginClient->request('GET', '/sanctum/csrf-cookie'), 204);
        $untrustedOriginLogin = $untrustedOriginClient->request('POST', '/api/v1/super/auth/login', [
            'email' => $email,
            'password' => $password,
        ], ['Origin' => 'https://untrusted.invalid']);
        $this->expectHttp('R01_PROVIDER_UNTRUSTED_ORIGIN_DENIED_'.$actor, $untrustedOriginLogin, 403);
        $this->check('R01_PROVIDER_UNTRUSTED_ORIGIN_NO_CREDENTIAL_ECHO_'.$actor,
            ! str_contains($untrustedOriginLogin['raw_body'], $email)
            && ! str_contains($untrustedOriginLogin['raw_body'], $password)
            && $untrustedOriginLogin['data'] === null);
        $untrustedOriginMe = $untrustedOriginClient->request('GET', '/api/v1/super/auth/me', null, [
            'Origin' => 'http://localhost:3002',
        ]);
        $this->expectHttp('R01_PROVIDER_UNTRUSTED_ORIGIN_NO_SESSION_'.$actor, $untrustedOriginMe, 401);

        $client = $this->client('api.crm.localhost', 'http://localhost:3002');
        $this->expectHttp('R01_PROVIDER_CSRF_'.$actor, $client->request('GET', '/sanctum/csrf-cookie'), 204);
        $login = $client->request('POST', '/api/v1/super/auth/login', [
            'email' => $email,
            'password' => $password,
        ]);
        $this->expectHttp('R01_PROVIDER_LOGIN_'.$actor, $login, 200);
        $this->check('R01_PROVIDER_MFA_REQUIRED_'.$actor, ($login['data']['state'] ?? null) === 'MFA_REQUIRED');
        $totp = TOTP::createFromSecret($this->secret($this->tag.'_'.$actor.'_totp_secret'))
            ->at((intdiv(time(), 30) + 1) * 30);
        $mfa = $client->request('POST', '/api/v1/super/auth/mfa/verify', ['code' => $totp]);
        $this->expectHttp('R01_PROVIDER_MFA_'.$actor, $mfa, 200);
        $me = $client->request('GET', '/api/v1/super/auth/me');
        $this->expectHttp('R01_PROVIDER_SESSION_'.$actor, $me, 200);
        $this->check('R01_PROVIDER_ACTOR_BOUND_'.$actor,
            ($me['data']['id'] ?? null) === ($this->actors[$actor] ?? null)
            && ($me['data']['step_up_valid'] ?? false) === true);

        return $client;
    }

    private function provisionCompany(
        Eng06CompanyHttpClient $requester,
        Eng06CompanyHttpClient $reviewer,
        string $slot,
        string $firstAdminEmail,
    ): array {
        $slug = 'eng06-'.$this->tag.'-'.$this->runId.'-'.$slot;
        $intent = [
            'display_name' => 'ENG-06 isolated '.$slot,
            'slug' => $slug,
            'timezone' => 'UTC',
            'first_admin_email' => $firstAdminEmail,
            'first_admin_display_name' => 'ENG-06 First Admin '.$slot,
            'reason' => 'ENG-06 private integration fixture',
            'ticket_reference' => 'ENG06-PROVISION-'.strtoupper($slot).'-001',
        ];
        $created = $requester->request('POST', '/api/v1/super/provisioning-operations', $intent, [
            'Idempotency-Key' => 'ENG06-'.$this->tag.'-'.$this->runId.'-'.$slot.'-CREATE',
        ]);
        $this->expectHttp('R01_PROVIDER_CREATE_'.$slot, $created, 202);
        $operationId = (string) ($created['data']['id'] ?? '');
        $approvalId = (string) ($created['data']['approval_request_id'] ?? '');
        $premature = $requester->request('POST', '/api/v1/super/provisioning-operations/'.$operationId.'/execute', [
            'initial_password' => $this->secret('admin_'.$slot.'_password'),
        ]);
        $this->expectHttp('R01_UNAPPROVED_EXECUTION_DENIED_'.$slot, $premature, 403, 'PROVIDER_APPROVAL_NOT_USABLE');
        $approved = $reviewer->request('POST', '/api/v1/super/approvals/'.$approvalId.'/approve', [
            'reason' => 'ENG-06 independent fixture review',
            'ticket_reference' => 'ENG06-REVIEW-'.strtoupper($slot).'-001',
            'expected_revision' => 1,
        ]);
        $this->expectHttp('R01_PROVIDER_APPROVE_'.$slot, $approved, 200);
        $executed = $requester->request('POST',
            '/api/v1/super/provisioning-operations/'.$operationId.'/execute', [
                'initial_password' => $this->secret('admin_'.$slot.'_password'),
            ]);
        $this->expectHttp('R01_PROVIDER_EXECUTE_'.$slot, $executed, 200);
        $this->check('R01_FIRST_ADMIN_CREATED_DIRECTLY_'.$slot,
            ($executed['data']['status'] ?? null) === 'SUCCEEDED'
            && ($executed['data']['hostname'] ?? null) === $slug.'.crm.localhost');

        return [
            'tenant_id' => (string) ($executed['data']['tenant_id'] ?? ''),
            'hostname' => (string) ($executed['data']['hostname'] ?? ''),
            'slug' => $slug,
            'operation_id' => $operationId,
        ];
    }

    private function loginTenant(string $host, string $email, string $password): Eng06CompanyHttpClient
    {
        $client = $this->client($host, 'http://localhost:3001');
        $csrf = $client->request('GET', '/sanctum/csrf-cookie');
        $this->expectHttp('TENANT_CSRF_COOKIE', $csrf, 204);
        $login = $client->request('POST', '/api/v1/auth/login', ['email' => $email, 'password' => $password]);
        $this->expectHttp('TENANT_STAFF_LOGIN', $login, 200);

        return $client;
    }

    private function seedNonAdminStaff(array $companyA, array $companyB, array $contextA, array $contextB): array
    {
        $pdo = $this->database('migrator');
        $email = 'eng06.shared.member.'.$this->tag.'.'.$this->runId.'@example.invalid';
        $staff = [];
        foreach ([
            'a' => [$companyA, $contextA, ['member.view', 'role.view'], 'shared_a_password'],
            'b' => [$companyB, $contextB, [], 'shared_b_password'],
        ] as $slot => [$company, $adminContext, $rolePermissions, $passwordFile]) {
            $userId = Uuid::uuid4()->toString();
            $membershipId = Uuid::uuid4()->toString();
            $roleId = $slot === 'a' ? Uuid::uuid4()->toString() : null;
            $this->beginTenantFixtureTransaction($pdo, $company['tenant_id'], $adminContext['staff']['id']);
            $insertUser = $pdo->prepare(<<<'SQL'
                INSERT INTO tenant_staff_users
                    (id, tenant_id, canonical_email, display_email, display_name, password_hash, status, auth_version, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', 1, now(), now())
            SQL);
            $insertUser->execute([
                $userId, $company['tenant_id'], $email, $email, 'ENG-06 shared staff '.$slot,
                password_hash($this->secret($passwordFile), PASSWORD_ARGON2ID),
            ]);
            $insertMembership = $pdo->prepare(<<<'SQL'
                INSERT INTO tenant_staff_memberships
                    (id, tenant_id, staff_user_id, status, authorization_version, joined_at,
                     created_by_membership_id, created_by_provider_operation_id, created_at, updated_at)
                VALUES (?, ?, ?, 'ACTIVE', 1, now(), ?, NULL, now(), now())
            SQL);
            $insertMembership->execute([$membershipId, $company['tenant_id'], $userId, $adminContext['membership']['id']]);

            if ($roleId !== null) {
                $pdo->prepare(<<<'SQL'
                    INSERT INTO roles
                        (id, tenant_id, display_name, normalized_name, status, source_template_id, version,
                         archived_at, created_at, updated_at)
                    VALUES (?, ?, 'ENG-06 role view fixture', 'eng06_role_view', 'ACTIVE', NULL, 1, NULL, now(), now())
                SQL)->execute([$roleId, $company['tenant_id']]);
                $insertRolePermission = $pdo->prepare(
                    'INSERT INTO role_permissions (tenant_id, role_id, permission_key, scope) VALUES (?, ?, ?, NULL)',
                );
                foreach ($rolePermissions as $key) {
                    $insertRolePermission->execute([$company['tenant_id'], $roleId, $key]);
                }
                $pdo->prepare(<<<'SQL'
                    INSERT INTO tenant_staff_membership_roles
                        (id, tenant_id, membership_id, role_id, assigned_by_membership_id,
                         assigned_by_provider_operation_id, assigned_at, revoked_at, revoked_by_membership_id, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, NULL, now(), NULL, NULL, now(), now())
                SQL)->execute([
                    Uuid::uuid4()->toString(), $company['tenant_id'], $membershipId, $roleId,
                    $adminContext['membership']['id'],
                ]);
            }

            $directKey = $slot === 'a' ? 'member.view' : 'member.manage';
            $directGrantId = Uuid::uuid4()->toString();
            $pdo->prepare(<<<'SQL'
                INSERT INTO tenant_staff_permission_grants
                    (id, tenant_id, membership_id, permission_key, scope, granted_by_membership_id,
                     granted_at, revoked_at, revoked_by_membership_id, created_at, updated_at)
                VALUES (?, ?, ?, ?, NULL, ?, now(), NULL, NULL, now(), now())
            SQL)->execute([
                $directGrantId, $company['tenant_id'], $membershipId, $directKey,
                $adminContext['membership']['id'],
            ]);
            $pdo->commit();

            $staff[$slot] = [
                'user_id' => $userId,
                'membership_id' => $membershipId,
                'role_id' => $roleId,
                'direct_grant_id' => $directGrantId,
            ];
        }

        return ['email' => $email, 'a' => $staff['a'], 'b' => $staff['b']];
    }

    private function revokeStaffAuthorization(array $company, array $adminContext, array $staff): array
    {
        $pdo = $this->database('migrator');
        $this->beginTenantFixtureTransaction($pdo, $company['tenant_id'], $adminContext['staff']['id']);
        $role = $pdo->prepare(<<<'SQL'
            UPDATE tenant_staff_membership_roles
            SET revoked_at = now(), revoked_by_membership_id = ?, updated_at = now()
            WHERE tenant_id = ? AND membership_id = ? AND revoked_at IS NULL
        SQL);
        $role->execute([$adminContext['membership']['id'], $company['tenant_id'], $staff['membership_id']]);
        $grant = $pdo->prepare(<<<'SQL'
            UPDATE tenant_staff_permission_grants
            SET revoked_at = now(), revoked_by_membership_id = ?, updated_at = now()
            WHERE tenant_id = ? AND membership_id = ? AND permission_key = 'member.view' AND revoked_at IS NULL
        SQL);
        $grant->execute([$adminContext['membership']['id'], $company['tenant_id'], $staff['membership_id']]);
        $result = ['role_rows' => $role->rowCount(), 'grant_rows' => $grant->rowCount()];
        $pdo->commit();

        return $result;
    }

    private function revokeStaffDirectGrant(array $company, array $adminContext, array $staff): void
    {
        $pdo = $this->database('migrator');
        $this->beginTenantFixtureTransaction($pdo, $company['tenant_id'], $adminContext['staff']['id']);
        $grant = $pdo->prepare(<<<'SQL'
            UPDATE tenant_staff_permission_grants
            SET revoked_at = now(), revoked_by_membership_id = ?, updated_at = now()
            WHERE tenant_id = ? AND membership_id = ? AND permission_key = 'member.view' AND revoked_at IS NULL
        SQL);
        $grant->execute([$adminContext['membership']['id'], $company['tenant_id'], $staff['membership_id']]);
        $result = $grant->rowCount();
        $pdo->commit();
        $this->check('A05_DIRECT_GRANT_REVOKED_IN_FIXTURE', $result === 1);
    }

    private function updateStaffStatus(array $company, array $adminContext, string $userId, string $status): void
    {
        $pdo = $this->database('migrator');
        $this->beginTenantFixtureTransaction($pdo, $company['tenant_id'], $adminContext['staff']['id']);
        $update = $pdo->prepare('UPDATE tenant_staff_users SET status = ?, updated_at = now() WHERE tenant_id = ? AND id = ?');
        $update->execute([$status, $company['tenant_id'], $userId]);
        $count = $update->rowCount();
        $pdo->commit();
        $this->check('C06_STAFF_STATE_ORACLE_'.$status, $count === 1);
    }

    private function updateMembershipStatus(array $company, array $adminContext, string $membershipId, string $status): void
    {
        $pdo = $this->database('migrator');
        $this->beginTenantFixtureTransaction($pdo, $company['tenant_id'], $adminContext['staff']['id']);
        $update = $pdo->prepare(<<<'SQL'
            UPDATE tenant_staff_memberships
            SET status = ?, authorization_version = authorization_version + 1, updated_at = now()
            WHERE tenant_id = ? AND id = ?
        SQL);
        $update->execute([$status, $company['tenant_id'], $membershipId]);
        $count = $update->rowCount();
        $pdo->commit();
        $this->check('C06_MEMBERSHIP_STATE_ORACLE_'.$status, $count === 1);
    }

    private function bumpStaffAuthVersion(array $company, array $adminContext, string $userId): void
    {
        $pdo = $this->database('migrator');
        $this->beginTenantFixtureTransaction($pdo, $company['tenant_id'], $adminContext['staff']['id']);
        $update = $pdo->prepare(<<<'SQL'
            UPDATE tenant_staff_users SET auth_version = auth_version + 1, updated_at = now()
            WHERE tenant_id = ? AND id = ?
        SQL);
        $update->execute([$company['tenant_id'], $userId]);
        $count = $update->rowCount();
        $pdo->commit();
        $this->check('C06_AUTH_VERSION_STATE_ORACLE', $count === 1);
    }

    private function suspendCompany(array $company, array $adminContext): void
    {
        $pdo = $this->database('migrator');
        $this->beginTenantFixtureTransaction($pdo, $company['tenant_id'], $adminContext['staff']['id']);
        $update = $pdo->prepare("UPDATE tenants SET status = 'SUSPENDED', updated_at = now() WHERE id = ?");
        $update->execute([$company['tenant_id']]);
        $count = $update->rowCount();
        $pdo->commit();
        $this->check('C06_COMPANY_STATE_ORACLE', $count === 1);
    }

    private function checkDatabaseRlsAndAcl(string $tenantA, string $tenantB, string $actorId): void
    {
        $pdo = $this->database('tenant_runtime');
        $identity = $pdo->query(<<<'SQL'
            SELECT current_database() AS db, current_user AS current_user, session_user AS session_user,
                   role.rolcanlogin, role.rolsuper, role.rolbypassrls,
                   has_schema_privilege(current_user, 'public', 'CREATE') AS can_create_public
            FROM pg_roles role WHERE role.rolname = current_user
        SQL)->fetch(PDO::FETCH_ASSOC);
        $this->check('A08_RUNTIME_ROLE_RESTRICTED',
            ($identity['db'] ?? null) === $this->dbName
            && ($identity['current_user'] ?? null) === ($identity['session_user'] ?? null)
            && $this->dbBoolean($identity['rolcanlogin'] ?? null)
            && ! $this->dbBoolean($identity['rolsuper'] ?? null)
            && ! $this->dbBoolean($identity['rolbypassrls'] ?? null)
            && ! $this->dbBoolean($identity['can_create_public'] ?? null));

        $bootstrap = $this->database('bootstrap');
        $rls = $bootstrap->query(<<<'SQL'
            SELECT relrowsecurity AS enabled, relforcerowsecurity AS forced,
                   pg_catalog.pg_get_userbyid(relowner) AS owner
            FROM pg_catalog.pg_class
            WHERE oid = 'public.tenant_staff_users'::regclass
        SQL)->fetch(PDO::FETCH_ASSOC);
        $this->check('A08_RLS_ENABLED_FORCED_AND_RUNTIME_NONOWNER',
            $this->dbBoolean($rls['enabled'] ?? null)
            && $this->dbBoolean($rls['forced'] ?? null)
            && ($rls['owner'] ?? null) !== ($identity['current_user'] ?? null));

        $unscoped = (int) $pdo->query('SELECT count(*) FROM public.tenant_staff_users')->fetchColumn();
        $this->check('A08_RLS_EMPTY_WITHOUT_CONTEXT', $unscoped === 0);
        $sqlState = null;
        try {
            $pdo->query('SELECT password_hash FROM public.tenant_staff_users LIMIT 1')->fetchColumn();
        } catch (PDOException $exception) {
            $sqlState = (string) ($exception->errorInfo[0] ?? $exception->getCode());
        }
        $this->check('A08_PASSWORD_HASH_COLUMN_ACL_DENIED', $sqlState === '42501');

        $pdo->beginTransaction();
        $this->setLocal($pdo, 'app.context_mode', 'TENANT');
        $this->setLocal($pdo, 'app.tenant_id', $tenantA);
        $this->setLocal($pdo, 'app.user_id', $actorId);
        $query = $pdo->prepare('SELECT count(*) FROM public.tenant_staff_users WHERE tenant_id = ?');
        $query->execute([$tenantA]);
        $visibleA = (int) $query->fetchColumn();
        $query->execute([$tenantB]);
        $visibleB = (int) $query->fetchColumn();
        $pdo->commit();
        $afterCommit = $pdo->query("SELECT COALESCE(current_setting('app.context_mode', true), '')")->fetchColumn();
        $afterCommitRows = (int) $pdo->query('SELECT count(*) FROM public.tenant_staff_users')->fetchColumn();
        $this->check('A08_FORGED_GUC_ONLY_FILTERS_ROWS_AND_COMMIT_CLEANS',
            $visibleA >= 2 && $visibleB === 0 && $afterCommit === '' && $afterCommitRows === 0);

        $pdo->beginTransaction();
        $this->setLocal($pdo, 'app.context_mode', 'TENANT');
        $this->setLocal($pdo, 'app.tenant_id', $tenantA);
        $this->setLocal($pdo, 'app.user_id', $actorId);
        $rolledBackRows = (int) $pdo->query('SELECT count(*) FROM public.tenant_staff_users')->fetchColumn();
        $pdo->rollBack();
        $afterRollback = $pdo->query("SELECT COALESCE(current_setting('app.context_mode', true), '')")->fetchColumn();
        $this->check('A08_ROLLBACK_CLEANS_GUC',
            $rolledBackRows >= 2 && $afterRollback === ''
            && (int) $pdo->query('SELECT count(*) FROM public.tenant_staff_users')->fetchColumn() === 0);
    }

    private function checkNoInvitationPath(Eng06CompanyHttpClient $client): void
    {
        $pdo = $this->database('migrator');
        $tables = $pdo->query(<<<'SQL'
            SELECT to_regclass('public.tenant_founder_invitations') IS NULL AS invitation_absent,
                   to_regclass('public.outbox_messages') IS NULL AS outbox_absent
        SQL)->fetch(PDO::FETCH_ASSOC);
        $this->check('R03_NO_INVITATION_OR_OUTBOX_TABLE',
            $this->dbBoolean($tables['invitation_absent'] ?? null)
            && $this->dbBoolean($tables['outbox_absent'] ?? null));
    }

    private function captureWarmHttpSamples(Eng06CompanyHttpClient $client): void
    {
        $samples = ['context' => [], 'authorization' => []];
        foreach (['context', 'authorization'] as $endpoint) {
            for ($index = 1; $index <= 5; $index++) {
                $response = $client->request('GET', '/api/v1/company/'.$endpoint);
                $this->expectHttp('PERF_WARM_'.$endpoint.'_'.str_pad((string) $index, 2, '0', STR_PAD_LEFT),
                    $response, 200);
                $samples[$endpoint][] = $response['elapsed_ms'];
            }
        }

        foreach ($samples as &$values) {
            sort($values, SORT_NUMERIC);
        }
        unset($values);
        $this->check('PERF_WARM_FIVE_SAMPLE_SUMMARY', count($samples['context']) === 5
            && count($samples['authorization']) === 5, [
                'context_ms' => $samples['context'],
                'context_p95_ms' => $samples['context'][4] ?? null,
                'authorization_ms' => $samples['authorization'],
                'authorization_p95_ms' => $samples['authorization'][4] ?? null,
            ]);
    }

    private function checkProviderEditRevokeRegression(
        Eng06CompanyHttpClient $requester,
        Eng06CompanyHttpClient $reviewer,
        Eng06CompanyHttpClient $tenantStaff,
        string $firstAdminEmail,
    ): void {
        $suffix = 'revoke-'.$this->tag.'-'.$this->runId;
        $intent = [
            'display_name' => 'ENG-06 pending edit '.$suffix,
            'slug' => 'eng06-'.$this->tag.'-'.$this->runId.'-pending',
            'timezone' => 'UTC',
            'first_admin_email' => $firstAdminEmail,
            'first_admin_display_name' => 'ENG-06 pending first admin',
            'reason' => 'ENG-06 bounded Provider regression',
            'ticket_reference' => 'ENG06-PENDING-001',
        ];
        $created = $requester->request('POST', '/api/v1/super/provisioning-operations', $intent, [
            'Idempotency-Key' => 'ENG06-'.$this->tag.'-'.$this->runId.'-PENDING',
        ]);
        $this->expectHttp('R02_PENDING_OPERATION_CREATED', $created, 202);
        $operation = (string) ($created['data']['id'] ?? '');
        $approval = (string) ($created['data']['approval_request_id'] ?? '');
        $reason = 'ENG06 encrypted edit proof '.bin2hex(random_bytes(12));
        $edit = $intent;
        unset($edit['reason'], $edit['ticket_reference']);
        $edit['expected_revision'] = 1;
        $edit['display_name'] .= ' revised';
        $edit['edit_reason'] = $reason;
        $edited = $requester->request('PATCH', '/api/v1/super/provisioning-operations/'.$operation, $edit);
        $this->expectHttp('R02_PENDING_OPERATION_EDITED', $edited, 200);
        $this->check('R02_EDIT_REVISION_AND_RESPONSE_REDACTION',
            ($edited['data']['revision'] ?? null) === 2
            && ! str_contains($edited['raw_body'], $reason)
            && ! array_key_exists('edit_reason', $edited['data'] ?? []));

        $historyPath = '/api/v1/super/provisioning-operations/'.$operation.'/revisions';
        $ownerHistory = $requester->request('GET', $historyPath);
        $this->expectHttp('R02_OWNER_REVISION_HISTORY', $ownerHistory, 200);
        $revisionTwo = null;
        foreach (($ownerHistory['data']['revisions'] ?? []) as $row) {
            if (($row['revision'] ?? null) === 2) {
                $revisionTwo = $row;
                break;
            }
        }
        $this->check('R02_OWNER_HISTORY_SAFE_PROJECTION', $revisionTwo !== null
            && ($revisionTwo['edit_reason'] ?? null) === $reason
            && ! array_key_exists('ciphertext', $revisionTwo)
            && ! array_key_exists('intent_digest', $revisionTwo));

        $tenantRead = $this->client('api.crm.localhost', 'http://localhost:3002')->request(
            'GET', $historyPath, null, ['Cookie' => $tenantStaff->cookieHeader()],
        );
        $this->expectHttp('R02_TENANT_STAFF_CANNOT_READ_PROVIDER_HISTORY', $tenantRead, 401, 'PROVIDER_AUTH_REQUIRED');
        $this->check('R02_WRONG_ACTOR_EDIT_REASON_NOT_EXPOSED', ! str_contains($tenantRead['raw_body'], $reason));
        $staleReview = $reviewer->request('POST', '/api/v1/super/approvals/'.$approval.'/approve', [
            'reason' => 'ENG-06 stale revision check',
            'ticket_reference' => 'ENG06-STALE-001',
            'expected_revision' => 1,
        ]);
        $this->expectHttp('R02_STALE_REVIEW_REVISION_REJECTED', $staleReview, 409, 'PROVIDER_REVISION_CONFLICT');
        $ownerRevoke = $requester->request('POST', '/api/v1/super/approvals/'.$approval.'/revoke', [
            'reason' => 'ENG-06 owner withdrew pending fixture',
            'ticket_reference' => 'ENG06-REVOKE-001',
        ]);
        $this->expectHttp('R02_OWNER_REVOKES_PENDING_APPROVAL', $ownerRevoke, 200);
        $this->check('R02_APPROVAL_REVOKED_STATE', ($ownerRevoke['data']['status'] ?? null) === 'REVOKED');
        $executeRevoked = $requester->request('POST',
            '/api/v1/super/provisioning-operations/'.$operation.'/execute', [
                'initial_password' => $this->secret('admin_a_password'),
            ]);
        $this->expectHttp('R02_REVOKED_OPERATION_CANNOT_EXECUTE', $executeRevoked, 403, 'PROVIDER_APPROVAL_NOT_USABLE');

        $oracle = $this->database('bootstrap');
        $target = $oracle->query(<<<'SQL'
            SELECT current_database() AS db,
                   (SELECT oid::text FROM pg_database WHERE datname = current_database()) AS oid,
                   (pg_control_system()).system_identifier::text AS system_id
        SQL)->fetch(PDO::FETCH_ASSOC);
        if (($target['db'] ?? null) !== $this->dbName
            || ($target['oid'] ?? null) !== getenv('ENG06_DB_OID')
            || ($target['system_id'] ?? null) !== getenv('ENG06_SYSTEM_ID')) {
            throw new RuntimeException('Provider regression oracle target guard failed.');
        }
        $oracle->beginTransaction();
        $oracle->exec('SET TRANSACTION READ ONLY');
        $cipherQuery = $oracle->prepare(<<<'SQL'
            SELECT edit_reason_ciphertext
            FROM provider_provision_revisions
            WHERE operation_id = ? AND revision = 2
        SQL);
        $cipherQuery->execute([$operation]);
        $ciphertext = $cipherQuery->fetchColumn();
        $auditQuery = $oracle->prepare(<<<'SQL'
            SELECT count(*) FROM security_audit_events
            WHERE event_type = 'provider.control_operation.edited'
              AND target_id = ? AND strpos(metadata::text, ?) > 0
        SQL);
        $auditQuery->execute([$operation, $reason]);
        $auditPlaintextCount = (int) $auditQuery->fetchColumn();
        $oracle->commit();
        $this->check('R02_REASON_CIPHERTEXT_AND_AUDIT_PRIVACY',
            is_string($ciphertext) && $ciphertext !== ''
            && ! str_contains($ciphertext, $reason)
            && $auditPlaintextCount === 0);
        $this->check('R02_REASON_NOT_IN_RUNTIME_LOGS',
            ! $this->fileContains('/var/www/html/storage/logs', $reason)
            && ! $this->fileContains('/var/www/html/storage/logs/eng06_http_server.log', $reason));
        $this->check('R02_REASON_NOT_IN_REPORT_ARTIFACTS', ! $this->fileContains('/report', $reason));
    }

    private function expireTenantSession(Eng06CompanyHttpClient $client): bool
    {
        $cookie = $client->cookieValue($this->sessionCookie);
        $appKey = base64_decode(trim((string) file_get_contents('/fixture/app_key_base64')), true);
        if (! is_string($cookie) || ! is_string($appKey) || strlen($appKey) !== 32) {
            return false;
        }
        $encrypter = new Encrypter($appKey, 'AES-256-CBC');
        $decrypted = $encrypter->decrypt(urldecode($cookie), false);
        $sessionId = CookieValuePrefix::validate($this->sessionCookie, $decrypted, [$appKey]);
        if (! is_string($sessionId) || $sessionId === '') {
            return false;
        }
        $directory = (string) getenv('ENG06_SESSION_DIR');
        $path = rtrim($directory, '/').'/'.$sessionId;
        $stored = is_file($path) ? file_get_contents($path) : false;
        if (! is_string($stored)) {
            return false;
        }
        try {
            $serialized = $encrypter->decrypt($stored, false);
        } catch (\Illuminate\Contracts\Encryption\DecryptException) {
            $serialized = $stored;
        }
        $attributes = json_decode($serialized, true);
        if (! is_array($attributes)
            || ! is_array($attributes['identity']['tenant_staff'] ?? null)) {
            return false;
        }
        $attributes['identity']['tenant_staff']['authenticated_at'] = time() - 28800;
        $serialized = json_encode($attributes, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        $stored = filter_var(getenv('SESSION_ENCRYPT'), FILTER_VALIDATE_BOOL)
            ? $encrypter->encrypt($serialized, false)
            : $serialized;

        return file_put_contents($path, $stored) !== false;
    }

    private function checkDatabaseIdentity(string $role): void
    {
        $pdo = $this->database($role);
        $actual = $pdo->query(<<<'SQL'
            SELECT current_database() AS db,
                   (SELECT oid::text FROM pg_database WHERE datname = current_database()) AS oid
        SQL)->fetch(PDO::FETCH_ASSOC);
        self::assertSame($this->dbName, $actual['db'] ?? null);
        self::assertSame(getenv('ENG06_DB_OID'), $actual['oid'] ?? null);
    }

    private function beginTenantFixtureTransaction(PDO $pdo, string $tenantId, string $userId): void
    {
        $pdo->beginTransaction();
        $this->setLocal($pdo, 'app.context_mode', 'TENANT');
        $this->setLocal($pdo, 'app.tenant_id', $tenantId);
        $this->setLocal($pdo, 'app.user_id', $userId);
    }

    private function setLocal(PDO $pdo, string $name, string $value): void
    {
        $set = $pdo->prepare('SELECT pg_catalog.set_config(?, ?, true)');
        $set->execute([$name, $value]);
    }

    private function database(string $role): PDO
    {
        if (! in_array($role, ['migrator', 'tenant_runtime', 'bootstrap'], true)) {
            throw new RuntimeException('Database role is outside the ENG-06 allowlist.');
        }
        // The disposable integrated runner supplies its own isolated role topology.
        // Bootstrap is used only for metadata/read-only acceptance oracles.
        $secretPath = match ($role) {
            'bootstrap' => '/fixture/pg_admin',
            'migrator' => '/fixture/migrator',
            'tenant_runtime' => '/fixture/tenant',
        };
        $login = (string) getenv(match ($role) {
            'bootstrap' => 'ENG06_BOOTSTRAP_LOGIN',
            'migrator' => 'ENG06_MIGRATOR_LOGIN',
            'tenant_runtime' => 'ENG06_TENANT_RUNTIME_LOGIN',
        });
        $host = (string) getenv('ENG06_DB_HOST');
        if ($login === '' || $host === '') {
            throw new RuntimeException('Disposable ENG-06 database role topology is not configured.');
        }

        return new PDO('pgsql:host='.$host.';port=5432;dbname='.$this->dbName, $login,
            trim((string) file_get_contents($secretPath)), [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_EMULATE_PREPARES => false,
            ]);
    }

    private function client(string $host, string $origin): Eng06CompanyHttpClient
    {
        return new Eng06CompanyHttpClient($host, $origin, $this->serverIp);
    }

    private function secret(string $name): string
    {
        $value = trim((string) file_get_contents('/fixture/'.$name));
        if ($value === '') {
            throw new RuntimeException('Required private fixture value is absent.');
        }

        return $value;
    }

    private function expectHttp(string $id, array $response, int $status, ?string $errorCode = null): void
    {
        $this->check($id, $response['status'] === $status
            && ($errorCode === null || $response['error_code'] === $errorCode), [
                'expected_status' => $status,
                'actual_status' => $response['status'],
                'expected_error_code' => $errorCode,
                'actual_error_code' => $response['error_code'],
                'elapsed_ms' => $response['elapsed_ms'],
            ]);
    }

    private function check(string $id, bool $passed, array $details = []): void
    {
        $this->cases[] = ['id' => $id, 'passed' => $passed] + $details;
        file_put_contents('/report/ENG06_HTTP_CASES_'.strtoupper($this->tag).'.json',
            json_encode(['database' => $this->dbName, 'cases' => $this->cases],
                JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES).PHP_EOL);
        self::assertTrue($passed, $id);
    }

    private function permissionFieldsAreAllowlisted(array $permissions): bool
    {
        foreach ($permissions as $permission) {
            if (! is_array($permission)) {
                return false;
            }
            $fields = array_keys($permission);
            sort($fields);
            if ($fields !== ['delegable', 'key', 'scopeable', 'scopes']) {
                return false;
            }
        }

        return true;
    }

    private function dbBoolean(mixed $value): bool
    {
        return $value === true || $value === 1 || $value === '1' || $value === 't' || $value === 'true';
    }

    private function fileContains(string $path, string $needle): bool
    {
        if (is_file($path)) {
            return str_contains((string) file_get_contents($path), $needle);
        }
        if (! is_dir($path)) {
            return false;
        }
        foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($path,
            \FilesystemIterator::SKIP_DOTS)) as $file) {
            if ($file->isFile() && str_contains((string) file_get_contents($file->getPathname()), $needle)) {
                return true;
            }
        }

        return false;
    }
}
