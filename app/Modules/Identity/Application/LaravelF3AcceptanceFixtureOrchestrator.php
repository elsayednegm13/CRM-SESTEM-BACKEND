<?php

declare(strict_types=1);

namespace App\Modules\Identity\Application;

use App\Modules\Identity\Domain\Exceptions\RestrictedTenantProbeCleanupException;
use App\Modules\Identity\Domain\TenantHostContext;
use App\Modules\Provider\Application\ProviderAcceptanceRequestBinder;
use App\Modules\Provider\Application\ProviderAuthenticationService;
use App\Modules\Provider\Application\ProviderAuthorizationService;
use App\Modules\Provider\Application\ProviderBootstrapService;
use App\Modules\Provider\Application\ProviderDirectProvisionService;
use App\Modules\Tenancy\Application\LeadService;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use LogicException;
use OTPHP\TOTP;
use Throwable;

/**
 * Internal acceptance fixture composition. Every authority and business write
 * uses the existing application services; this class has no route or raw SQL.
 */
final class LaravelF3AcceptanceFixtureOrchestrator implements F3AcceptanceFixtureOrchestrator
{
    public function __construct(
        private readonly ProviderBootstrapService $bootstrap,
        private readonly ProviderAuthenticationService $providerAuth,
        private readonly ProviderAuthorizationService $providerAuthorization,
        private readonly ProviderAcceptanceRequestBinder $providerRequests,
        private readonly ProviderDirectProvisionService $provision,
        private readonly FirstAdminActivationAuthorityService $activation,
        private readonly TenantAuthorityBridge $tenantAuthority,
        private readonly TenantAcceptanceRequestBinder $tenantRequests,
        private readonly TenantAuthorityRevoker $tenantRevoker,
        private readonly TenantStaffAccountService $staffAccounts,
        private readonly TenantStaffRoleMutationService $staffRoles,
        private readonly LeadService $leads,
    ) {}

    public function prepare(array $input): array
    {
        $requestId = (string) Str::uuid7();
        $provider = $input['provider'];
        $this->bootstrap->create([
            'bootstrap_secret' => $provider['bootstrap_secret'], 'email' => $provider['email'],
            'password' => $provider['password'], 'password_confirmation' => $provider['password'],
        ], $requestId);

        $request = $this->request('provider-fixture', $requestId);
        return $this->providerRequests->run($request, function () use ($input, $provider, $request): array {
            $passwordLogin = $this->providerAuth->login($request, $provider['email'], $provider['password']);
            if ($passwordLogin !== 'AUTHENTICATED') {
                throw new LogicException('Fresh Provider did not enter password-authenticated state.');
            }
            // MFA is optional for ordinary Provider functionality. Exercise a
            // normal RBAC lookup before enrollment, then retain the enrolled
            // path below for the separate high-risk provisioning boundary.
            $ordinaryContext = $this->providerAuthorization->current($request);
            if ($ordinaryContext->stepUpVerifiedAt !== null) {
                throw new LogicException('Fresh non-enrolled Provider unexpectedly has step-up authority.');
            }
            $stepUpBeforeEnrollment = 'ABSENT';
            $this->providerAuthorization->capabilities($ordinaryContext);
            $securityContext = $this->providerAuthorization->currentForSecuritySettings($request);
            $setup = $this->providerAuth->startSettingsEnrollment($request, $securityContext, $provider['password']);
            $secret = $setup['secret'] ?? null;
            if (! is_string($secret) || $secret === '') {
                throw new LogicException('Provider enrollment returned no factor secret.');
            }
            $recovery = $this->providerAuth->confirmSettingsEnrollment(
                $request, $securityContext, TOTP::createFromSecret($secret)->at(now('UTC')->timestamp),
            );
            unset($secret, $setup);
            if (count($recovery) < 2 || ! is_string($recovery[0]) || ! is_string($recovery[1])) {
                throw new LogicException('Provider enrollment returned insufficient one-time factors.');
            }
            $mfaLogin = $this->providerAuth->login($request, $provider['email'], $provider['password']);
            if ($mfaLogin !== 'MFA_REQUIRED') {
                throw new LogicException('Enrolled Provider did not require MFA.');
            }
            $this->providerAuth->verify($request, $recovery[0]);
            $context = $this->providerAuthorization->current($request);
            $this->providerAuth->stepUp($request, $context, $provider['password'], $recovery[1]);
            $context = $this->providerAuthorization->current($request);
            if ($context->stepUpVerifiedAt === null) {
                throw new LogicException('Provider step-up did not yield verified authority.');
            }
            // F4 application-authentication evidence: explicit per-subtest outcomes, never inferred.
            $result = ['run_id' => $input['run_id'], 'provider' => [
                'first_factor_login' => $passwordLogin,
                'step_up_before_enrollment' => $stepUpBeforeEnrollment,
                'mfa_after_enrollment' => $mfaLogin,
                'step_up' => 'VERIFIED',
                'provisioned_tenants' => 0,
            ], 'tenants' => []];
            try {
                foreach (['A','B'] as $key) {
                    $tenant = $input['tenants'][$key];
                    $created = $this->provision->create($context, [
                        'display_name' => $tenant['display_name'], 'slug' => $tenant['slug'],
                        'timezone' => $tenant['timezone'], 'first_admin_email' => $tenant['admin_email'],
                        'first_admin_display_name' => 'F3 Synthetic Admin '.$key,
                        'initial_password' => $tenant['initial_password'],
                    ], 'F3FIXTURE-'.strtoupper(substr(hash('sha256', $input['run_id'].'|'.$key), 0, 24)), $request);
                    $baseDomain = (string) config('tenancy.base_domain');
                    $hostname = (string) $created['hostname'];
                    if ($baseDomain === '' || ! hash_equals($tenant['slug'].'.'.$baseDomain, $hostname)) {
                        throw new LogicException('Provisioned tenant hostname does not match the configured acceptance domain.');
                    }
                    $host = new TenantHostContext((string) $created['tenant_id'], $tenant['slug'],
                        $hostname, $baseDomain, $this->environmentScope($baseDomain));
                    $this->activation->activate($this->request('activation-'.$key, (string) Str::uuid7()), $host,
                        $tenant['admin_email'], $tenant['initial_password'], $tenant['password'], (string) Str::uuid7());
                    $witness = $this->createLead($host, $tenant, $input['run_id'], $key);
                    $result['tenants'][$key] = [
                        'tenant_id' => (string) $created['tenant_id'], 'hostname' => (string) $created['hostname'],
                        'lead_id' => (string) $witness['lead']['id'], 'admin_email' => $tenant['admin_email'],
                        'admin_membership_id' => $witness['admin_membership_id'],
                        'observer_email' => $tenant['observer_email'],
                        'observer_membership_id' => $witness['observer_membership_id'],
                        'commit_xid' => $witness['commit_xid'],
                        'commit_backend_pid' => $witness['commit_backend_pid'],
                        'lead_committed_at' => $witness['committed_at'],
                    ];
                    $result['provider']['provisioned_tenants']++;
                }
            } finally {
                $this->providerAuth->logout($request);
            }

            return $result;
        });
    }

    private function createLead(TenantHostContext $host, array $tenant, string $runId, string $key): array
    {
        $request = $this->request('tenant-'.$key, (string) Str::uuid7());
        return $this->tenantRequests->run($request, function () use ($host, $tenant, $runId, $key, $request): array {
            $connection = DB::connection('pgsql_tenant_runtime');
            $cleanup = null;
            $primary = null;
            $cleanupFailure = null;
            $connection->beginTransaction();
            try {
                $authority = $this->tenantAuthority->authenticateAndBind(
                    $host, $tenant['admin_email'], $tenant['password'],
                    'f3fixture-'.substr(hash('sha256', $runId.'|'.$key), 0, 40), $request,
                );
                $cleanup = $request->attributes->get('tenant_staff_authority_cleanup');
                $lead = $this->leads->createLead($authority['context'], [
                    'name' => 'F3 Fixture Lead '.$key, 'source' => 'F3_ACCEPTANCE',
                ]);
                $observer = $this->staffAccounts->createStaffMember(
                    $authority['context'], $tenant['observer_email'], 'F3 Independent Observer '.$key,
                    $tenant['observer_password'],
                );
                $this->staffRoles->grantPermission(
                    $authority['context'], $observer['membership_id'], 'leads.view', 'ALL_TENANT',
                );
                $commit = $connection->selectOne(
                    'SELECT pg_current_xact_id()::text AS xid, pg_backend_pid()::int AS backend_pid',
                );
                if (! is_object($commit) || ! is_string($commit->xid ?? null)
                    || preg_match('/^\d+$/D', $commit->xid) !== 1
                    || ! is_numeric($commit->backend_pid ?? null) || (int) $commit->backend_pid < 1) {
                    throw new LogicException('F3 witness commit provenance is invalid.');
                }
                $connection->commit();
                return [
                    'lead' => $lead,
                    'admin_membership_id' => $authority['context']->membershipId,
                    'observer_membership_id' => $observer['membership_id'],
                    'commit_xid' => $commit->xid,
                    'commit_backend_pid' => (int) $commit->backend_pid,
                    'committed_at' => now('UTC')->toIso8601String(),
                ];
            } catch (Throwable $exception) {
                $primary = $exception;
                if ($connection->transactionLevel() > 0) {
                    $connection->rollBack();
                }
                throw $exception;
            } finally {
                try {
                    if (is_array($cleanup)) {
                        $this->tenantRevoker->revokeHash((string) ($cleanup['hash'] ?? ''), (string) ($cleanup['generation'] ?? ''));
                    }
                } catch (Throwable $exception) {
                    $cleanupFailure = $exception;
                } finally {
                    Auth::guard('tenant_staff')->logout();
                    $request->session()->flush();
                    $request->attributes->remove('tenant_staff_context');
                    $request->attributes->remove('tenant_staff_runtime_connection_id');
                    $request->attributes->remove('tenant_staff_authority_cleanup');
                }
                if ($cleanupFailure !== null) {
                    if ($primary !== null) {
                        throw new RestrictedTenantProbeCleanupException($primary::class, $cleanupFailure, $primary);
                    }
                    throw $cleanupFailure;
                }
            }
        });
    }

    private function request(string $name, string $requestId): Request
    {
        $request = Request::create('/', 'POST');
        $session = new Store($name, new ArraySessionHandler(900));
        $session->start();
        $request->setLaravelSession($session);
        $request->attributes->set('request_id', $requestId);
        return $request;
    }

    private function environmentScope(string $baseDomain): string
    {
        if (str_ends_with($baseDomain, '.localhost')) {
            if (! in_array(config('app.env'), ['local', 'testing'], true)
                || config('tenancy.allow_localhost_base_domain') !== true
                || config('tenancy.local_test_base_domain') !== $baseDomain) {
                throw new LogicException('The acceptance domain is not enabled for local testing.');
            }

            return 'LOCAL_TEST';
        }

        return 'NON_LOCAL';
    }
}
