<?php

use App\Modules\System\Http\Controllers\HealthController;
use App\Modules\Identity\Http\Controllers\AuthController;
use App\Modules\Identity\Http\Controllers\EmailVerificationController;
use App\Modules\Identity\Http\Controllers\PasswordController;
use App\Modules\Identity\Http\Middleware\RequireAllowedSpaOrigin;
use App\Modules\Identity\Http\Middleware\ValidateIdentitySession;
use App\Modules\Identity\Http\Middleware\ResolveTenantHost;
use App\Modules\Identity\Http\Middleware\RejectCompanyContextSelectors;
use App\Modules\Identity\Http\Middleware\TenantStaffRequestContext;
use App\Modules\Identity\Http\Middleware\ValidateTenantStaffSession;
use App\Modules\Identity\Http\Controllers\TenantStaffAuthController;
use App\Modules\Identity\Http\Controllers\FirstAdminActivationController;
use App\Modules\Identity\Http\Controllers\FirstAdminActivationAuthorityController;
use App\Modules\Identity\Http\Controllers\AuthRecoveryNotImplementedController;
use App\Modules\Tenancy\Http\Controllers\CompanyContextController;
use App\Modules\Tenancy\Http\Controllers\CompanyAuthorizationController;
use App\Modules\Tenancy\Http\Controllers\CompanyRolesController;
use App\Modules\Tenancy\Http\Controllers\TenantStaffCompanyRolesController;
use App\Modules\Tenancy\Http\Controllers\TenantStaffMemberController;
use App\Modules\Tenancy\Http\Controllers\TenantStaffRoleManagementController;
use App\Modules\Tenancy\Http\Controllers\LeadController;
use App\Modules\Tenancy\Http\Controllers\CustomerController;
use App\Modules\Tenancy\Http\Controllers\LeadConversionController;
use App\Modules\Tenancy\Http\Controllers\PipelineController;
use App\Modules\Tenancy\Http\Controllers\DealController;
use App\Modules\Tenancy\Http\Controllers\TaskController;
use App\Modules\Tenancy\Http\Controllers\SalesActivityController;
use App\Modules\Tenancy\Http\Middleware\ResolveCompanyContext;
use App\Modules\Provider\Http\Controllers\ProviderAuthController;
use App\Modules\Provider\Http\Controllers\ProviderApprovalController;
use App\Modules\Provider\Http\Controllers\ProviderControlController;
use App\Modules\Provider\Http\Controllers\ProviderDirectCompanyController;
use App\Modules\Provider\Http\Controllers\ProviderTeamController;
use App\Modules\Provider\Http\Controllers\ProviderPlanController;
use App\Modules\Provider\Http\Controllers\ProviderSubscriptionController;
use App\Modules\Provider\Http\Controllers\ProviderBootstrapController;
use App\Modules\Provider\Http\Middleware\ForceProviderBootstrapCsrf;
use App\Modules\Provider\Http\Middleware\RequireProviderBootstrapRequest;
use App\Modules\Provider\Http\Middleware\RequireProviderOrigin;
use App\Modules\Provider\Http\Middleware\ValidateProviderSecuritySettingsSession;
use App\Modules\Provider\Http\Middleware\ValidateProviderSession;
use Illuminate\Support\Facades\Route;

Route::prefix('v1')->name('api.v1.')->group(function (): void {
    Route::get('/', static fn () => response()->json([
        'data' => ['version' => 'v1', 'status' => 'available'],
        'meta' => ['request_id' => request()->attributes->get('request_id')],
    ]))->name('index');

    Route::get('/health', HealthController::class)->name('health');
    Route::get('/health/live', [HealthController::class, 'live'])->name('health.live');
    Route::get('/health/ready', [HealthController::class, 'ready'])->name('health.ready');

    Route::prefix('auth')->name('auth.')->middleware(ResolveTenantHost::class)->group(function (): void {
        Route::post('/first-admin/activate', FirstAdminActivationController::class)
            ->middleware([RequireAllowedSpaOrigin::class, 'throttle:api'])->name('first-admin.activate');
        Route::post('/first-admin/activate-authority', FirstAdminActivationAuthorityController::class)
            ->middleware([RequireAllowedSpaOrigin::class, 'throttle:api'])->name('first-admin.activate-authority');
        Route::post('/login', [TenantStaffAuthController::class, 'login'])
            ->middleware([RequireAllowedSpaOrigin::class, TenantStaffRequestContext::class])->name('login');
        Route::post('/forgot-password', AuthRecoveryNotImplementedController::class)
            ->middleware(RequireAllowedSpaOrigin::class)->name('password.email');
        Route::post('/reset-password', AuthRecoveryNotImplementedController::class)
            ->middleware(RequireAllowedSpaOrigin::class)->name('password.update');

        Route::middleware([
            RequireAllowedSpaOrigin::class,
            TenantStaffRequestContext::class,
            'auth:tenant_staff',
            ValidateTenantStaffSession::class,
        ])->group(function (): void {
            Route::post('/logout', [TenantStaffAuthController::class, 'logout'])->name('logout');
            Route::get('/me', [TenantStaffAuthController::class, 'me'])->name('me');
            Route::post('/email/verification-notification', AuthRecoveryNotImplementedController::class)
                ->name('verification.send');
        });
    });

    Route::prefix('company')->name('company.')
        ->middleware([
            ResolveTenantHost::class,
            RejectCompanyContextSelectors::class,
            RequireAllowedSpaOrigin::class,
            TenantStaffRequestContext::class,
            'auth:tenant_staff',
            ValidateTenantStaffSession::class,
        ])
        ->group(function (): void {
            Route::get('/context', CompanyContextController::class)
                ->name('context');
            Route::get('/authorization', CompanyAuthorizationController::class)
                ->name('authorization');
            Route::get('/roles', TenantStaffCompanyRolesController::class)->name('roles');
            Route::post('/roles', [TenantStaffRoleManagementController::class, 'store'])->name('roles.store');
            Route::patch('/roles/{role}', [TenantStaffRoleManagementController::class, 'updateGrants'])->name('roles.grants');
            Route::delete('/roles/{role}', [TenantStaffRoleManagementController::class, 'archive'])->name('roles.archive');
            Route::get('/staff', [TenantStaffMemberController::class, 'index'])->name('staff.index');
            Route::post('/staff', [TenantStaffMemberController::class, 'store'])->name('staff.store');
            Route::post('/staff/{membership}/disable', [TenantStaffMemberController::class, 'disable'])->name('staff.disable');
            Route::post('/staff/{membership}/reactivate', [TenantStaffMemberController::class, 'reactivate'])->name('staff.reactivate');
            Route::post('/staff/{membership}/roles', [TenantStaffRoleManagementController::class, 'assign'])->name('staff.roles.assign');
            Route::delete('/staff/{membership}/roles/{role}', [TenantStaffRoleManagementController::class, 'revoke'])->name('staff.roles.revoke');
            Route::post('/staff/{membership}/permissions', [TenantStaffRoleManagementController::class, 'grantPermission'])->name('staff.permissions.grant');
            Route::delete('/staff/{membership}/permissions/{permission}', [TenantStaffRoleManagementController::class, 'revokePermission'])->name('staff.permissions.revoke');
            Route::get('/leads', [LeadController::class, 'index'])->name('leads.index');
            Route::post('/leads', [LeadController::class, 'store'])->name('leads.store');
            Route::get('/leads/{lead}', [LeadController::class, 'show'])->name('leads.show');
            Route::patch('/leads/{lead}', [LeadController::class, 'update'])->name('leads.update');
            Route::patch('/leads/{lead}/stage', [LeadController::class, 'updateStage'])->name('leads.stage');
            Route::patch('/leads/{lead}/assign', [LeadController::class, 'assign'])->name('leads.assign');
            Route::delete('/leads/{lead}', [LeadController::class, 'archive'])->name('leads.archive');
            Route::post('/leads/{lead}/convert', LeadConversionController::class)->name('leads.convert');
            Route::get('/customers', [CustomerController::class, 'index'])->name('customers.index');
            Route::post('/customers', [CustomerController::class, 'store'])->name('customers.store');
            Route::get('/customers/{customer}', [CustomerController::class, 'show'])->name('customers.show');
            Route::patch('/customers/{customer}', [CustomerController::class, 'update'])->name('customers.update');
            Route::post('/customers/{customer}/contacts', [CustomerController::class, 'addContact'])->name('customers.contacts.store');
            Route::get('/customers/{customer}/contacts', [CustomerController::class, 'contacts'])->name('customers.contacts.index');
            Route::patch('/customers/{customer}/contacts/{contact}', [CustomerController::class, 'updateContact'])->name('customers.contacts.update');
            Route::get('/customers/{customer}/addresses', [CustomerController::class, 'addresses'])->name('customers.addresses.index');
            Route::post('/customers/{customer}/addresses', [CustomerController::class, 'addAddress'])->name('customers.addresses.store');
            Route::patch('/customers/{customer}/addresses/{address}', [CustomerController::class, 'updateAddress'])->name('customers.addresses.update');
            Route::get('/pipelines', [PipelineController::class, 'index'])->name('pipelines.index');
            Route::post('/pipelines', [PipelineController::class, 'store'])->name('pipelines.store');
            Route::get('/deals', [DealController::class, 'index'])->name('deals.index');
            Route::post('/deals', [DealController::class, 'store'])->name('deals.store');
            Route::get('/deals/{deal}', [DealController::class, 'show'])->name('deals.show');
            Route::patch('/deals/{deal}', [DealController::class, 'update'])->name('deals.update');
            Route::post('/deals/{deal}/transition', [DealController::class, 'transition'])->name('deals.transition');
            Route::get('/tasks', [TaskController::class, 'index'])->name('tasks.index');
            Route::post('/tasks', [TaskController::class, 'store'])->name('tasks.store');
            Route::patch('/tasks/{task}', [TaskController::class, 'update'])->name('tasks.update');
            Route::post('/tasks/{task}/complete', [TaskController::class, 'complete'])->name('tasks.complete');
            Route::get('/activities', [SalesActivityController::class, 'index'])->name('activities.index');
        });

    Route::prefix('super')->name('super.')->middleware(RequireProviderOrigin::class)
        ->group(function (): void {
            Route::prefix('setup')->name('setup.')
                ->middleware([ForceProviderBootstrapCsrf::class, RequireProviderBootstrapRequest::class, 'throttle:5,60'])
                ->group(function (): void {
                    Route::post('/status', [ProviderBootstrapController::class, 'status'])->name('status');
                    Route::post('/', [ProviderBootstrapController::class, 'store'])->name('store');
                });
            Route::prefix('auth')->name('auth.')->group(function (): void {
                Route::post('/login', [ProviderAuthController::class, 'login'])->name('login');
                Route::post('/mfa/enroll/start', [ProviderAuthController::class, 'enrollStart'])->name('mfa.enroll.start');
                Route::post('/mfa/enroll/confirm', [ProviderAuthController::class, 'enrollConfirm'])->name('mfa.enroll.confirm');
                Route::post('/mfa/verify', [ProviderAuthController::class, 'verify'])->name('mfa.verify');
                Route::post('/logout', [ProviderAuthController::class, 'logout'])->name('logout');
                Route::middleware(ValidateProviderSession::class)->group(function (): void {
                    Route::post('/step-up', [ProviderAuthController::class, 'stepUp'])->name('step-up');
                    Route::get('/me', [ProviderAuthController::class, 'me'])->name('me');
                    Route::get('/authorization', [ProviderAuthController::class, 'authorization'])->name('authorization');
                });
                Route::middleware(ValidateProviderSecuritySettingsSession::class)->group(function (): void {
                    Route::get('/mfa/settings', [ProviderAuthController::class, 'mfaStatus'])->name('mfa.settings.status');
                    Route::post('/mfa/settings/enroll/start', [ProviderAuthController::class, 'settingsEnrollStart'])->name('mfa.settings.enroll.start');
                    Route::post('/mfa/settings/enroll/confirm', [ProviderAuthController::class, 'settingsEnrollConfirm'])->name('mfa.settings.enroll.confirm');
                });
            });
            Route::get('/approvals', [ProviderApprovalController::class, 'index'])
                ->middleware(ValidateProviderSession::class)->name('approvals.index');
            Route::middleware([ValidateProviderSession::class, 'throttle:api'])->group(function (): void {
                Route::post('/companies', ProviderDirectCompanyController::class)->name('companies.store');
                Route::get('/provisioning-operations/{operation}/revisions', [ProviderControlController::class, 'revisions'])
                    ->name('provisioning.revisions');
                Route::post('/provisioning-operations', [ProviderControlController::class, 'provision'])
                    ->name('provisioning.request');
                Route::patch('/provisioning-operations/{operation}', [ProviderControlController::class, 'edit'])
                    ->name('provisioning.edit');
                Route::post('/provisioning-operations/{operation}/execute', [ProviderControlController::class, 'execute'])
                    ->name('provisioning.execute');
                Route::post('/recovery-operations', [ProviderControlController::class, 'recover'])->name('recovery.request');
                Route::post('/lifecycle-operations', [ProviderControlController::class, 'lifecycle'])
                    ->name('lifecycle.request');
                Route::post('/lifecycle-operations/{operation}/execute', [ProviderControlController::class, 'executeLifecycle'])
                    ->name('lifecycle.execute');
                Route::post('/approvals/{approval}/{decision}', [ProviderControlController::class, 'review'])
                    ->whereIn('decision', ['approve', 'reject', 'revoke'])->name('approvals.review');
                Route::post('/recovery-operations/{operation}/execute', [ProviderControlController::class, 'executeRecovery'])
                    ->name('recovery.execute');
                Route::get('/team', [ProviderTeamController::class, 'index'])->name('team.index');
                Route::post('/team', [ProviderTeamController::class, 'store'])->name('team.store');
                Route::post('/team/{provider}/capabilities', [ProviderTeamController::class, 'grant'])
                    ->name('team.capabilities.grant');
                Route::delete('/team/{provider}/capabilities/{capability}', [ProviderTeamController::class, 'revoke'])
                    ->name('team.capabilities.revoke');
                Route::patch('/team/{provider}/status', [ProviderTeamController::class, 'status'])
                    ->name('team.status');
                Route::get('/plans', [ProviderPlanController::class, 'index'])->name('plans.index');
                Route::post('/plans', [ProviderPlanController::class, 'store'])->name('plans.store');
                Route::patch('/plans/{plan}', [ProviderPlanController::class, 'update'])->name('plans.update');
                Route::put('/plans/{plan}/limits', [ProviderPlanController::class, 'setLimit'])->name('plans.limits.set');
                Route::get('/companies/{tenant}/subscription', [ProviderSubscriptionController::class, 'show'])
                    ->name('subscription.show');
                Route::post('/companies/{tenant}/subscription', [ProviderSubscriptionController::class, 'store'])
                    ->name('subscription.store');
                Route::delete('/companies/{tenant}/subscription', [ProviderSubscriptionController::class, 'destroy'])
                    ->name('subscription.destroy');
                Route::put('/companies/{tenant}/limit-overrides', [ProviderSubscriptionController::class, 'setLimitOverride'])
                    ->name('subscription.overrides.set');
                Route::delete('/companies/{tenant}/limit-overrides/{key}', [ProviderSubscriptionController::class, 'removeLimitOverride'])
                    ->name('subscription.overrides.remove');
            });
        });
});

Route::get('/v1/auth/email/verify/{id}/{hash}', AuthRecoveryNotImplementedController::class)
    ->middleware(ResolveTenantHost::class)
    ->name('verification.verify');
