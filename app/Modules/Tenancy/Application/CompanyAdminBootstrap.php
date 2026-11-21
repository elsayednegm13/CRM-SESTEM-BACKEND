<?php

namespace App\Modules\Tenancy\Application;

use App\Modules\Identity\Infrastructure\Persistence\User;
use App\Modules\Tenancy\Domain\AuthorizationDeniedException;
use App\Modules\Tenancy\Domain\TenantContext;
use App\Modules\Tenancy\Infrastructure\Persistence\Role;
use App\Modules\Tenancy\Infrastructure\Persistence\Tenant;
use App\Modules\Tenancy\Infrastructure\Persistence\TenantMembership;
use App\Modules\Shared\Audit\SecurityAuditWriter;
use Illuminate\Support\Facades\DB;

/** Restricted disposable proof bootstrap. No HTTP route or production customer onboarding. */
final class CompanyAdminBootstrap
{
    public function __construct(
        private readonly AuthorizationSecurityEvents $events,
        private readonly SecurityAuditWriter $audit,
    )
    {
    }

    public function create(User $founder, array $tenantAttributes, string $requestId): TenantContext
    {
        if (! app()->environment(['local', 'testing']) || ! config('tenancy.disposable_bootstrap_enabled')) {
            throw new AuthorizationDeniedException;
        }

        $context = DB::transaction(function () use ($founder, $tenantAttributes, $requestId): TenantContext {
            $user = DB::table('users')->where('id', $founder->id)->lockForUpdate()->first(['id', 'status', 'auth_version']);
            if (! $user || $user->status !== 'ACTIVE') {
                throw new AuthorizationDeniedException;
            }
            $template = DB::table('role_templates')->where('code', 'company_admin')
                ->where('version', 1)->where('status', 'ACTIVE')->first(['id']);
            if (! $template) {
                throw new AuthorizationDeniedException;
            }
            $templateGrants = DB::table('role_template_permissions')->where('template_id', $template->id)->get(['permission_key', 'scope']);
            // Exact-match fail-closed check against unexpected template drift. Updated for
            // migration 2026_10_23_000036 (leads.view/leads.manage added to this template).
            $keys = $templateGrants->pluck('permission_key')->sort()->values()->all();
            if ($keys !== ['company.administer', 'leads.manage', 'leads.view', 'member.manage', 'member.view', 'role.manage', 'role.view']
                || ! $templateGrants->contains(fn ($grant) => $grant->permission_key === 'company.administer' && $grant->scope === 'ALL_TENANT')) {
                throw new AuthorizationDeniedException;
            }

            $tenant = Tenant::query()->create($tenantAttributes);
            $membership = TenantMembership::query()->create([
                'tenant_id' => $tenant->id, 'user_id' => $user->id, 'joined_at' => now(),
            ]);
            $membership->forceFill(['status' => 'ACTIVE'])->save();
            $membership->refresh();
            $role = Role::query()->create([
                'tenant_id' => $tenant->id, 'display_name' => 'Company Admin',
                'normalized_name' => 'company_admin', 'source_template_id' => $template->id,
            ]);
            foreach ($templateGrants as $grant) {
                DB::table('role_permissions')->insert([
                    'tenant_id' => $tenant->id, 'role_id' => $role->id,
                    'permission_key' => $grant->permission_key, 'scope' => $grant->scope,
                ]);
            }
            DB::table('membership_roles')->insert([
                'tenant_id' => $tenant->id, 'membership_id' => $membership->id,
                'role_id' => $role->id, 'assigned_by_user_id' => null, 'assigned_at' => now(),
            ]);
            $tenant->forceFill(['status' => 'ACTIVE'])->save();

            $context = new TenantContext($user->id, $tenant->id, $membership->id,
                (int) $membership->authorization_version, (int) $user->auth_version, $requestId);
            $this->audit->appendDisposableBootstrap($context);
            DB::afterCommit(fn () => $this->events->emit('CompanyAdminBootstrapped', 'allowed', $context, $context->tenantId));
            return $context;
        });
        return $context;
    }
}
