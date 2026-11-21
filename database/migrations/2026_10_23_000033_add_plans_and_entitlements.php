<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;

/**
 * Control: plans & entitlements (docs/PLAN.md Phase 1, D-6).
 * `plans`/`plan_limits` are global reference data (like `permissions`/`role_templates`) and
 * carry no RLS, by the same rule docs/RLS_ARCHITECTURE.md states for global tables.
 * `tenant_subscriptions`/`tenant_limit_overrides` carry `tenant_id` and get the full RLS
 * treatment the "future tenant-owned migration contract" in that doc requires: tenant staff can
 * read their own tenant's row (for a future Subscription-view page); only a capability-holding
 * Provider can write, via a new lightweight 'PROVIDER' + target-tenant mode -- this is a direct
 * admin action with no dual-control requirement (D-6), so it does not go through the heavier
 * provider_control_operations/approval pipeline that company.provision/recover/lifecycle use.
 * Feature flags are not a separate table: a plan_limits row with limit_value 0 or 1 is a flag.
 */
return new class extends Migration
{
    public function up(): void
    {
        DB::table('provider_capabilities')->insertOrIgnore([
            'key' => 'plans.manage',
            'description' => 'Create and edit the global plan catalog and its limits',
            'status' => 'ACTIVE',
            'version' => 1,
        ]);
        DB::table('provider_capabilities')->insertOrIgnore([
            'key' => 'company.subscription.manage',
            'description' => "Assign a company's plan and set per-company limit overrides",
            'status' => 'ACTIVE',
            'version' => 1,
        ]);

        Schema::create('plans', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->string('code', 40)->unique();
            $table->string('display_name', 120);
            $table->unsignedInteger('price_monthly_minor');
            $table->unsignedInteger('price_annual_minor');
            $table->string('currency', 3)->default('EGP');
            $table->string('status', 8)->default('ACTIVE');
            $table->unsignedInteger('sort_order')->default(0);
            $table->timestampsTz();
        });
        DB::statement("ALTER TABLE plans ADD CONSTRAINT plans_code_check CHECK (code ~ '^[a-z][a-z0-9_]{0,38}[a-z0-9]$')");
        DB::statement("ALTER TABLE plans ADD CONSTRAINT plans_status_check CHECK (status IN ('ACTIVE','RETIRED'))");
        DB::statement('ALTER TABLE plans ADD CONSTRAINT plans_price_check CHECK (price_monthly_minor > 0 AND price_annual_minor > 0)');

        Schema::create('plan_limits', function (Blueprint $table): void {
            $table->uuid('plan_id');
            $table->string('limit_key', 64);
            $table->integer('limit_value')->nullable();
            $table->timestampsTz();
            $table->primary(['plan_id', 'limit_key']);
            $table->foreign('plan_id')->references('id')->on('plans')->cascadeOnDelete();
        });
        DB::statement("ALTER TABLE plan_limits ADD CONSTRAINT plan_limits_key_check CHECK (limit_key ~ '^[a-z][a-z0-9_]{0,62}[a-z0-9]$')");
        DB::statement('ALTER TABLE plan_limits ADD CONSTRAINT plan_limits_value_check CHECK (limit_value IS NULL OR limit_value >= 0)');

        Schema::create('tenant_subscriptions', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->uuid('tenant_id');
            $table->uuid('plan_id');
            $table->string('billing_cycle', 8);
            $table->string('status', 10)->default('ACTIVE');
            $table->timestampTz('started_at');
            $table->timestampTz('current_period_ends_at')->nullable();
            $table->timestampTz('cancelled_at')->nullable();
            $table->uuid('created_by_provider_user_id');
            $table->timestampsTz();
            $table->foreign('tenant_id')->references('id')->on('tenants')->restrictOnDelete();
            $table->foreign('plan_id')->references('id')->on('plans')->restrictOnDelete();
            $table->foreign('created_by_provider_user_id')->references('id')->on('provider_users')->restrictOnDelete();
            $table->index(['tenant_id', 'status']);
        });
        DB::statement("ALTER TABLE tenant_subscriptions ADD CONSTRAINT tenant_subscriptions_billing_cycle_check CHECK (billing_cycle IN ('MONTHLY','ANNUAL'))");
        DB::statement("ALTER TABLE tenant_subscriptions ADD CONSTRAINT tenant_subscriptions_status_check CHECK (status IN ('ACTIVE','CANCELLED','EXPIRED'))");
        DB::statement('ALTER TABLE tenant_subscriptions ADD CONSTRAINT tenant_subscriptions_cancelled_check CHECK ((status = ' .
            "'CANCELLED' AND cancelled_at IS NOT NULL) OR (status <> 'CANCELLED' AND cancelled_at IS NULL))");
        DB::statement("CREATE UNIQUE INDEX tenant_subscriptions_one_active_per_tenant ON tenant_subscriptions (tenant_id) WHERE status = 'ACTIVE'");

        Schema::create('tenant_limit_overrides', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->uuid('tenant_id');
            $table->string('limit_key', 64);
            $table->integer('limit_value')->nullable();
            $table->string('reason', 500);
            $table->uuid('created_by_provider_user_id');
            $table->timestampsTz();
            $table->foreign('tenant_id')->references('id')->on('tenants')->restrictOnDelete();
            $table->foreign('created_by_provider_user_id')->references('id')->on('provider_users')->restrictOnDelete();
            $table->unique(['tenant_id', 'limit_key']);
        });
        DB::statement("ALTER TABLE tenant_limit_overrides ADD CONSTRAINT tenant_limit_overrides_key_check CHECK (limit_key ~ '^[a-z][a-z0-9_]{0,62}[a-z0-9]$')");
        DB::statement('ALTER TABLE tenant_limit_overrides ADD CONSTRAINT tenant_limit_overrides_value_check CHECK (limit_value IS NULL OR limit_value >= 0)');
        DB::statement("ALTER TABLE tenant_limit_overrides ADD CONSTRAINT tenant_limit_overrides_reason_check CHECK (length(btrim(reason)) BETWEEN 1 AND 500)");

        foreach (['tenant_subscriptions', 'tenant_limit_overrides'] as $table) {
            DB::statement("ALTER TABLE {$table} ENABLE ROW LEVEL SECURITY");
            DB::statement("ALTER TABLE {$table} FORCE ROW LEVEL SECURITY");
        }

        // A lightweight, non-dual-control admin mode: 'PROVIDER' context (same mode MFA/team
        // management already use) plus a target tenant carried on the already-reset app.tenant_id
        // GUC (see ProviderDatabaseContext::run()'s new optional $targetTenantId). No step-up or
        // auth_version check at the SQL layer here, matching every other 'PROVIDER'-mode table;
        // the PHP service's assertStepUp()/assertCapability() calls are the authority, same as
        // ProviderTeamService.
        DB::statement(<<<'SQL'
            CREATE OR REPLACE FUNCTION app_provider_admin_tenant_allowed(candidate_tenant_id uuid, required_capability text) RETURNS boolean
            LANGUAGE sql STABLE SECURITY INVOKER
            AS $$
                SELECT current_setting('app.context_mode', true) = 'PROVIDER'
                  AND candidate_tenant_id = app_rls_current_tenant_id()
                  AND EXISTS (
                    SELECT 1 FROM provider_users p
                    JOIN provider_user_capabilities a ON a.provider_user_id = p.id
                    JOIN provider_capabilities c ON c.key = a.capability_key
                    WHERE p.id = app_provider_control_setting_uuid('app.provider_user_id')
                      AND p.status = 'ACTIVE' AND p.email_verified_at IS NOT NULL AND p.mfa_enrolled_at IS NOT NULL
                      AND a.capability_key = required_capability AND c.status = 'ACTIVE'
                      AND (a.expires_at IS NULL OR a.expires_at > transaction_timestamp())
                  )
            $$
        SQL);

        DB::statement(<<<'SQL'
            CREATE POLICY tenant_subscriptions_tenant_select ON tenant_subscriptions FOR SELECT
            USING (app_rls_context_mode() = 'TENANT' AND tenant_id = app_rls_current_tenant_id())
        SQL);
        DB::statement(<<<'SQL'
            CREATE POLICY tenant_subscriptions_provider_select ON tenant_subscriptions FOR SELECT
            USING (app_provider_admin_tenant_allowed(tenant_id, 'company.subscription.manage'))
        SQL);
        DB::statement(<<<'SQL'
            CREATE POLICY tenant_subscriptions_provider_insert ON tenant_subscriptions FOR INSERT
            WITH CHECK (app_provider_admin_tenant_allowed(tenant_id, 'company.subscription.manage'))
        SQL);
        DB::statement(<<<'SQL'
            CREATE POLICY tenant_subscriptions_provider_update ON tenant_subscriptions FOR UPDATE
            USING (app_provider_admin_tenant_allowed(tenant_id, 'company.subscription.manage'))
            WITH CHECK (app_provider_admin_tenant_allowed(tenant_id, 'company.subscription.manage'))
        SQL);

        DB::statement(<<<'SQL'
            CREATE POLICY tenant_limit_overrides_tenant_select ON tenant_limit_overrides FOR SELECT
            USING (app_rls_context_mode() = 'TENANT' AND tenant_id = app_rls_current_tenant_id())
        SQL);
        DB::statement(<<<'SQL'
            CREATE POLICY tenant_limit_overrides_provider_select ON tenant_limit_overrides FOR SELECT
            USING (app_provider_admin_tenant_allowed(tenant_id, 'company.subscription.manage'))
        SQL);
        DB::statement(<<<'SQL'
            CREATE POLICY tenant_limit_overrides_provider_insert ON tenant_limit_overrides FOR INSERT
            WITH CHECK (app_provider_admin_tenant_allowed(tenant_id, 'company.subscription.manage'))
        SQL);
        DB::statement(<<<'SQL'
            CREATE POLICY tenant_limit_overrides_provider_update ON tenant_limit_overrides FOR UPDATE
            USING (app_provider_admin_tenant_allowed(tenant_id, 'company.subscription.manage'))
            WITH CHECK (app_provider_admin_tenant_allowed(tenant_id, 'company.subscription.manage'))
        SQL);
        DB::statement(<<<'SQL'
            CREATE POLICY tenant_limit_overrides_provider_delete ON tenant_limit_overrides FOR DELETE
            USING (app_provider_admin_tenant_allowed(tenant_id, 'company.subscription.manage'))
        SQL);

        // Seed the 3 placeholder plans from the marketing site (daleel-crm's pricing page),
        // prices as minor units (piastres) -- see docs/DECISIONS.md D-6. Annual price already
        // matches the marketing site's discounted annual-equivalent monthly figure x 12.
        $plans = [
            ['code' => 'basic', 'display_name' => 'الأساسية', 'price_monthly_minor' => 29900, 'price_annual_minor' => 239 * 12 * 100,
                'sort_order' => 1, 'limits' => ['max_users' => 5, 'max_leads_per_month' => 1000]],
            ['code' => 'pro', 'display_name' => 'الاحترافية', 'price_monthly_minor' => 59900, 'price_annual_minor' => 479 * 12 * 100,
                'sort_order' => 2, 'limits' => ['max_users' => 15, 'max_leads_per_month' => 10000]],
            ['code' => 'enterprise', 'display_name' => 'المؤسسية', 'price_monthly_minor' => 119900, 'price_annual_minor' => 959 * 12 * 100,
                'sort_order' => 3, 'limits' => ['max_users' => null, 'max_leads_per_month' => null]],
        ];
        $now = now('UTC');
        foreach ($plans as $plan) {
            $planId = (string) Str::uuid7();
            DB::table('plans')->insert([
                'id' => $planId, 'code' => $plan['code'], 'display_name' => $plan['display_name'],
                'price_monthly_minor' => $plan['price_monthly_minor'], 'price_annual_minor' => $plan['price_annual_minor'],
                'currency' => 'EGP', 'status' => 'ACTIVE', 'sort_order' => $plan['sort_order'],
                'created_at' => $now, 'updated_at' => $now,
            ]);
            foreach ($plan['limits'] as $key => $value) {
                DB::table('plan_limits')->insert([
                    'plan_id' => $planId, 'limit_key' => $key, 'limit_value' => $value,
                    'created_at' => $now, 'updated_at' => $now,
                ]);
            }
        }
    }

    public function down(): void
    {
        throw new RuntimeException('Forward-only migration; see docs/DECISIONS.md.');
    }
};
