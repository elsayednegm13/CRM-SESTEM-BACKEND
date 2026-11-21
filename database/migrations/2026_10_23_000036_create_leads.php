<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * Control: Leads (docs/PLAN.md Phase 2, first new tenant-owned business table).
 * Follows the "future tenant-owned migration contract" in docs/RLS_ARCHITECTURE.md: tenant_id
 * NOT NULL with FK to tenants, tenant-leading indexes, FORCE RLS with SELECT/INSERT/UPDATE/
 * DELETE policies tied to the transaction-local TENANT context. RLS here only proves tenant
 * isolation, same as every other tenant table; per-row ASSIGNED/SELF scoping (see
 * App\Modules\Tenancy\Application\TenantAuthorizationService::allowsObject(), the existing
 * pattern) is an application-layer concern, enforced by LeadService's own WHERE clauses --
 * documented in docs/RLS_ARCHITECTURE.md's limits section ("RLS does not replace ... object
 * policy").
 *
 * New scoped permissions: leads.view / leads.manage, the first use of ASSIGNED/SELF scope in
 * this codebase (the role and member permissions are presence-only). Added to the company_admin role template
 * at ALL_TENANT so every company provisioned after this migration has full lead access from
 * day one; existing already-instantiated roles are an immutable snapshot and are not
 * retroactively changed, same as every other template revision in this codebase.
 */
return new class extends Migration
{
    public function up(): void
    {
        $now = now('UTC');
        DB::table('permissions')->insert([
            ['key' => 'leads.view', 'scopeable' => true, 'allowed_scopes' => json_encode(['ALL_TENANT', 'ASSIGNED', 'SELF']),
                'delegable' => true, 'status' => 'ACTIVE', 'version' => 1, 'description' => 'View leads', 'created_at' => $now, 'updated_at' => $now],
            ['key' => 'leads.manage', 'scopeable' => true, 'allowed_scopes' => json_encode(['ALL_TENANT', 'ASSIGNED', 'SELF']),
                'delegable' => true, 'status' => 'ACTIVE', 'version' => 1, 'description' => 'Create and edit leads', 'created_at' => $now, 'updated_at' => $now],
        ]);

        $companyAdminTemplateId = DB::table('role_templates')->where('code', 'company_admin')->where('version', 1)->value('id');
        if (is_string($companyAdminTemplateId)) {
            foreach (['leads.view', 'leads.manage'] as $key) {
                DB::table('role_template_permissions')->insert([
                    'template_id' => $companyAdminTemplateId, 'permission_key' => $key, 'scope' => 'ALL_TENANT',
                ]);
            }
        }

        Schema::create('leads', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->uuid('tenant_id');
            $table->string('name', 160);
            $table->string('phone', 32)->nullable();
            $table->string('email', 254)->nullable();
            $table->string('city', 100)->nullable();
            $table->string('country', 100)->nullable();
            $table->string('source', 100)->nullable();
            $table->string('campaign', 160)->nullable();
            $table->string('pipeline_stage', 20)->default('new');
            $table->string('interest_level', 8)->nullable();
            $table->unsignedInteger('estimated_value_minor')->nullable();
            $table->string('status', 10)->default('ACTIVE');
            $table->uuid('assigned_membership_id')->nullable();
            $table->uuid('created_by_membership_id');
            $table->timestampTz('last_contacted_at')->nullable();
            $table->timestampsTz();

            $table->foreign('tenant_id')->references('id')->on('tenants')->restrictOnDelete();
            $table->foreign(['tenant_id', 'assigned_membership_id'], 'leads_assigned_membership_fk')
                ->references(['tenant_id', 'id'])->on('tenant_staff_memberships')->restrictOnDelete();
            $table->foreign(['tenant_id', 'created_by_membership_id'], 'leads_created_by_membership_fk')
                ->references(['tenant_id', 'id'])->on('tenant_staff_memberships')->restrictOnDelete();
            $table->index(['tenant_id', 'pipeline_stage'], 'leads_tenant_stage_idx');
            $table->index(['tenant_id', 'assigned_membership_id'], 'leads_tenant_assigned_idx');
            $table->index(['tenant_id', 'status'], 'leads_tenant_status_idx');
        });

        DB::statement("ALTER TABLE leads ADD CONSTRAINT leads_name_check CHECK (length(btrim(name)) BETWEEN 1 AND 160)");
        DB::statement("ALTER TABLE leads ADD CONSTRAINT leads_email_check CHECK (email IS NULL OR email ~ '^[^[:space:]@]+@[^[:space:]@]+\\.[^[:space:]@]+$')");
        DB::statement("ALTER TABLE leads ADD CONSTRAINT leads_stage_check CHECK (pipeline_stage IN ('new','contacted','interested','followup','quotation','negotiation','won','lost'))");
        DB::statement("ALTER TABLE leads ADD CONSTRAINT leads_interest_check CHECK (interest_level IS NULL OR interest_level IN ('HOT','WARM','COLD'))");
        DB::statement("ALTER TABLE leads ADD CONSTRAINT leads_status_check CHECK (status IN ('ACTIVE','ARCHIVED'))");

        DB::statement('ALTER TABLE leads ENABLE ROW LEVEL SECURITY');
        DB::statement('ALTER TABLE leads FORCE ROW LEVEL SECURITY');
        DB::statement("CREATE POLICY leads_tenant_select ON leads FOR SELECT USING (app_rls_context_mode() = 'TENANT' AND tenant_id = app_rls_current_tenant_id())");
        DB::statement("CREATE POLICY leads_tenant_insert ON leads FOR INSERT WITH CHECK (app_rls_context_mode() = 'TENANT' AND tenant_id = app_rls_current_tenant_id())");
        DB::statement("CREATE POLICY leads_tenant_update ON leads FOR UPDATE USING (app_rls_context_mode() = 'TENANT' AND tenant_id = app_rls_current_tenant_id()) WITH CHECK (app_rls_context_mode() = 'TENANT' AND tenant_id = app_rls_current_tenant_id())");
        DB::statement("CREATE POLICY leads_tenant_delete ON leads FOR DELETE USING (app_rls_context_mode() = 'TENANT' AND tenant_id = app_rls_current_tenant_id())");
        DB::statement('REVOKE ALL ON TABLE leads FROM PUBLIC');
    }

    public function down(): void
    {
        throw new RuntimeException('Forward-only migration; see docs/DECISIONS.md.');
    }
};
