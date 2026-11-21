<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * W2 source candidate only until separately authorized on an owned PostgreSQL environment.
 * It follows the exact tenant-leading, FORCE RLS and column-grant pattern of migrations 036/037.
 */
return new class extends Migration
{
    public function up(): void
    {
        $now = now('UTC');
        DB::table('permissions')->insert([
            ['key' => 'customers.view', 'scopeable' => false, 'allowed_scopes' => json_encode([]), 'delegable' => true, 'status' => 'ACTIVE', 'version' => 1, 'description' => 'View customers and contacts', 'created_at' => $now, 'updated_at' => $now],
            ['key' => 'customers.manage', 'scopeable' => false, 'allowed_scopes' => json_encode([]), 'delegable' => true, 'status' => 'ACTIVE', 'version' => 1, 'description' => 'Create and change customers and contacts', 'created_at' => $now, 'updated_at' => $now],
            ['key' => 'leads.convert', 'scopeable' => false, 'allowed_scopes' => json_encode([]), 'delegable' => true, 'status' => 'ACTIVE', 'version' => 1, 'description' => 'Convert a lead to a customer', 'created_at' => $now, 'updated_at' => $now],
        ]);
        $templateId = DB::table('role_templates')->where('code', 'company_admin')->where('version', 1)->value('id');
        if (is_string($templateId)) foreach (['customers.view', 'customers.manage', 'leads.convert'] as $permission) DB::table('role_template_permissions')->insert(['template_id' => $templateId, 'permission_key' => $permission, 'scope' => null]);
        // Composite references below make cross-tenant joins impossible at the database boundary.
        DB::statement('ALTER TABLE leads ADD CONSTRAINT leads_tenant_id_unique UNIQUE (tenant_id, id)');

        Schema::create('customers', function (Blueprint $table): void {
            $table->uuid('id')->primary(); $table->uuid('tenant_id'); $table->string('type', 16); $table->string('display_name', 160); $table->string('legal_name', 200)->nullable(); $table->string('email', 254)->nullable(); $table->string('phone', 32)->nullable(); $table->char('country_code', 2)->nullable(); $table->string('status', 12)->default('ACTIVE'); $table->uuid('source_lead_id')->nullable(); $table->uuid('created_by_membership_id'); $table->timestampsTz();
            $table->foreign('tenant_id')->references('id')->on('tenants')->restrictOnDelete();
            $table->foreign(['tenant_id', 'source_lead_id'], 'customers_source_lead_fk')->references(['tenant_id', 'id'])->on('leads')->restrictOnDelete();
            $table->foreign(['tenant_id', 'created_by_membership_id'], 'customers_created_by_fk')->references(['tenant_id', 'id'])->on('tenant_staff_memberships')->restrictOnDelete();
            $table->unique(['tenant_id', 'id'], 'customers_tenant_id_unique'); $table->unique(['tenant_id', 'source_lead_id'], 'customers_tenant_source_lead_unique'); $table->index(['tenant_id', 'status', 'created_at'], 'customers_tenant_status_created_idx'); $table->index(['tenant_id', 'email'], 'customers_tenant_email_idx'); $table->index(['tenant_id', 'phone'], 'customers_tenant_phone_idx');
        });
        Schema::create('customer_contacts', function (Blueprint $table): void {
            $table->uuid('id')->primary(); $table->uuid('tenant_id'); $table->uuid('customer_id'); $table->string('display_name', 160); $table->string('email', 254)->nullable(); $table->string('phone', 32)->nullable(); $table->string('job_title', 120)->nullable(); $table->string('note', 1000)->nullable(); $table->boolean('is_primary')->default(false); $table->timestampsTz();
            $table->foreign('tenant_id')->references('id')->on('tenants')->restrictOnDelete(); $table->foreign(['tenant_id', 'customer_id'], 'contacts_customer_tenant_fk')->references(['tenant_id', 'id'])->on('customers')->restrictOnDelete(); $table->unique(['tenant_id', 'id'], 'contacts_tenant_id_unique'); $table->index(['tenant_id', 'customer_id'], 'contacts_tenant_customer_idx');
        });
        Schema::create('customer_addresses', function (Blueprint $table): void {
            $table->uuid('id')->primary(); $table->uuid('tenant_id'); $table->uuid('customer_id'); $table->string('kind', 16)->default('GENERAL'); $table->string('line1', 200); $table->string('line2', 200)->nullable(); $table->string('city', 100)->nullable(); $table->string('region', 100)->nullable(); $table->string('postal_code', 32)->nullable(); $table->char('country_code', 2)->nullable(); $table->timestampsTz();
            $table->foreign('tenant_id')->references('id')->on('tenants')->restrictOnDelete(); $table->foreign(['tenant_id', 'customer_id'], 'addresses_customer_tenant_fk')->references(['tenant_id', 'id'])->on('customers')->restrictOnDelete(); $table->index(['tenant_id', 'customer_id'], 'addresses_tenant_customer_idx');
        });
        Schema::create('lead_conversions', function (Blueprint $table): void {
            $table->uuid('id')->primary(); $table->uuid('tenant_id'); $table->uuid('lead_id'); $table->uuid('customer_id'); $table->uuid('contact_id')->nullable(); $table->char('payload_hash', 64); $table->uuid('converted_by_membership_id'); $table->timestampTz('converted_at');
            $table->foreign('tenant_id')->references('id')->on('tenants')->restrictOnDelete(); $table->foreign(['tenant_id', 'lead_id'], 'conversions_lead_tenant_fk')->references(['tenant_id', 'id'])->on('leads')->restrictOnDelete(); $table->foreign(['tenant_id', 'customer_id'], 'conversions_customer_tenant_fk')->references(['tenant_id', 'id'])->on('customers')->restrictOnDelete(); $table->foreign(['tenant_id', 'contact_id'], 'conversions_contact_tenant_fk')->references(['tenant_id', 'id'])->on('customer_contacts')->restrictOnDelete(); $table->foreign(['tenant_id', 'converted_by_membership_id'], 'conversions_actor_tenant_fk')->references(['tenant_id', 'id'])->on('tenant_staff_memberships')->restrictOnDelete(); $table->unique(['tenant_id', 'lead_id'], 'conversions_tenant_lead_unique'); $table->unique(['tenant_id', 'id'], 'conversions_tenant_id_unique');
        });

        DB::statement("ALTER TABLE customers ADD CONSTRAINT customers_type_check CHECK (type IN ('PERSON','ORGANIZATION'))"); DB::statement("ALTER TABLE customers ADD CONSTRAINT customers_status_check CHECK (status IN ('ACTIVE','INACTIVE'))"); DB::statement("ALTER TABLE customers ADD CONSTRAINT customers_country_check CHECK (country_code IS NULL OR country_code ~ '^[A-Z]{2}$')"); DB::statement("ALTER TABLE customer_addresses ADD CONSTRAINT addresses_kind_check CHECK (kind IN ('GENERAL','BILLING','SHIPPING'))"); DB::statement("CREATE UNIQUE INDEX contacts_one_primary_per_customer ON customer_contacts (tenant_id, customer_id) WHERE is_primary"); DB::statement("CREATE UNIQUE INDEX customers_tenant_email_unique ON customers (tenant_id, email) WHERE email IS NOT NULL"); DB::statement("CREATE UNIQUE INDEX customers_tenant_phone_unique ON customers (tenant_id, phone) WHERE phone IS NOT NULL");
        foreach (['customers', 'customer_contacts', 'customer_addresses', 'lead_conversions'] as $table) { DB::statement("ALTER TABLE {$table} ENABLE ROW LEVEL SECURITY"); DB::statement("ALTER TABLE {$table} FORCE ROW LEVEL SECURITY"); DB::statement("CREATE POLICY {$table}_tenant_select ON {$table} FOR SELECT USING (app_rls_context_mode() = 'TENANT' AND tenant_id = app_rls_current_tenant_id())"); DB::statement("CREATE POLICY {$table}_tenant_insert ON {$table} FOR INSERT WITH CHECK (app_rls_context_mode() = 'TENANT' AND tenant_id = app_rls_current_tenant_id())"); DB::statement("CREATE POLICY {$table}_tenant_update ON {$table} FOR UPDATE USING (app_rls_context_mode() = 'TENANT' AND tenant_id = app_rls_current_tenant_id()) WITH CHECK (app_rls_context_mode() = 'TENANT' AND tenant_id = app_rls_current_tenant_id())"); DB::statement("CREATE POLICY {$table}_tenant_delete ON {$table} FOR DELETE USING (app_rls_context_mode() = 'TENANT' AND tenant_id = app_rls_current_tenant_id())"); DB::statement("REVOKE ALL ON TABLE {$table} FROM PUBLIC"); }
        foreach ([
            'GRANT SELECT (id, tenant_id, type, display_name, legal_name, email, phone, country_code, status, source_lead_id, created_by_membership_id, created_at, updated_at) ON public.customers TO daleel_tenant_runtime',
            'GRANT INSERT (id, tenant_id, type, display_name, legal_name, email, phone, country_code, status, source_lead_id, created_by_membership_id, created_at, updated_at) ON public.customers TO daleel_tenant_runtime',
            'GRANT UPDATE (type, display_name, legal_name, email, phone, country_code, status, updated_at) ON public.customers TO daleel_tenant_runtime',
            'GRANT SELECT (id, tenant_id, customer_id, display_name, email, phone, job_title, note, is_primary, created_at, updated_at) ON public.customer_contacts TO daleel_tenant_runtime',
            'GRANT INSERT (id, tenant_id, customer_id, display_name, email, phone, job_title, note, is_primary, created_at, updated_at) ON public.customer_contacts TO daleel_tenant_runtime',
            'GRANT UPDATE (is_primary, updated_at) ON public.customer_contacts TO daleel_tenant_runtime',
            'GRANT SELECT ON public.customer_addresses TO daleel_tenant_runtime',
            'GRANT SELECT (id, tenant_id, lead_id, customer_id, contact_id, payload_hash, converted_by_membership_id, converted_at) ON public.lead_conversions TO daleel_tenant_runtime',
            'GRANT INSERT (id, tenant_id, lead_id, customer_id, contact_id, payload_hash, converted_by_membership_id, converted_at) ON public.lead_conversions TO daleel_tenant_runtime',
        ] as $grant) DB::statement($grant);
    }

    public function down(): void { throw new LogicException('Forward-only W2 migration candidate.'); }
};
