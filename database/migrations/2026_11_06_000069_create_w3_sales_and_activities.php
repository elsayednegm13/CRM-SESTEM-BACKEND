<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * W3 source-only schema candidate.  It is deliberately forward-only and has
 * not been executed by this change set.
 */
return new class extends Migration {
    public function up(): void
    {
        $now = now('UTC');
        foreach (['deals.view', 'deals.manage', 'pipelines.manage', 'tasks.view', 'tasks.manage', 'activities.view'] as $permission) {
            DB::table('permissions')->insertOrIgnore([
                'key' => $permission,
                'scopeable' => false,
                'allowed_scopes' => json_encode([]),
                'delegable' => true,
                'status' => 'ACTIVE',
                'version' => 1,
                'description' => 'Manage V1 sales workspace: '.$permission,
                'created_at' => $now,
                'updated_at' => $now,
            ]);
        }
        $templateId = DB::table('role_templates')->where('code', 'company_admin')->where('version', 1)->value('id');
        if (is_string($templateId)) {
            foreach (['deals.view', 'deals.manage', 'pipelines.manage', 'tasks.view', 'tasks.manage', 'activities.view'] as $permission) {
                DB::table('role_template_permissions')->insertOrIgnore([
                    'template_id' => $templateId,
                    'permission_key' => $permission,
                    'scope' => null,
                ]);
            }
        }
        Schema::create('sales_pipelines', function (Blueprint $table): void {
            $table->uuid('id')->primary(); $table->uuid('tenant_id'); $table->string('name', 120); $table->boolean('is_default')->default(false);
            $table->uuid('created_by_membership_id')->nullable(); $table->timestampsTz();
            $table->unique(['tenant_id', 'id']); $table->unique(['tenant_id', 'name']);
            $table->foreign(['tenant_id', 'created_by_membership_id'])->references(['tenant_id', 'id'])->on('tenant_staff_memberships')->restrictOnDelete();
        });
        Schema::create('sales_pipeline_stages', function (Blueprint $table): void {
            $table->uuid('id')->primary(); $table->uuid('tenant_id'); $table->uuid('pipeline_id'); $table->string('name', 120); $table->unsignedSmallInteger('sort_order');
            $table->string('kind', 12)->default('OPEN'); $table->boolean('is_active')->default(true); $table->timestampsTz();
            $table->unique(['tenant_id', 'id']); $table->unique(['tenant_id', 'pipeline_id', 'id']); $table->unique(['tenant_id', 'pipeline_id', 'sort_order']);
            $table->foreign(['tenant_id', 'pipeline_id'])->references(['tenant_id', 'id'])->on('sales_pipelines')->restrictOnDelete();
        });
        Schema::create('deals', function (Blueprint $table): void {
            $table->uuid('id')->primary(); $table->uuid('tenant_id'); $table->uuid('customer_id'); $table->uuid('contact_id')->nullable(); $table->uuid('pipeline_id'); $table->uuid('stage_id');
            $table->string('title', 160); $table->decimal('value_amount', 20, 4)->default(0); $table->char('currency_code', 3); $table->uuid('owner_membership_id')->nullable();
            $table->string('status', 12)->default('OPEN'); $table->text('lost_reason')->nullable(); $table->timestampTz('closed_at')->nullable(); $table->unsignedInteger('version')->default(1); $table->timestampsTz();
            $table->unique(['tenant_id', 'id']);
            $table->foreign(['tenant_id', 'customer_id'])->references(['tenant_id', 'id'])->on('customers')->restrictOnDelete();
            $table->foreign(['tenant_id', 'customer_id', 'contact_id'])->references(['tenant_id', 'customer_id', 'id'])->on('customer_contacts')->restrictOnDelete();
            $table->foreign(['tenant_id', 'pipeline_id', 'stage_id'])->references(['tenant_id', 'pipeline_id', 'id'])->on('sales_pipeline_stages')->restrictOnDelete();
            $table->foreign(['tenant_id', 'owner_membership_id'])->references(['tenant_id', 'id'])->on('tenant_staff_memberships')->restrictOnDelete();
            $table->index(['tenant_id', 'status', 'stage_id']);
        });
        Schema::create('deal_stage_transitions', function (Blueprint $table): void {
            $table->uuid('id')->primary(); $table->uuid('tenant_id'); $table->uuid('deal_id'); $table->uuid('from_stage_id'); $table->uuid('to_stage_id'); $table->unsignedInteger('version'); $table->uuid('changed_by_membership_id'); $table->timestampTz('created_at');
            $table->foreign(['tenant_id', 'deal_id'])->references(['tenant_id', 'id'])->on('deals')->restrictOnDelete(); $table->index(['tenant_id', 'deal_id']);
        });
        Schema::create('sales_tasks', function (Blueprint $table): void {
            $table->uuid('id')->primary(); $table->uuid('tenant_id'); $table->uuid('customer_id')->nullable(); $table->uuid('deal_id')->nullable(); $table->string('title', 160); $table->text('description')->nullable();
            $table->uuid('assignee_membership_id')->nullable(); $table->timestampTz('due_at')->nullable(); $table->string('status', 16)->default('TODO'); $table->string('priority', 12)->default('NORMAL'); $table->timestampTz('completed_at')->nullable(); $table->uuid('created_by_membership_id'); $table->timestampsTz();
            $table->unique(['tenant_id', 'id']);
            $table->foreign(['tenant_id', 'customer_id'])->references(['tenant_id', 'id'])->on('customers')->restrictOnDelete(); $table->foreign(['tenant_id', 'deal_id'])->references(['tenant_id', 'id'])->on('deals')->restrictOnDelete(); $table->foreign(['tenant_id', 'assignee_membership_id'])->references(['tenant_id', 'id'])->on('tenant_staff_memberships')->restrictOnDelete(); $table->foreign(['tenant_id', 'created_by_membership_id'])->references(['tenant_id', 'id'])->on('tenant_staff_memberships')->restrictOnDelete();
            $table->index(['tenant_id', 'status', 'due_at']);
        });
        Schema::create('sales_activities', function (Blueprint $table): void {
            $table->uuid('id')->primary(); $table->uuid('tenant_id'); $table->uuid('customer_id')->nullable(); $table->uuid('deal_id')->nullable(); $table->uuid('task_id')->nullable(); $table->string('event_type', 80); $table->uuid('actor_membership_id')->nullable(); $table->jsonb('metadata')->default(DB::raw("'{}'::jsonb")); $table->timestampTz('occurred_at');
            $table->foreign(['tenant_id', 'customer_id'])->references(['tenant_id', 'id'])->on('customers')->restrictOnDelete(); $table->foreign(['tenant_id', 'deal_id'])->references(['tenant_id', 'id'])->on('deals')->restrictOnDelete(); $table->foreign(['tenant_id', 'task_id'])->references(['tenant_id', 'id'])->on('sales_tasks')->restrictOnDelete(); $table->foreign(['tenant_id', 'actor_membership_id'])->references(['tenant_id', 'id'])->on('tenant_staff_memberships')->restrictOnDelete();
            $table->index(['tenant_id', 'occurred_at']);
        });
        DB::statement('ALTER TABLE public.sales_tasks ADD CONSTRAINT sales_tasks_exactly_one_target CHECK ((customer_id IS NOT NULL) <> (deal_id IS NOT NULL))');
        DB::statement('ALTER TABLE public.sales_activities ADD CONSTRAINT sales_activities_has_target CHECK ((customer_id IS NOT NULL) OR (deal_id IS NOT NULL) OR (task_id IS NOT NULL))');
        foreach (['sales_pipelines', 'sales_pipeline_stages', 'deals', 'deal_stage_transitions', 'sales_tasks', 'sales_activities'] as $table) {
            DB::statement("ALTER TABLE public.{$table} ENABLE ROW LEVEL SECURITY"); DB::statement("ALTER TABLE public.{$table} FORCE ROW LEVEL SECURITY");
            DB::statement("CREATE POLICY {$table}_tenant_isolation ON public.{$table} USING (tenant_id = current_setting('app.tenant_id', true)::uuid) WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid)");
            DB::statement("REVOKE ALL ON TABLE public.{$table} FROM PUBLIC"); DB::statement("GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.{$table} TO daleel_tenant_runtime");
        }
    }
    public function down(): void { throw new \LogicException('W3 schema is forward-only.'); }
};
