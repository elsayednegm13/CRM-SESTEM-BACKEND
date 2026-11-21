<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('security_audit_events', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->timestampTz('occurred_at')->useCurrent();
            $table->string('category', 32);
            $table->string('event_type', 80);
            $table->string('outcome', 8);
            $table->uuid('request_id')->nullable();
            $table->string('actor_type', 16);
            $table->uuid('actor_id')->nullable();
            $table->uuid('tenant_id')->nullable();
            $table->string('target_type', 32);
            $table->string('target_id', 128);
            $table->string('source_channel', 16);
            $table->uuid('operation_id')->nullable();
            $table->jsonb('metadata')->default('{}');

            $table->foreign('tenant_id')->references('id')->on('tenants')->restrictOnDelete();
            $table->index('occurred_at');
            $table->index(['tenant_id', 'occurred_at']);
        });

        DB::statement("ALTER TABLE security_audit_events ADD CONSTRAINT security_audit_category_check CHECK (category IN ('IDENTITY_SECURITY','TENANT_SECURITY','AUTHORIZATION','PROVIDER_SECURITY','COMMERCIAL','MAINTENANCE','SYSTEM_SECURITY'))");
        DB::statement("ALTER TABLE security_audit_events ADD CONSTRAINT security_audit_outcome_check CHECK (outcome IN ('SUCCESS','DENIED','FAILED'))");
        DB::statement("ALTER TABLE security_audit_events ADD CONSTRAINT security_audit_actor_type_check CHECK (actor_type IN ('TENANT_USER','PROVIDER_USER','SERVICE_ACTOR','SYSTEM'))");
        DB::statement("ALTER TABLE security_audit_events ADD CONSTRAINT security_audit_channel_check CHECK (source_channel IN ('API','INTERNAL','PROVIDER','WORKER','SCHEDULER','CLI','SYSTEM'))");
        DB::statement("ALTER TABLE security_audit_events ADD CONSTRAINT security_audit_actor_reference_check CHECK ((actor_type IN ('TENANT_USER','PROVIDER_USER','SERVICE_ACTOR') AND actor_id IS NOT NULL) OR (actor_type = 'SYSTEM' AND actor_id IS NULL))");
        DB::statement("ALTER TABLE security_audit_events ADD CONSTRAINT security_audit_tenant_actor_check CHECK (actor_type <> 'TENANT_USER' OR tenant_id IS NOT NULL)");
        DB::statement("ALTER TABLE security_audit_events ADD CONSTRAINT security_audit_event_type_check CHECK (event_type ~ '^[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)+$')");
        DB::statement("ALTER TABLE security_audit_events ADD CONSTRAINT security_audit_target_check CHECK (target_type ~ '^[a-z][a-z0-9_]*$' AND target_id ~ '^[A-Za-z0-9_.:-]+$')");
        DB::statement("ALTER TABLE security_audit_events ADD CONSTRAINT security_audit_current_event_target_check CHECK (CASE WHEN event_type IN ('role.created','role.grants_changed','role.archived') THEN target_type = 'role' AND pg_input_is_valid(target_id, 'uuid') WHEN event_type IN ('role.assigned','role.revoked','membership.suspended','membership.reactivated') THEN target_type = 'membership' AND pg_input_is_valid(target_id, 'uuid') WHEN event_type = 'user.disabled' THEN target_type = 'user' AND pg_input_is_valid(target_id, 'uuid') WHEN event_type = 'tenant.company_admin_bootstrapped' THEN target_type = 'tenant' AND pg_input_is_valid(target_id, 'uuid') ELSE true END)");
        DB::statement("ALTER TABLE security_audit_events ADD CONSTRAINT security_audit_metadata_check CHECK (jsonb_typeof(metadata) = 'object' AND octet_length(metadata::text) <= 2048 AND CASE event_type WHEN 'role.grants_changed' THEN metadata = '{\"changed_fields\":[\"grants\"]}'::jsonb WHEN 'membership.suspended' THEN metadata = '{\"before_status\":\"ACTIVE\",\"after_status\":\"SUSPENDED\"}'::jsonb WHEN 'membership.reactivated' THEN metadata = '{\"before_status\":\"SUSPENDED\",\"after_status\":\"ACTIVE\"}'::jsonb ELSE metadata = '{}'::jsonb END)");

        DB::statement('ALTER TABLE security_audit_events ENABLE ROW LEVEL SECURITY');
        DB::statement('ALTER TABLE security_audit_events FORCE ROW LEVEL SECURITY');
        DB::statement(<<<'SQL'
            CREATE POLICY security_audit_tenant_insert ON security_audit_events FOR INSERT
            WITH CHECK (
                outcome = 'SUCCESS' AND source_channel = 'INTERNAL'
                AND (
                    (actor_type = 'TENANT_USER'
                        AND app_rls_context_mode() = 'TENANT'
                        AND actor_id = app_rls_current_user_id()
                        AND tenant_id = app_rls_current_tenant_id()
                        AND ((category = 'AUTHORIZATION' AND event_type IN
                            ('role.created','role.grants_changed','role.archived','role.assigned','role.revoked'))
                            OR (category = 'TENANT_SECURITY' AND event_type IN
                            ('membership.suspended','membership.reactivated'))))
                    OR (actor_type = 'SYSTEM' AND actor_id IS NULL
                        AND category = 'IDENTITY_SECURITY' AND event_type = 'user.disabled'
                        AND target_type = 'user' AND target_id = app_rls_current_user_id()::text
                        AND ((app_rls_context_mode() = 'TENANT'
                            AND tenant_id = app_rls_current_tenant_id())
                            OR (app_rls_context_mode() = 'TENANT_DISCOVERY' AND tenant_id IS NULL)))
                )
            )
        SQL);
    }

    public function down(): void
    {
        Schema::dropIfExists('security_audit_events');
    }
};
