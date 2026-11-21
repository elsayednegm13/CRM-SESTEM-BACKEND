<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('tenant_staff_password_reset_tokens', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->uuid('tenant_id');
            $table->uuid('staff_user_id');
            $table->char('token_hash', 64)->unique();
            $table->timestampTz('created_at')->useCurrent();
            $table->timestampTz('expires_at');
            $table->timestampTz('consumed_at')->nullable();

            $table->foreign('tenant_id', 'tsrt_tenant_fk')->references('id')->on('tenants')->restrictOnDelete();
            $table->foreign(['tenant_id', 'staff_user_id'], 'tsrt_staff_fk')
                ->references(['tenant_id', 'id'])->on('tenant_staff_users')->restrictOnDelete();
            $table->index(['tenant_id', 'staff_user_id', 'expires_at'], 'tsrt_staff_expiry_idx');
        });

        DB::statement("ALTER TABLE tenant_staff_password_reset_tokens ADD CONSTRAINT tsrt_hash_check CHECK (token_hash ~ '^[a-f0-9]{64}$')");
        DB::statement('ALTER TABLE tenant_staff_password_reset_tokens ADD CONSTRAINT tsrt_expiry_check CHECK (expires_at > created_at)');
        DB::statement('ALTER TABLE tenant_staff_password_reset_tokens ADD CONSTRAINT tsrt_consumed_check CHECK (consumed_at IS NULL OR consumed_at >= created_at)');
        DB::statement(<<<'SQL'
            CREATE OR REPLACE FUNCTION tenant_staff_reset_token_consume_once() RETURNS trigger
            LANGUAGE plpgsql
            AS $$
            BEGIN
                IF OLD.consumed_at IS NOT NULL
                    OR NEW.consumed_at IS NULL
                    OR NEW.id IS DISTINCT FROM OLD.id
                    OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
                    OR NEW.staff_user_id IS DISTINCT FROM OLD.staff_user_id
                    OR NEW.token_hash IS DISTINCT FROM OLD.token_hash
                    OR NEW.created_at IS DISTINCT FROM OLD.created_at
                    OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
                    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'reset token may be consumed once; token metadata is immutable';
                END IF;
                RETURN NEW;
            END
            $$
        SQL);
        DB::statement(<<<'SQL'
            CREATE TRIGGER tenant_staff_reset_token_consume_once_trigger
            BEFORE UPDATE ON tenant_staff_password_reset_tokens
            FOR EACH ROW EXECUTE FUNCTION tenant_staff_reset_token_consume_once()
        SQL);

        Schema::create('tenant_staff_security_events', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->timestampTz('occurred_at')->useCurrent();
            $table->uuid('tenant_id');
            $table->string('event_type', 80);
            $table->string('outcome', 8);
            $table->uuid('request_id')->nullable();
            $table->uuid('actor_membership_id')->nullable();
            $table->uuid('provider_operation_id')->nullable();
            $table->uuid('target_staff_user_id');
            $table->jsonb('metadata')->default('{}');

            $table->foreign('tenant_id', 'tsse_tenant_fk')->references('id')->on('tenants')->restrictOnDelete();
            $table->foreign(['tenant_id', 'actor_membership_id'], 'tsse_actor_membership_fk')
                ->references(['tenant_id', 'id'])->on('tenant_staff_memberships')->restrictOnDelete();
            $table->foreign('provider_operation_id', 'tsse_provider_operation_fk')
                ->references('id')->on('provider_control_operations')->restrictOnDelete();
            $table->foreign(['tenant_id', 'target_staff_user_id'], 'tsse_target_staff_fk')
                ->references(['tenant_id', 'id'])->on('tenant_staff_users')->restrictOnDelete();
            $table->index(['tenant_id', 'occurred_at'], 'tsse_tenant_time_idx');
        });

        DB::statement("ALTER TABLE tenant_staff_security_events ADD CONSTRAINT tsse_actor_check CHECK (num_nonnulls(actor_membership_id, provider_operation_id) = 1)");
        DB::statement("ALTER TABLE tenant_staff_security_events ADD CONSTRAINT tsse_outcome_check CHECK (outcome IN ('SUCCESS', 'DENIED', 'FAILED'))");
        DB::statement("ALTER TABLE tenant_staff_security_events ADD CONSTRAINT tsse_event_type_check CHECK (event_type IN ('tenant_staff.created', 'tenant_staff.email_changed', 'tenant_staff.disabled', 'tenant_staff.reactivated', 'tenant_staff.password_set', 'tenant_staff.password_reset_completed', 'tenant_staff.role_assigned', 'tenant_staff.role_revoked', 'tenant_staff.permission_granted', 'tenant_staff.permission_revoked', 'tenant_staff.auth_denied'))");
        DB::statement("ALTER TABLE tenant_staff_security_events ADD CONSTRAINT tsse_metadata_check CHECK (jsonb_typeof(metadata) = 'object' AND metadata = '{}'::jsonb)");

        DB::statement(<<<'SQL'
            CREATE OR REPLACE FUNCTION tenant_staff_security_event_append_only() RETURNS trigger
            LANGUAGE plpgsql
            AS $$
            BEGIN
                RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'tenant staff security events are append-only';
            END
            $$
        SQL);
        DB::statement(<<<'SQL'
            CREATE TRIGGER tenant_staff_security_event_no_update
            BEFORE UPDATE OR DELETE ON tenant_staff_security_events
            FOR EACH ROW EXECUTE FUNCTION tenant_staff_security_event_append_only()
        SQL);

        DB::statement('ALTER TABLE tenant_staff_password_reset_tokens ENABLE ROW LEVEL SECURITY');
        DB::statement('ALTER TABLE tenant_staff_password_reset_tokens FORCE ROW LEVEL SECURITY');
        DB::statement("CREATE POLICY tenant_staff_reset_tokens_actor_scope ON tenant_staff_password_reset_tokens FOR ALL USING (app_rls_context_mode() = 'TENANT' AND tenant_id = app_rls_current_tenant_id() AND EXISTS (SELECT 1 FROM tenant_staff_memberships actor WHERE actor.tenant_id = tenant_staff_password_reset_tokens.tenant_id AND actor.staff_user_id = app_rls_current_user_id() AND actor.status = 'ACTIVE')) WITH CHECK (app_rls_context_mode() = 'TENANT' AND tenant_id = app_rls_current_tenant_id() AND EXISTS (SELECT 1 FROM tenant_staff_memberships actor WHERE actor.tenant_id = tenant_staff_password_reset_tokens.tenant_id AND actor.staff_user_id = app_rls_current_user_id() AND actor.status = 'ACTIVE'))");
        DB::statement('REVOKE ALL ON TABLE tenant_staff_password_reset_tokens FROM PUBLIC');

        DB::statement('ALTER TABLE tenant_staff_security_events ENABLE ROW LEVEL SECURITY');
        DB::statement('ALTER TABLE tenant_staff_security_events FORCE ROW LEVEL SECURITY');
        DB::statement("CREATE POLICY tenant_staff_security_events_actor_scope ON tenant_staff_security_events FOR ALL USING (app_rls_context_mode() = 'TENANT' AND tenant_id = app_rls_current_tenant_id() AND EXISTS (SELECT 1 FROM tenant_staff_memberships actor WHERE actor.tenant_id = tenant_staff_security_events.tenant_id AND actor.staff_user_id = app_rls_current_user_id() AND actor.status = 'ACTIVE')) WITH CHECK (app_rls_context_mode() = 'TENANT' AND tenant_id = app_rls_current_tenant_id() AND actor_membership_id IN (SELECT actor.id FROM tenant_staff_memberships actor WHERE actor.tenant_id = tenant_staff_security_events.tenant_id AND actor.staff_user_id = app_rls_current_user_id() AND actor.status = 'ACTIVE') AND provider_operation_id IS NULL)");
        DB::statement('REVOKE ALL ON TABLE tenant_staff_security_events FROM PUBLIC');
    }

    public function down(): void
    {
        throw new LogicException('FND-ID-01 migrations are forward-only; restore from an approved snapshot instead.');
    }
};
