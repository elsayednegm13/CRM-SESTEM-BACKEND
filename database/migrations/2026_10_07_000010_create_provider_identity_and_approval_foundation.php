<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('provider_users', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->string('email', 254)->unique();
            $table->string('password');
            $table->string('status', 8)->default('ACTIVE');
            $table->timestampTz('email_verified_at')->nullable();
            $table->unsignedBigInteger('auth_version')->default(1);
            $table->unsignedBigInteger('authorization_version')->default(1);
            $table->timestampTz('mfa_enrolled_at')->nullable();
            $table->timestampTz('last_login_at')->nullable();
            $table->timestampsTz();
        });
        DB::statement("ALTER TABLE provider_users ADD CONSTRAINT provider_users_status_check CHECK (status IN ('ACTIVE','DISABLED'))");
        DB::statement('ALTER TABLE provider_users ADD CONSTRAINT provider_users_auth_version_check CHECK (auth_version >= 1 AND authorization_version >= 1)');

        Schema::create('provider_mfa_totp', function (Blueprint $table): void {
            $table->uuid('provider_user_id')->primary();
            $table->text('secret_ciphertext');
            $table->timestampTz('confirmed_at');
            $table->unsignedBigInteger('last_used_counter')->nullable();
            $table->timestampsTz();
            $table->foreign('provider_user_id')->references('id')->on('provider_users')->restrictOnDelete();
        });

        Schema::create('provider_mfa_recovery_codes', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->uuid('provider_user_id');
            $table->string('code_hash', 255);
            $table->timestampTz('used_at')->nullable();
            $table->timestampsTz();
            $table->foreign('provider_user_id')->references('id')->on('provider_users')->restrictOnDelete();
            $table->index(['provider_user_id', 'used_at']);
        });

        Schema::create('provider_capabilities', function (Blueprint $table): void {
            $table->string('key', 64)->primary();
            $table->string('description', 160);
            $table->string('status', 8)->default('ACTIVE');
            $table->unsignedInteger('version')->default(1);
        });
        DB::statement("ALTER TABLE provider_capabilities ADD CONSTRAINT provider_capabilities_status_check CHECK (status IN ('ACTIVE','RETIRED') AND version >= 1)");
        DB::table('provider_capabilities')->insert([
            ['key' => 'company.provision', 'description' => 'Request company provisioning approval'],
            ['key' => 'company.recover', 'description' => 'Request company recovery approval'],
            ['key' => 'company.lifecycle.manage', 'description' => 'Reserved company lifecycle authority'],
            ['key' => 'provider.approval.review', 'description' => 'Review independent provider approvals'],
        ]);

        Schema::create('provider_user_capabilities', function (Blueprint $table): void {
            $table->uuid('provider_user_id');
            $table->string('capability_key', 64);
            $table->timestampTz('granted_at')->useCurrent();
            $table->timestampTz('expires_at')->nullable();
            $table->primary(['provider_user_id', 'capability_key']);
            $table->foreign('provider_user_id')->references('id')->on('provider_users')->restrictOnDelete();
            $table->foreign('capability_key')->references('key')->on('provider_capabilities')->restrictOnDelete();
        });
        DB::statement('ALTER TABLE provider_user_capabilities ADD CONSTRAINT provider_capability_expiry_check CHECK (expires_at IS NULL OR expires_at > granted_at)');

        Schema::create('provider_approval_requests', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->uuid('requester_provider_user_id');
            $table->string('action_key', 64);
            $table->string('target_kind', 24);
            $table->uuid('target_id');
            $table->string('reason', 500);
            $table->string('ticket_reference', 100);
            $table->unsignedSmallInteger('required_approvals');
            $table->timestampTz('expires_at');
            $table->string('status', 8)->default('PENDING');
            $table->timestampsTz();
            $table->foreign('requester_provider_user_id')->references('id')->on('provider_users')->restrictOnDelete();
            $table->foreign('action_key')->references('key')->on('provider_capabilities')->restrictOnDelete();
            $table->index(['status', 'expires_at']);
        });
        DB::statement("ALTER TABLE provider_approval_requests ADD CONSTRAINT provider_approval_request_check CHECK (action_key IN ('company.provision','company.recover') AND ((action_key = 'company.provision' AND target_kind = 'PROVISIONING_INTENT') OR (action_key = 'company.recover' AND target_kind = 'TENANT')) AND status IN ('PENDING','APPROVED','REJECTED','REVOKED','EXPIRED') AND required_approvals BETWEEN 1 AND 3 AND length(btrim(reason)) BETWEEN 1 AND 500 AND length(btrim(ticket_reference)) BETWEEN 1 AND 100 AND expires_at > created_at)");

        Schema::create('provider_approval_decisions', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->uuid('approval_request_id');
            $table->uuid('approver_provider_user_id');
            $table->string('decision', 7);
            $table->timestampTz('decided_at')->useCurrent();
            $table->foreign('approval_request_id')->references('id')->on('provider_approval_requests')->restrictOnDelete();
            $table->foreign('approver_provider_user_id')->references('id')->on('provider_users')->restrictOnDelete();
            $table->unique(['approval_request_id', 'approver_provider_user_id'], 'provider_approval_one_decision_per_reviewer');
        });
        DB::statement("ALTER TABLE provider_approval_decisions ADD CONSTRAINT provider_approval_decision_check CHECK (decision IN ('APPROVE','REJECT'))");

        DB::statement(<<<'SQL'
            ALTER TABLE security_audit_events ADD CONSTRAINT security_audit_provider_event_shape_check CHECK (
                event_type NOT LIKE 'provider.%' OR (
                    category = 'PROVIDER_SECURITY' AND actor_type = 'PROVIDER_USER'
                    AND source_channel = 'PROVIDER' AND tenant_id IS NULL
                    AND pg_input_is_valid(target_id, 'uuid')
                    AND ((event_type IN ('provider.mfa.enrolled','provider.mfa.recovery_code_used') AND target_type = 'provider_user' AND target_id = actor_id::text)
                        OR (event_type IN ('provider.approval.requested','provider.approval.approved','provider.approval.rejected','provider.approval.revoked') AND target_type = 'approval_request'))
                )
            )
        SQL);
        DB::statement(<<<'SQL'
            CREATE POLICY security_audit_provider_insert ON security_audit_events FOR INSERT
            WITH CHECK (
                outcome = 'SUCCESS' AND category = 'PROVIDER_SECURITY'
                AND actor_type = 'PROVIDER_USER' AND source_channel = 'PROVIDER'
                AND tenant_id IS NULL AND current_setting('app.context_mode', true) = 'PROVIDER'
                AND actor_id = CASE WHEN pg_input_is_valid(NULLIF(current_setting('app.provider_user_id', true), ''), 'uuid')
                    THEN current_setting('app.provider_user_id', true)::uuid ELSE NULL END
                AND event_type IN ('provider.mfa.enrolled','provider.mfa.recovery_code_used',
                    'provider.approval.requested','provider.approval.approved',
                    'provider.approval.rejected','provider.approval.revoked')
            )
        SQL);
    }

    public function down(): void
    {
        DB::statement('DROP POLICY security_audit_provider_insert ON security_audit_events');
        DB::statement('ALTER TABLE security_audit_events DROP CONSTRAINT security_audit_provider_event_shape_check');
        Schema::dropIfExists('provider_approval_decisions');
        Schema::dropIfExists('provider_approval_requests');
        Schema::dropIfExists('provider_user_capabilities');
        Schema::dropIfExists('provider_capabilities');
        Schema::dropIfExists('provider_mfa_recovery_codes');
        Schema::dropIfExists('provider_mfa_totp');
        Schema::dropIfExists('provider_users');
    }
};
