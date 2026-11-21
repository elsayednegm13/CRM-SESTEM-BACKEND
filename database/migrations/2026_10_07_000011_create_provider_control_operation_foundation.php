<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('provider_control_operations', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->string('action_key', 64);
            $table->uuid('requester_provider_user_id');
            $table->uuid('approval_request_id')->nullable();
            $table->char('idempotency_key_hash', 64);
            $table->char('intent_digest', 64);
            $table->uuid('target_tenant_id');
            $table->string('status', 24)->default('PENDING_APPROVAL');
            $table->uuid('result_reference')->nullable();
            $table->string('display_name', 160)->nullable();
            $table->string('canonical_slug', 100)->nullable();
            $table->string('timezone', 64)->nullable();
            $table->string('founder_email', 254)->nullable();
            $table->uuid('successor_user_id')->nullable();
            $table->uuid('compromised_membership_id')->nullable();
            $table->string('recovery_mode', 24)->nullable();
            $table->string('reason', 500);
            $table->string('ticket_reference', 100);
            $table->timestampTz('expires_at');
            $table->timestampTz('completed_at')->nullable();
            $table->timestampsTz();

            $table->foreign('requester_provider_user_id')->references('id')->on('provider_users')->restrictOnDelete();
            $table->unique(['requester_provider_user_id', 'action_key', 'idempotency_key_hash'],
                'provider_control_operation_idempotency_unique');
            $table->index(['target_tenant_id', 'action_key', 'status'], 'provider_control_operation_target_status_idx');
            $table->index(['status', 'expires_at'], 'provider_control_operation_expiry_idx');
        });
        DB::statement("ALTER TABLE provider_control_operations ADD CONSTRAINT provider_control_operation_action_check CHECK (action_key IN ('company.provision','company.recover'))");
        DB::statement("ALTER TABLE provider_control_operations ADD CONSTRAINT provider_control_operation_status_check CHECK (status IN ('PENDING_APPROVAL','READY','SUCCEEDED','CANCELLED'))");
        DB::statement("ALTER TABLE provider_control_operations ADD CONSTRAINT provider_control_operation_digest_check CHECK (idempotency_key_hash ~ '^[a-f0-9]{64}$' AND intent_digest ~ '^[a-f0-9]{64}$')");
        DB::statement("ALTER TABLE provider_control_operations ADD CONSTRAINT provider_control_operation_reason_check CHECK (length(btrim(reason)) BETWEEN 1 AND 500 AND length(btrim(ticket_reference)) BETWEEN 1 AND 100 AND ticket_reference ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$')");
        DB::statement("ALTER TABLE provider_control_operations ADD CONSTRAINT provider_control_operation_intent_check CHECK ((action_key = 'company.provision' AND display_name IS NOT NULL AND canonical_slug IS NOT NULL AND timezone IS NOT NULL AND founder_email IS NOT NULL AND successor_user_id IS NULL AND compromised_membership_id IS NULL AND recovery_mode IS NULL) OR (action_key = 'company.recover' AND display_name IS NULL AND canonical_slug IS NULL AND timezone IS NULL AND founder_email IS NULL AND successor_user_id IS NOT NULL AND recovery_mode IN ('RESTORE_ADMIN','REPLACE_ADMIN') AND ((recovery_mode = 'RESTORE_ADMIN' AND compromised_membership_id IS NULL) OR (recovery_mode = 'REPLACE_ADMIN' AND compromised_membership_id IS NOT NULL))))");
        DB::statement("ALTER TABLE provider_control_operations ADD CONSTRAINT provider_control_operation_completion_check CHECK ((status = 'SUCCEEDED' AND completed_at IS NOT NULL AND result_reference IS NOT NULL) OR (status <> 'SUCCEEDED' AND completed_at IS NULL))");

        DB::statement('ALTER TABLE provider_approval_requests ADD COLUMN operation_id uuid NULL');
        DB::statement('ALTER TABLE provider_approval_requests ADD COLUMN intent_digest char(64) NULL');
        DB::statement('ALTER TABLE provider_approval_requests ADD COLUMN consumed_at timestamptz NULL');
        DB::statement('ALTER TABLE provider_approval_requests ADD COLUMN consumed_operation_id uuid NULL');
        DB::statement('ALTER TABLE provider_approval_requests ADD CONSTRAINT provider_approval_operation_fk FOREIGN KEY (operation_id) REFERENCES provider_control_operations(id) ON DELETE RESTRICT');
        DB::statement('ALTER TABLE provider_approval_requests ADD CONSTRAINT provider_approval_consumed_operation_fk FOREIGN KEY (consumed_operation_id) REFERENCES provider_control_operations(id) ON DELETE RESTRICT');
        DB::statement('ALTER TABLE provider_approval_requests ADD CONSTRAINT provider_approval_one_operation_unique UNIQUE (operation_id)');
        DB::statement("ALTER TABLE provider_approval_requests ADD CONSTRAINT provider_approval_operation_binding_check CHECK ((operation_id IS NULL AND intent_digest IS NULL AND consumed_at IS NULL AND consumed_operation_id IS NULL) OR (operation_id IS NOT NULL AND intent_digest ~ '^[a-f0-9]{64}$' AND ((consumed_at IS NULL AND consumed_operation_id IS NULL) OR (consumed_at IS NOT NULL AND consumed_operation_id = operation_id))))");
        DB::statement('ALTER TABLE provider_control_operations ADD CONSTRAINT provider_control_operation_approval_fk FOREIGN KEY (approval_request_id) REFERENCES provider_approval_requests(id) ON DELETE RESTRICT');

        DB::statement('ALTER TABLE provider_approval_decisions ADD COLUMN reason varchar(500) NULL');
        DB::statement('ALTER TABLE provider_approval_decisions ADD COLUMN ticket_reference varchar(100) NULL');
        DB::statement('ALTER TABLE provider_approval_decisions DROP CONSTRAINT provider_approval_decision_check');
        DB::statement("ALTER TABLE provider_approval_decisions ADD CONSTRAINT provider_approval_decision_check CHECK (decision IN ('APPROVE','REJECT','REVOKE') AND (reason IS NULL OR length(btrim(reason)) BETWEEN 1 AND 500) AND (ticket_reference IS NULL OR (length(btrim(ticket_reference)) BETWEEN 1 AND 100 AND ticket_reference ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$')))");

        Schema::create('tenant_founder_invitations', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->uuid('operation_id')->unique();
            $table->uuid('tenant_id');
            $table->string('email_canonical', 254);
            $table->uuid('existing_user_id')->nullable();
            $table->char('token_hash', 64)->unique();
            $table->timestampTz('expires_at');
            $table->timestampTz('accepted_at')->nullable();
            $table->timestampTz('revoked_at')->nullable();
            $table->timestampTz('created_at')->useCurrent();

            $table->foreign('operation_id')->references('id')->on('provider_control_operations')->restrictOnDelete();
            $table->foreign('tenant_id')->references('id')->on('tenants')->restrictOnDelete();
            $table->foreign('existing_user_id')->references('id')->on('users')->restrictOnDelete();
            $table->index(['tenant_id', 'email_canonical', 'accepted_at']);
        });
        DB::statement("ALTER TABLE tenant_founder_invitations ADD CONSTRAINT tenant_founder_invitation_hash_check CHECK (token_hash ~ '^[a-f0-9]{64}$')");
        DB::statement('ALTER TABLE tenant_founder_invitations ADD CONSTRAINT tenant_founder_invitation_state_check CHECK (NOT (accepted_at IS NOT NULL AND revoked_at IS NOT NULL))');

        Schema::create('outbox_messages', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->string('event_type', 80);
            $table->string('aggregate_type', 40);
            $table->uuid('aggregate_id');
            $table->jsonb('payload');
            $table->timestampTz('created_at')->useCurrent();
            $table->timestampTz('published_at')->nullable();
            $table->unsignedInteger('attempt_count')->default(0);

            $table->foreign('aggregate_id')->references('id')->on('tenant_founder_invitations')->restrictOnDelete();
            $table->unique(['event_type', 'aggregate_type', 'aggregate_id'], 'outbox_once_per_founder_invitation');
        });
        DB::statement("ALTER TABLE outbox_messages ADD CONSTRAINT outbox_founder_delivery_shape_check CHECK (event_type = 'founder.invitation.delivery_requested' AND aggregate_type = 'tenant_founder_invitation' AND jsonb_typeof(payload) = 'object' AND payload ??& ARRAY['invitation_id','encrypted_token'] AND payload - ARRAY['invitation_id','encrypted_token'] = '{}'::jsonb AND jsonb_typeof(payload->'invitation_id') = 'string' AND payload->>'invitation_id' = aggregate_id::text AND jsonb_typeof(payload->'encrypted_token') = 'string' AND length(payload->>'encrypted_token') BETWEEN 100 AND 4096 AND attempt_count >= 0)");
        DB::statement('ALTER TABLE outbox_messages ENABLE ROW LEVEL SECURITY');
        DB::statement('ALTER TABLE outbox_messages FORCE ROW LEVEL SECURITY');

        DB::statement(<<<'SQL'
            CREATE OR REPLACE FUNCTION app_provider_control_setting_uuid(setting_name text) RETURNS uuid
            LANGUAGE sql STABLE SECURITY INVOKER
            AS $$
                SELECT CASE WHEN pg_input_is_valid(NULLIF(current_setting(setting_name, true), ''), 'uuid')
                    THEN current_setting(setting_name, true)::uuid ELSE NULL END
            $$
        SQL);
        DB::statement(<<<'SQL'
            CREATE OR REPLACE FUNCTION app_provider_control_actor_allowed() RETURNS boolean
            LANGUAGE sql STABLE SECURITY INVOKER
            AS $$
                SELECT EXISTS (
                    SELECT 1
                    FROM provider_users p
                    JOIN provider_user_capabilities a ON a.provider_user_id = p.id
                    JOIN provider_capabilities c ON c.key = a.capability_key
                    WHERE p.id = app_provider_control_setting_uuid('app.provider_user_id')
                      AND p.status = 'ACTIVE' AND p.email_verified_at IS NOT NULL AND p.mfa_enrolled_at IS NOT NULL
                      AND pg_input_is_valid(NULLIF(current_setting('app.provider_auth_version', true), ''), 'bigint')
                      AND p.auth_version = current_setting('app.provider_auth_version', true)::bigint
                      AND c.status = 'ACTIVE'
                      AND a.capability_key = current_setting('app.provider_capability', true)
                      AND (a.expires_at IS NULL OR a.expires_at > transaction_timestamp())
                      AND pg_input_is_valid(NULLIF(current_setting('app.provider_step_up_at', true), ''), 'timestamptz')
                      AND current_setting('app.provider_step_up_at', true)::timestamptz <= transaction_timestamp()
                      AND current_setting('app.provider_step_up_at', true)::timestamptz > transaction_timestamp() - interval '10 minutes'
                )
            $$
        SQL);
        DB::statement(<<<'SQL'
            CREATE OR REPLACE FUNCTION app_provider_control_tenant_allowed(candidate_tenant_id uuid) RETURNS boolean
            LANGUAGE sql STABLE SECURITY INVOKER
            AS $$
                SELECT current_setting('app.context_mode', true) = 'PROVIDER_CONTROL'
                  AND app_provider_control_actor_allowed()
                  AND EXISTS (
                    SELECT 1
                    FROM provider_control_operations o
                    JOIN provider_approval_requests a ON a.id = o.approval_request_id
                    WHERE o.id = app_provider_control_setting_uuid('app.provider_operation_id')
                      AND o.action_key = current_setting('app.provider_action', true)
                      AND o.target_tenant_id = candidate_tenant_id
                      AND o.requester_provider_user_id = app_provider_control_setting_uuid('app.provider_user_id')
                      AND o.status IN ('READY','SUCCEEDED') AND o.expires_at > transaction_timestamp()
                      AND a.id = app_provider_control_setting_uuid('app.provider_approval_id')
                      AND a.operation_id = o.id AND a.action_key = o.action_key
                      AND a.target_id = o.target_tenant_id AND a.intent_digest = o.intent_digest
                      AND a.status = 'APPROVED' AND a.expires_at > transaction_timestamp()
                      AND (a.consumed_at IS NULL OR a.consumed_operation_id = o.id)
                      AND (SELECT count(*) FROM provider_approval_decisions d
                           WHERE d.approval_request_id = a.id AND d.decision = 'APPROVE') >= a.required_approvals
                      AND NOT EXISTS (SELECT 1 FROM provider_approval_decisions d
                           WHERE d.approval_request_id = a.id AND d.decision = 'REJECT')
                  )
            $$
        SQL);
        DB::statement(<<<'SQL'
            CREATE OR REPLACE FUNCTION app_provider_control_request_tenant_allowed(candidate_tenant_id uuid) RETURNS boolean
            LANGUAGE sql STABLE SECURITY INVOKER
            AS $$
                SELECT current_setting('app.context_mode', true) = 'PROVIDER_CONTROL_REQUEST'
                  AND current_setting('app.provider_action', true) = 'company.recover'
                  AND app_provider_control_setting_uuid('app.provider_target_tenant_id') = candidate_tenant_id
                  AND app_provider_control_actor_allowed()
            $$
        SQL);
        DB::statement(<<<'SQL'
            CREATE OR REPLACE FUNCTION app_founder_activation_tenant_allowed(candidate_tenant_id uuid) RETURNS boolean
            LANGUAGE sql STABLE SECURITY INVOKER
            AS $$
                SELECT current_setting('app.context_mode', true) = 'FOUNDER_ACTIVATION'
                  AND EXISTS (
                    SELECT 1
                    FROM tenant_founder_invitations i
                    JOIN provider_control_operations o ON o.id = i.operation_id
                    JOIN users u ON u.id = app_provider_control_setting_uuid('app.user_id')
                    WHERE i.id = app_provider_control_setting_uuid('app.founder_invitation_id')
                      AND i.tenant_id = candidate_tenant_id
                      AND i.email_canonical = u.email
                      AND (i.existing_user_id IS NULL OR i.existing_user_id = u.id)
                      AND i.revoked_at IS NULL AND i.expires_at > transaction_timestamp()
                      AND o.action_key = 'company.provision' AND o.status = 'SUCCEEDED'
                      AND o.target_tenant_id = i.tenant_id
                      AND u.status = 'ACTIVE' AND u.email_verified_at IS NOT NULL
                  )
            $$
        SQL);

        // The tenant root uses `id`; child rows use `tenant_id`, so keep it out
        // of this generic child-table policy loop.
        foreach (['tenant_memberships', 'roles', 'role_permissions', 'membership_roles'] as $table) {
            DB::statement("CREATE POLICY {$table}_provider_control_select ON {$table} FOR SELECT USING (app_provider_control_tenant_allowed(tenant_id))");
            DB::statement("CREATE POLICY {$table}_founder_activation_select ON {$table} FOR SELECT USING (app_founder_activation_tenant_allowed(tenant_id))");
            DB::statement("CREATE POLICY {$table}_provider_control_insert ON {$table} FOR INSERT WITH CHECK (app_provider_control_tenant_allowed(tenant_id))");
            DB::statement("CREATE POLICY {$table}_founder_activation_insert ON {$table} FOR INSERT WITH CHECK (app_founder_activation_tenant_allowed(tenant_id))");
            DB::statement("CREATE POLICY {$table}_provider_control_update ON {$table} FOR UPDATE USING (app_provider_control_tenant_allowed(tenant_id)) WITH CHECK (app_provider_control_tenant_allowed(tenant_id))");
            DB::statement("CREATE POLICY {$table}_founder_activation_update ON {$table} FOR UPDATE USING (app_founder_activation_tenant_allowed(tenant_id)) WITH CHECK (app_founder_activation_tenant_allowed(tenant_id))");
        }
        DB::statement("CREATE POLICY tenants_provider_control_select ON tenants FOR SELECT USING (app_provider_control_tenant_allowed(id))");
        DB::statement("CREATE POLICY tenants_founder_activation_select ON tenants FOR SELECT USING (app_founder_activation_tenant_allowed(id))");
        DB::statement("CREATE POLICY tenants_provider_control_request_select ON tenants FOR SELECT USING (app_provider_control_request_tenant_allowed(id))");
        DB::statement("CREATE POLICY tenants_provider_control_insert ON tenants FOR INSERT WITH CHECK (app_provider_control_tenant_allowed(id) AND current_setting('app.provider_action', true) = 'company.provision' AND status = 'PROVISIONING')");
        DB::statement("CREATE POLICY tenants_founder_activation_update ON tenants FOR UPDATE USING (app_founder_activation_tenant_allowed(id) AND status = 'PROVISIONING') WITH CHECK (app_founder_activation_tenant_allowed(id) AND status = 'ACTIVE')");

        DB::statement("CREATE POLICY outbox_provider_control_insert ON outbox_messages FOR INSERT WITH CHECK (EXISTS (SELECT 1 FROM tenant_founder_invitations i WHERE i.id = aggregate_id AND app_provider_control_tenant_allowed(i.tenant_id) AND event_type = 'founder.invitation.delivery_requested'))");

        DB::statement(<<<'SQL'
            CREATE POLICY security_audit_provider_control_insert ON security_audit_events FOR INSERT
            WITH CHECK (
                outcome = 'SUCCESS' AND actor_type = 'PROVIDER_USER'
                AND actor_id = app_provider_control_setting_uuid('app.provider_user_id')
                AND source_channel = 'PROVIDER'
                AND current_setting('app.context_mode', true) IN ('PROVIDER_CONTROL','PROVIDER_CONTROL_REQUEST')
                AND app_provider_control_actor_allowed()
                AND (
                    (tenant_id IS NULL AND event_type IN ('provider.control_operation.created',
                        'provider.control_operation.cancelled','provider.approval.requested',
                        'provider.approval.approved','provider.approval.rejected','provider.approval.revoked'))
                    OR (tenant_id IS NOT NULL AND target_id = tenant_id::text
                        AND event_type IN ('tenant.provisioning.executed','tenant.recovery.executed')
                        AND app_provider_control_tenant_allowed(tenant_id))
                )
            )
        SQL);
        DB::statement(<<<'SQL'
            CREATE POLICY security_audit_founder_activation_insert ON security_audit_events FOR INSERT
            WITH CHECK (
                outcome = 'SUCCESS' AND actor_type = 'TENANT_USER'
                AND actor_id = app_provider_control_setting_uuid('app.user_id')
                AND tenant_id = app_provider_control_setting_uuid('app.provider_target_tenant_id')
                AND source_channel = 'API'
                AND current_setting('app.context_mode', true) = 'FOUNDER_ACTIVATION'
                AND event_type IN ('tenant.founder_invitation.accepted','tenant.activated')
                AND app_founder_activation_tenant_allowed(tenant_id)
            )
        SQL);

        DB::statement('ALTER TABLE security_audit_events DROP CONSTRAINT security_audit_provider_event_shape_check');
        DB::statement(<<<'SQL'
            ALTER TABLE security_audit_events ADD CONSTRAINT security_audit_provider_event_shape_check CHECK (
                event_type NOT LIKE 'provider.%' OR (
                    category = 'PROVIDER_SECURITY' AND actor_type = 'PROVIDER_USER'
                    AND source_channel = 'PROVIDER' AND tenant_id IS NULL
                    AND pg_input_is_valid(target_id, 'uuid')
                    AND (
                        (event_type IN ('provider.mfa.enrolled','provider.mfa.recovery_code_used')
                            AND target_type = 'provider_user' AND target_id = actor_id::text)
                        OR (event_type IN ('provider.approval.requested','provider.approval.approved',
                            'provider.approval.rejected','provider.approval.revoked') AND target_type = 'approval_request')
                        OR (event_type IN ('provider.control_operation.created','provider.control_operation.cancelled')
                            AND target_type = 'provider_control_operation')
                    )
                )
            )
        SQL);
        DB::statement('ALTER TABLE security_audit_events DROP CONSTRAINT security_audit_current_event_target_check');
        DB::statement(<<<'SQL'
            ALTER TABLE security_audit_events ADD CONSTRAINT security_audit_current_event_target_check CHECK (
                CASE
                    WHEN event_type IN ('role.created','role.grants_changed','role.archived')
                        THEN target_type = 'role' AND pg_input_is_valid(target_id, 'uuid')
                    WHEN event_type IN ('role.assigned','role.revoked','membership.suspended','membership.reactivated')
                        THEN target_type = 'membership' AND pg_input_is_valid(target_id, 'uuid')
                    WHEN event_type = 'user.disabled'
                        THEN target_type = 'user' AND pg_input_is_valid(target_id, 'uuid')
                    WHEN event_type = 'tenant.company_admin_bootstrapped'
                        THEN target_type = 'tenant' AND pg_input_is_valid(target_id, 'uuid')
                    WHEN event_type IN ('provider.control_operation.created','provider.control_operation.cancelled')
                        THEN target_type = 'provider_control_operation' AND pg_input_is_valid(target_id, 'uuid')
                    WHEN event_type IN ('tenant.provisioning.executed','tenant.activated','tenant.recovery.executed')
                        THEN target_type = 'tenant' AND pg_input_is_valid(target_id, 'uuid')
                    WHEN event_type = 'tenant.founder_invitation.accepted'
                        THEN target_type = 'tenant_founder_invitation' AND pg_input_is_valid(target_id, 'uuid')
                    ELSE true
                END
            )
        SQL);
        DB::statement('ALTER TABLE security_audit_events DROP CONSTRAINT security_audit_metadata_check');
        DB::statement(<<<'SQL'
            ALTER TABLE security_audit_events ADD CONSTRAINT security_audit_metadata_check CHECK (
                jsonb_typeof(metadata) = 'object' AND octet_length(metadata::text) <= 2048
                AND CASE event_type
                    WHEN 'role.grants_changed' THEN metadata = '{"changed_fields":["grants"]}'::jsonb
                    WHEN 'membership.suspended' THEN metadata = '{"before_status":"ACTIVE","after_status":"SUSPENDED"}'::jsonb
                    WHEN 'membership.reactivated' THEN metadata = '{"before_status":"SUSPENDED","after_status":"ACTIVE"}'::jsonb
                    WHEN 'tenant.provisioning.executed' THEN
                        metadata ?? 'founder_invitation_id' AND metadata - 'founder_invitation_id' = '{}'::jsonb
                        AND jsonb_typeof(metadata->'founder_invitation_id') = 'string'
                        AND pg_input_is_valid(metadata->>'founder_invitation_id','uuid')
                    WHEN 'tenant.founder_invitation.accepted' THEN
                        metadata ?? 'membership_id' AND metadata - 'membership_id' = '{}'::jsonb
                        AND jsonb_typeof(metadata->'membership_id') = 'string'
                        AND pg_input_is_valid(metadata->>'membership_id','uuid')
                    WHEN 'tenant.activated' THEN
                        metadata ?? 'membership_id' AND metadata - 'membership_id' = '{}'::jsonb
                        AND jsonb_typeof(metadata->'membership_id') = 'string'
                        AND pg_input_is_valid(metadata->>'membership_id','uuid')
                    WHEN 'tenant.recovery.executed' THEN
                        metadata ??& ARRAY['successor_user_id','successor_membership_id','compromised_membership_id']
                        AND metadata - ARRAY['successor_user_id','successor_membership_id','compromised_membership_id'] = '{}'::jsonb
                        AND jsonb_typeof(metadata->'successor_user_id') = 'string'
                        AND pg_input_is_valid(metadata->>'successor_user_id','uuid')
                        AND jsonb_typeof(metadata->'successor_membership_id') = 'string'
                        AND pg_input_is_valid(metadata->>'successor_membership_id','uuid')
                        AND (metadata->'compromised_membership_id' = 'null'::jsonb OR
                            (jsonb_typeof(metadata->'compromised_membership_id') = 'string'
                                AND pg_input_is_valid(metadata->>'compromised_membership_id','uuid')))
                    ELSE metadata = '{}'::jsonb
                END
            )
        SQL);
    }

    public function down(): void
    {
        DB::statement('DROP POLICY security_audit_founder_activation_insert ON security_audit_events');
        DB::statement('DROP POLICY security_audit_provider_control_insert ON security_audit_events');
        DB::statement('DROP POLICY outbox_provider_control_insert ON outbox_messages');
        DB::statement('DROP POLICY tenants_provider_control_select ON tenants');
        DB::statement('DROP POLICY tenants_founder_activation_select ON tenants');
        foreach (['tenant_memberships', 'roles', 'role_permissions', 'membership_roles'] as $table) {
            DB::statement("DROP POLICY {$table}_provider_control_select ON {$table}");
            DB::statement("DROP POLICY {$table}_founder_activation_select ON {$table}");
            DB::statement("DROP POLICY {$table}_provider_control_insert ON {$table}");
            DB::statement("DROP POLICY {$table}_founder_activation_insert ON {$table}");
            DB::statement("DROP POLICY {$table}_provider_control_update ON {$table}");
            DB::statement("DROP POLICY {$table}_founder_activation_update ON {$table}");
        }
        DB::statement('DROP POLICY tenants_provider_control_request_select ON tenants');
        DB::statement('DROP POLICY tenants_provider_control_insert ON tenants');
        DB::statement('DROP POLICY tenants_founder_activation_update ON tenants');

        DB::statement('ALTER TABLE security_audit_events DROP CONSTRAINT security_audit_provider_event_shape_check');
        DB::statement('ALTER TABLE security_audit_events DROP CONSTRAINT security_audit_current_event_target_check');
        DB::statement('ALTER TABLE security_audit_events DROP CONSTRAINT security_audit_metadata_check');
        DB::statement("ALTER TABLE security_audit_events ADD CONSTRAINT security_audit_provider_event_shape_check CHECK (event_type NOT LIKE 'provider.%' OR (category = 'PROVIDER_SECURITY' AND actor_type = 'PROVIDER_USER' AND source_channel = 'PROVIDER' AND tenant_id IS NULL AND pg_input_is_valid(target_id, 'uuid') AND ((event_type IN ('provider.mfa.enrolled','provider.mfa.recovery_code_used') AND target_type = 'provider_user' AND target_id = actor_id::text) OR (event_type IN ('provider.approval.requested','provider.approval.approved','provider.approval.rejected','provider.approval.revoked') AND target_type = 'approval_request'))))");
        DB::statement("ALTER TABLE security_audit_events ADD CONSTRAINT security_audit_current_event_target_check CHECK (CASE WHEN event_type IN ('role.created','role.grants_changed','role.archived') THEN target_type = 'role' AND pg_input_is_valid(target_id, 'uuid') WHEN event_type IN ('role.assigned','role.revoked','membership.suspended','membership.reactivated') THEN target_type = 'membership' AND pg_input_is_valid(target_id, 'uuid') WHEN event_type = 'user.disabled' THEN target_type = 'user' AND pg_input_is_valid(target_id, 'uuid') WHEN event_type = 'tenant.company_admin_bootstrapped' THEN target_type = 'tenant' AND pg_input_is_valid(target_id, 'uuid') ELSE true END)");
        DB::statement("ALTER TABLE security_audit_events ADD CONSTRAINT security_audit_metadata_check CHECK (jsonb_typeof(metadata) = 'object' AND octet_length(metadata::text) <= 2048 AND CASE event_type WHEN 'role.grants_changed' THEN metadata = '{\"changed_fields\":[\"grants\"]}'::jsonb WHEN 'membership.suspended' THEN metadata = '{\"before_status\":\"ACTIVE\",\"after_status\":\"SUSPENDED\"}'::jsonb WHEN 'membership.reactivated' THEN metadata = '{\"before_status\":\"SUSPENDED\",\"after_status\":\"ACTIVE\"}'::jsonb ELSE metadata = '{}'::jsonb END)");

        DB::statement('DROP FUNCTION app_founder_activation_tenant_allowed(uuid)');
        DB::statement('DROP FUNCTION app_provider_control_request_tenant_allowed(uuid)');
        DB::statement('DROP FUNCTION app_provider_control_tenant_allowed(uuid)');
        DB::statement('DROP FUNCTION app_provider_control_actor_allowed()');
        DB::statement('DROP FUNCTION app_provider_control_setting_uuid(text)');

        DB::statement('ALTER TABLE outbox_messages DISABLE ROW LEVEL SECURITY');
        Schema::dropIfExists('outbox_messages');
        Schema::dropIfExists('tenant_founder_invitations');
        DB::statement('ALTER TABLE provider_approval_decisions DROP CONSTRAINT provider_approval_decision_check');
        DB::statement("ALTER TABLE provider_approval_decisions ADD CONSTRAINT provider_approval_decision_check CHECK (decision IN ('APPROVE','REJECT'))");
        DB::statement('ALTER TABLE provider_approval_decisions DROP COLUMN ticket_reference');
        DB::statement('ALTER TABLE provider_approval_decisions DROP COLUMN reason');
        DB::statement('ALTER TABLE provider_control_operations DROP CONSTRAINT provider_control_operation_approval_fk');
        DB::statement('ALTER TABLE provider_approval_requests DROP CONSTRAINT provider_approval_operation_binding_check');
        DB::statement('ALTER TABLE provider_approval_requests DROP CONSTRAINT provider_approval_one_operation_unique');
        DB::statement('ALTER TABLE provider_approval_requests DROP CONSTRAINT provider_approval_consumed_operation_fk');
        DB::statement('ALTER TABLE provider_approval_requests DROP CONSTRAINT provider_approval_operation_fk');
        DB::statement('ALTER TABLE provider_approval_requests DROP COLUMN consumed_operation_id');
        DB::statement('ALTER TABLE provider_approval_requests DROP COLUMN consumed_at');
        DB::statement('ALTER TABLE provider_approval_requests DROP COLUMN intent_digest');
        DB::statement('ALTER TABLE provider_approval_requests DROP COLUMN operation_id');
        Schema::dropIfExists('provider_control_operations');
    }
};
