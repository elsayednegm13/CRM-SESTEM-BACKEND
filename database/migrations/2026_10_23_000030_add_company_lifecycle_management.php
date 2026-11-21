<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/**
 * Control: company lifecycle management (suspend/resume/archive).
 * Reuses the existing provider_control_operations/provider_approval_requests
 * pipeline already proven for company.provision — see
 * ProviderControlOperationService::createLifecycleChange()/executeLifecycleChange()
 * and docs/PLAN.md Phase 1. The 'company.lifecycle.manage' capability key already
 * exists (migration 2026_10_07_000010); this control only widens the operation/
 * approval/audit contracts to admit it and adds the one new tenants RLS UPDATE
 * policy a status transition actually needs.
 */
return new class extends Migration
{
    public function up(): void
    {
        $provider = $this->runtimeRole('pgsql_provider');

        DB::statement('ALTER TABLE provider_control_operations DROP CONSTRAINT provider_control_operation_action_check');
        DB::statement("ALTER TABLE provider_control_operations ADD CONSTRAINT provider_control_operation_action_check CHECK (action_key IN ('company.provision','company.recover','company.lifecycle.manage'))");

        DB::statement('ALTER TABLE provider_control_operations ADD COLUMN lifecycle_action varchar(16) NULL');
        DB::statement("ALTER TABLE provider_control_operations ADD CONSTRAINT provider_control_operation_lifecycle_action_check CHECK (lifecycle_action IS NULL OR lifecycle_action IN ('SUSPEND','RESUME','ARCHIVE'))");
        // The approvals-inbox listing (pgsql_provider, read-only) needs this column to show reviewers
        // which transition they are approving, exactly as it already reads provision's columns.
        DB::statement("GRANT SELECT (lifecycle_action) ON provider_control_operations TO {$provider}");

        DB::statement('ALTER TABLE provider_control_operations DROP CONSTRAINT provider_control_operation_intent_check');
        DB::statement(<<<'SQL'
            ALTER TABLE provider_control_operations ADD CONSTRAINT provider_control_operation_intent_check CHECK (
                (action_key = 'company.provision' AND display_name IS NOT NULL AND canonical_slug IS NOT NULL
                    AND timezone IS NOT NULL AND founder_email IS NOT NULL AND successor_user_id IS NULL
                    AND compromised_membership_id IS NULL AND recovery_mode IS NULL AND lifecycle_action IS NULL)
                OR (action_key = 'company.recover' AND display_name IS NULL AND canonical_slug IS NULL
                    AND timezone IS NULL AND founder_email IS NULL AND successor_user_id IS NOT NULL
                    AND recovery_mode IN ('RESTORE_ADMIN','REPLACE_ADMIN') AND lifecycle_action IS NULL
                    AND ((recovery_mode = 'RESTORE_ADMIN' AND compromised_membership_id IS NULL)
                        OR (recovery_mode = 'REPLACE_ADMIN' AND compromised_membership_id IS NOT NULL)))
                OR (action_key = 'company.lifecycle.manage' AND display_name IS NULL AND canonical_slug IS NULL
                    AND timezone IS NULL AND founder_email IS NULL AND successor_user_id IS NULL
                    AND compromised_membership_id IS NULL AND recovery_mode IS NULL AND lifecycle_action IS NOT NULL)
            )
        SQL);

        DB::statement('ALTER TABLE provider_approval_requests DROP CONSTRAINT provider_approval_request_check');
        DB::statement(<<<'SQL'
            ALTER TABLE provider_approval_requests ADD CONSTRAINT provider_approval_request_check CHECK (
                action_key IN ('company.provision','company.recover','company.lifecycle.manage')
                AND ((action_key = 'company.provision' AND target_kind = 'PROVISIONING_INTENT')
                    OR (action_key = 'company.recover' AND target_kind = 'TENANT')
                    OR (action_key = 'company.lifecycle.manage' AND target_kind = 'TENANT'))
                AND status IN ('PENDING','APPROVED','REJECTED','REVOKED','EXPIRED')
                AND required_approvals BETWEEN 1 AND 3
                AND length(btrim(reason)) BETWEEN 1 AND 500
                AND length(btrim(ticket_reference)) BETWEEN 1 AND 100
                AND expires_at > created_at
            )
        SQL);

        // tenants_provider_first_admin_activation_guard (migration 027) is RESTRICTIVE and scoped
        // TO daleel_provider_first_admin_writer. pgsql_provider_control is documented (docs/
        // PROVIDER_CONTROL_OPERATIONS.md) to be a member of that group. RESTRICTIVE policies are
        // ANDed with every PERMISSIVE policy regardless of action_key, so as written this policy's
        // USING/WITH CHECK — both requiring app.provider_action = 'company.provision' — silently
        // blocks every other UPDATE pgsql_provider_control ever attempts on tenants, including the
        // new lifecycle one below. Re-scope it to apply only when the action actually is
        // company.provision, preserving its exact original behavior for that action untouched.
        $guardUsing = DB::selectOne(<<<'SQL'
            SELECT pg_get_expr(polqual, polrelid) AS expr FROM pg_policy
            WHERE polname = 'tenants_provider_first_admin_activation_guard' AND polrelid = 'tenants'::regclass
        SQL)->expr;
        $guardCheck = DB::selectOne(<<<'SQL'
            SELECT pg_get_expr(polwithcheck, polrelid) AS expr FROM pg_policy
            WHERE polname = 'tenants_provider_first_admin_activation_guard' AND polrelid = 'tenants'::regclass
        SQL)->expr;
        DB::statement('DROP POLICY tenants_provider_first_admin_activation_guard ON tenants');
        DB::statement(<<<SQL
            CREATE POLICY tenants_provider_first_admin_activation_guard
            ON public.tenants AS RESTRICTIVE FOR UPDATE TO daleel_provider_first_admin_writer
            USING (current_setting('app.provider_action', true) <> 'company.provision' OR ({$guardUsing}))
            WITH CHECK (current_setting('app.provider_action', true) <> 'company.provision' OR ({$guardCheck}))
        SQL);

        // Status transitions only, only under an approved company.lifecycle.manage operation for this
        // exact tenant (app_provider_control_tenant_allowed already binds operation/approval/requester/
        // tenant together). PROVISIONING is handled solely by the existing founder-activation policy;
        // ARCHIVED is terminal, so it is a valid WITH CHECK target but never a USING (from) state.
        DB::statement(<<<'SQL'
            CREATE POLICY tenants_provider_control_lifecycle_update ON tenants FOR UPDATE
            USING (
                app_provider_control_tenant_allowed(id)
                AND current_setting('app.provider_action', true) = 'company.lifecycle.manage'
                AND status IN ('ACTIVE', 'SUSPENDED')
            )
            WITH CHECK (
                app_provider_control_tenant_allowed(id)
                AND current_setting('app.provider_action', true) = 'company.lifecycle.manage'
                AND status IN ('ACTIVE', 'SUSPENDED', 'ARCHIVED')
            )
        SQL);

        // tenant.lifecycle.changed does not start with 'provider.', so the separate
        // security_audit_provider_event_shape_check constraint does not apply to it; only the
        // tenant-scoped insert policy and the metadata shape need to admit the new event type.
        DB::statement('DROP POLICY security_audit_provider_control_insert ON security_audit_events');
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
                        'provider.control_operation.cancelled','provider.control_operation.edited',
                        'provider.approval.requested','provider.approval.approved',
                        'provider.approval.rejected','provider.approval.revoked'))
                    OR (tenant_id IS NOT NULL AND target_id = tenant_id::text
                        AND event_type IN ('tenant.provisioning.executed','tenant.recovery.executed','tenant.lifecycle.changed')
                        AND app_provider_control_tenant_allowed(tenant_id))
                )
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
                    WHEN 'provider.control_operation.edited' THEN
                        metadata ??& ARRAY['before_digest','after_digest','revision','changed_fields']
                        AND metadata - ARRAY['before_digest','after_digest','revision','changed_fields'] = '{}'::jsonb
                        AND metadata->>'before_digest' ~ '^[a-f0-9]{64}$'
                        AND metadata->>'after_digest' ~ '^[a-f0-9]{64}$'
                        AND jsonb_typeof(metadata->'revision') = 'number'
                        AND (metadata->>'revision')::bigint >= 2
                        AND jsonb_typeof(metadata->'changed_fields') = 'array'
                        AND jsonb_array_length(metadata->'changed_fields') BETWEEN 1 AND 5
                        AND metadata->'changed_fields' <@ '["display_name","canonical_slug","timezone","founder_email","first_admin_display_name"]'::jsonb
                    WHEN 'tenant.provisioning.executed' THEN metadata = '{}'::jsonb OR (
                        metadata ?? 'founder_invitation_id' AND metadata - 'founder_invitation_id' = '{}'::jsonb
                        AND jsonb_typeof(metadata->'founder_invitation_id') = 'string'
                        AND pg_input_is_valid(metadata->>'founder_invitation_id','uuid'))
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
                    WHEN 'tenant.lifecycle.changed' THEN
                        metadata ??& ARRAY['before_status','after_status']
                        AND metadata - ARRAY['before_status','after_status'] = '{}'::jsonb
                        AND metadata->>'before_status' IN ('ACTIVE','SUSPENDED')
                        AND metadata->>'after_status' IN ('ACTIVE','SUSPENDED','ARCHIVED')
                        AND metadata->>'before_status' <> metadata->>'after_status'
                    ELSE metadata = '{}'::jsonb
                END)
        SQL);
    }

    public function down(): void
    {
        throw new RuntimeException('Forward-only migration; see docs/DECISIONS.md.');
    }

    private function runtimeRole(string $connection): string
    {
        $name = config("database.connections.{$connection}.username");
        if (! is_string($name) || ! preg_match('/^[a-z_][a-z0-9_]{0,62}$/D', $name)) {
            throw new RuntimeException("Missing or unsafe {$connection} runtime role.");
        }
        $role = DB::selectOne('SELECT rolcanlogin, rolsuper, rolbypassrls, rolcreatedb, rolcreaterole FROM pg_roles WHERE rolname = ?', [$name]);
        $enabled = static fn (mixed $value): bool => in_array($value, [true, 't', 'true', '1', 1], true);
        if (! $role || ! $enabled($role->rolcanlogin) || $enabled($role->rolsuper)
            || $enabled($role->rolbypassrls) || $enabled($role->rolcreatedb) || $enabled($role->rolcreaterole)) {
            throw new RuntimeException("Unsafe {$connection} runtime role.");
        }
        return $name;
    }
};
