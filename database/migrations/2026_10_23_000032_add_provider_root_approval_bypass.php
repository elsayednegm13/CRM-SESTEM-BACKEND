<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/**
 * Control: SUPER_ADMIN root bypass of the two-person approval quorum (owner decision D-4,
 * docs/DECISIONS.md). A provider.root holder's company.provision/company.recover/
 * company.lifecycle.manage request is self-approved in the same transaction it is created in
 * (ProviderControlOperationService::applyRootBypassIfHeld()) and becomes READY immediately --
 * no second reviewer is ever involved. Every bypass is still a distinct, clearly-marked audit
 * row (provider.control_operation.root_bypassed), never silent.
 *
 * No RLS change is needed: app_provider_control_tenant_allowed()'s quorum subquery
 * (`SELECT count(*) ... WHERE decision = 'APPROVE' >= required_approvals`) was never scoped to
 * an independent approver -- only the PHP-level assertApproval() excludes the requester from
 * that count, specifically to force a second human in the normal path. This control widens
 * exactly that one PHP check to also accept a single, explicitly flagged root-bypass decision.
 */
return new class extends Migration
{
    public function up(): void
    {
        DB::table('provider_capabilities')->insertOrIgnore([
            'key' => 'provider.root',
            'description' => 'Bypasses the independent-reviewer approval quorum; every use is audited',
            'status' => 'ACTIVE',
            'version' => 1,
        ]);

        DB::statement('ALTER TABLE provider_approval_decisions ADD COLUMN is_root_bypass boolean NOT NULL DEFAULT false');
        DB::statement("ALTER TABLE provider_approval_decisions ADD CONSTRAINT provider_approval_decision_root_bypass_check CHECK (NOT is_root_bypass OR decision = 'APPROVE')");

        // Exact original text (migration 2026_10_23_000031), plus one new event type.
        DB::statement('ALTER TABLE security_audit_events DROP CONSTRAINT security_audit_provider_event_shape_check');
        DB::statement(<<<'SQL'
            ALTER TABLE security_audit_events ADD CONSTRAINT security_audit_provider_event_shape_check CHECK (
                event_type NOT LIKE 'provider.%' OR (
                    category = 'PROVIDER_SECURITY' AND actor_type = 'PROVIDER_USER'
                    AND source_channel = 'PROVIDER' AND tenant_id IS NULL
                    AND pg_input_is_valid(target_id, 'uuid')
                    AND ((event_type IN ('provider.mfa.enrolled','provider.mfa.recovery_code_used')
                            AND target_type = 'provider_user' AND target_id = actor_id::text)
                        OR (event_type IN ('provider.approval.requested','provider.approval.approved',
                            'provider.approval.rejected','provider.approval.revoked') AND target_type = 'approval_request')
                        OR (event_type IN ('provider.control_operation.created','provider.control_operation.cancelled',
                            'provider.control_operation.edited') AND target_type = 'provider_control_operation')
                        OR (event_type IN ('provider.team.member_created','provider.capability.granted',
                            'provider.capability.revoked','provider.user.status_changed') AND target_type = 'provider_user')
                        OR (event_type = 'provider.control_operation.root_bypassed' AND target_type = 'approval_request'))))
        SQL);

        // Exact original text (migration 2026_10_23_000031), plus one new WHEN branch.
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
                    WHEN 'provider.team.member_created' THEN metadata = '{}'::jsonb
                    WHEN 'provider.capability.granted' THEN
                        metadata ?? 'capability_key' AND metadata - 'capability_key' = '{}'::jsonb
                        AND jsonb_typeof(metadata->'capability_key') = 'string'
                    WHEN 'provider.capability.revoked' THEN
                        metadata ?? 'capability_key' AND metadata - 'capability_key' = '{}'::jsonb
                        AND jsonb_typeof(metadata->'capability_key') = 'string'
                    WHEN 'provider.user.status_changed' THEN
                        metadata ??& ARRAY['before_status','after_status']
                        AND metadata - ARRAY['before_status','after_status'] = '{}'::jsonb
                        AND metadata->>'before_status' IN ('ACTIVE','DISABLED')
                        AND metadata->>'after_status' IN ('ACTIVE','DISABLED')
                        AND metadata->>'before_status' <> metadata->>'after_status'
                    WHEN 'provider.control_operation.root_bypassed' THEN
                        metadata ?? 'action_key' AND metadata - 'action_key' = '{}'::jsonb
                        AND metadata->>'action_key' IN ('company.provision','company.recover','company.lifecycle.manage')
                    ELSE metadata = '{}'::jsonb
                END)
        SQL);

        // provider.control_operation.root_bypassed is written on the SAME pgsql_provider_control
        // transaction as the operation/approval it bypasses (PROVIDER_CONTROL mode), not the plain
        // PROVIDER mode security_audit_provider_insert covers -- widen the provider-control policy
        // and isProviderControlMutation() (app code) instead, mirroring tenant.lifecycle.changed.
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
                        'provider.control_operation.root_bypassed',
                        'provider.approval.requested','provider.approval.approved',
                        'provider.approval.rejected','provider.approval.revoked'))
                    OR (tenant_id IS NOT NULL AND target_id = tenant_id::text
                        AND event_type IN ('tenant.provisioning.executed','tenant.recovery.executed','tenant.lifecycle.changed')
                        AND app_provider_control_tenant_allowed(tenant_id))
                )
            )
        SQL);
    }

    public function down(): void
    {
        throw new RuntimeException('Forward-only migration; see docs/DECISIONS.md.');
    }
};
