<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/**
 * Control: provider team & capability administration.
 * Until now no HTTP path could create a provider_user or grant/revoke a
 * provider_capabilities row; the only path was the disposable test fixtures.
 * This control adds the 'provider.team.manage' capability and widens the
 * (non-RLS; provider_users/provider_user_capabilities have none, by design —
 * see docs/PROVIDER_SECURITY.md) audit contracts to admit team-management
 * events alongside the existing self-service ones (MFA, approvals).
 * See ProviderTeamService and App\Console\Commands\BootstrapProviderRoot.
 */
return new class extends Migration
{
    public function up(): void
    {
        DB::table('provider_capabilities')->insertOrIgnore([
            'key' => 'provider.team.manage',
            'description' => 'Create provider team members and grant/revoke their capabilities',
            'status' => 'ACTIVE',
            'version' => 1,
        ]);

        // provider_users/provider_user_capabilities carry no RLS (see docs/PROVIDER_SECURITY.md);
        // the real enforcement for these new actions is ProviderTeamService's PHP-level capability
        // + step-up checks. Production deployment must grant pgsql_provider explicit column
        // privileges on these tables (see tools/dev-db/bootstrap-roles.sql); migrations never carry
        // runtime credentials, so that grant cannot be automated here.

        // Exact original text (migration 2026_10_07_000010), plus one new OR branch for the
        // team-management events below. Unlike the MFA branch, these target a DIFFERENT
        // provider_user than the actor, so they carry no target_id = actor_id constraint.
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
                            'provider.capability.revoked','provider.user.status_changed') AND target_type = 'provider_user'))))
        SQL);

        // Exact original text (migration 2026_10_23_000030), plus four new WHEN branches.
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
                    ELSE metadata = '{}'::jsonb
                END)
        SQL);

        // Exact original text (migration 2026_10_07_000010), plus the four new event types.
        DB::statement('DROP POLICY security_audit_provider_insert ON security_audit_events');
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
                    'provider.approval.rejected','provider.approval.revoked',
                    'provider.team.member_created','provider.capability.granted',
                    'provider.capability.revoked','provider.user.status_changed')
            )
        SQL);
    }

    public function down(): void
    {
        throw new RuntimeException('Forward-only migration; see docs/DECISIONS.md.');
    }
};
