<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    public function up(): void
    {
        DB::statement(<<<'SQL'
            CREATE OR REPLACE FUNCTION app_provider_control_actor_allowed() RETURNS boolean
            LANGUAGE plpgsql STABLE SECURITY INVOKER
            AS $$
            BEGIN
                IF current_setting('app.context_mode', true) IS NULL
                   OR current_setting('app.context_mode', true) NOT IN ('PROVIDER_CONTROL', 'PROVIDER_CONTROL_REQUEST') THEN
                    RETURN FALSE;
                END IF;

                RETURN EXISTS (
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
                );
            END
            $$
        SQL);

        DB::statement(<<<'SQL'
            CREATE OR REPLACE FUNCTION app_provider_control_tenant_allowed(candidate_tenant_id uuid) RETURNS boolean
            LANGUAGE plpgsql STABLE SECURITY INVOKER
            AS $$
            BEGIN
                IF current_setting('app.context_mode', true) IS DISTINCT FROM 'PROVIDER_CONTROL' THEN
                    RETURN FALSE;
                END IF;

                IF NOT app_provider_control_actor_allowed() THEN
                    RETURN FALSE;
                END IF;

                RETURN EXISTS (
                    SELECT 1
                    FROM provider_control_operations o
                    JOIN provider_approval_requests a ON a.id = o.approval_request_id
                    WHERE o.id = app_provider_control_setting_uuid('app.provider_operation_id')
                      AND o.action_key = current_setting('app.provider_action', true)
                      AND o.target_tenant_id = candidate_tenant_id
                      AND o.requester_provider_user_id = app_provider_control_setting_uuid('app.provider_user_id')
                      AND o.status IN ('READY', 'SUCCEEDED') AND o.expires_at > transaction_timestamp()
                      AND a.id = app_provider_control_setting_uuid('app.provider_approval_id')
                      AND a.operation_id = o.id AND a.action_key = o.action_key
                      AND a.target_id = o.target_tenant_id AND a.intent_digest = o.intent_digest
                      AND a.status = 'APPROVED' AND a.expires_at > transaction_timestamp()
                      AND (a.consumed_at IS NULL OR a.consumed_operation_id = o.id)
                      AND (SELECT count(*) FROM provider_approval_decisions d
                           WHERE d.approval_request_id = a.id AND d.decision = 'APPROVE') >= a.required_approvals
                      AND NOT EXISTS (SELECT 1 FROM provider_approval_decisions d
                           WHERE d.approval_request_id = a.id AND d.decision IN ('REJECT', 'REVOKE'))
                );
            END
            $$
        SQL);

        DB::statement(<<<'SQL'
            CREATE OR REPLACE FUNCTION app_provider_control_request_tenant_allowed(candidate_tenant_id uuid) RETURNS boolean
            LANGUAGE plpgsql STABLE SECURITY INVOKER
            AS $$
            BEGIN
                IF current_setting('app.context_mode', true) IS DISTINCT FROM 'PROVIDER_CONTROL_REQUEST'
                   OR current_setting('app.provider_action', true) IS DISTINCT FROM 'company.recover'
                   OR app_provider_control_setting_uuid('app.provider_target_tenant_id') IS DISTINCT FROM candidate_tenant_id THEN
                    RETURN FALSE;
                END IF;

                RETURN app_provider_control_actor_allowed();
            END
            $$
        SQL);

        DB::statement(<<<'SQL'
            CREATE OR REPLACE FUNCTION app_founder_activation_tenant_allowed(candidate_tenant_id uuid) RETURNS boolean
            LANGUAGE plpgsql STABLE SECURITY INVOKER
            AS $$
            BEGIN
                IF current_setting('app.context_mode', true) IS DISTINCT FROM 'FOUNDER_ACTIVATION' THEN
                    RETURN FALSE;
                END IF;

                RETURN EXISTS (
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
                );
            END
            $$
        SQL);
    }

    public function down(): void
    {
        throw new RuntimeException('The guarded RLS helpers are a security correction and cannot be reverted automatically.');
    }
};
