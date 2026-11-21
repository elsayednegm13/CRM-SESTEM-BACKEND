<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    public function up(): void
    {
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
    }

    public function down(): void
    {
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
                      AND (i.accepted_at IS NULL OR i.accepted_at = transaction_timestamp())
                      AND i.revoked_at IS NULL AND i.expires_at > transaction_timestamp()
                      AND o.action_key = 'company.provision' AND o.status = 'SUCCEEDED'
                      AND o.target_tenant_id = i.tenant_id
                      AND u.status = 'ACTIVE' AND u.email_verified_at IS NOT NULL
                  )
            $$
        SQL);
    }
};
