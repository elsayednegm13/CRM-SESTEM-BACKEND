<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    public function up(): void
    {
        DB::statement(<<<'SQL'
            CREATE OR REPLACE FUNCTION app_founder_activation_lock_user(invitation_id uuid, candidate_user_id uuid)
            RETURNS TABLE(id uuid, email varchar, status varchar, email_verified_at timestamptz, auth_version integer)
            LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public
            AS $$
                SELECT u.id, u.email, u.status, u.email_verified_at, u.auth_version
                FROM public.users u
                JOIN public.tenant_founder_invitations i ON i.id = invitation_id
                WHERE current_setting('app.context_mode', true) = 'FOUNDER_ACTIVATION'
                  AND current_setting('app.founder_invitation_id', true) = invitation_id::text
                  AND u.id = candidate_user_id AND i.email_canonical = u.email
                  AND i.revoked_at IS NULL AND i.accepted_at IS NULL
                  AND i.expires_at > transaction_timestamp()
                FOR UPDATE OF u
            $$
        SQL);
        DB::statement('REVOKE ALL ON FUNCTION app_founder_activation_lock_user(uuid, uuid) FROM PUBLIC');
        DB::statement(<<<'SQL'
            CREATE OR REPLACE FUNCTION app_provider_control_lock_successor(operation_id uuid, candidate_user_id uuid)
            RETURNS TABLE(id uuid, email varchar, status varchar, email_verified_at timestamptz, auth_version integer)
            LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public
            AS $$
                SELECT u.id, u.email, u.status, u.email_verified_at, u.auth_version
                FROM public.users u
                JOIN public.provider_control_operations o ON o.id = operation_id
                JOIN public.provider_approval_requests a ON a.id = o.approval_request_id
                WHERE current_setting('app.context_mode', true) = 'PROVIDER_CONTROL'
                  AND app_provider_control_setting_uuid('app.provider_operation_id') = operation_id
                  AND app_provider_control_actor_allowed()
                  AND current_setting('app.provider_action', true) = 'company.recover'
                  AND o.action_key = 'company.recover' AND o.status = 'READY'
                  AND o.requester_provider_user_id = app_provider_control_setting_uuid('app.provider_user_id')
                  AND o.successor_user_id = candidate_user_id
                  AND o.target_tenant_id = app_provider_control_setting_uuid('app.provider_target_tenant_id')
                  AND a.status = 'APPROVED' AND a.operation_id = o.id
                  AND a.intent_digest = o.intent_digest AND a.consumed_at IS NULL
                  AND a.expires_at > transaction_timestamp()
                FOR UPDATE OF u
            $$
        SQL);
        DB::statement('REVOKE ALL ON FUNCTION app_provider_control_lock_successor(uuid, uuid) FROM PUBLIC');
    }

    public function down(): void
    {
        DB::statement('DROP FUNCTION app_provider_control_lock_successor(uuid, uuid)');
        DB::statement('DROP FUNCTION app_founder_activation_lock_user(uuid, uuid)');
    }
};
