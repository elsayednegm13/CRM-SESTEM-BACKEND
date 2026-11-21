<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    public function up(): void
    {
        $provider = $this->runtimeRole('pgsql_provider');
        $control = $this->runtimeRole('pgsql_provider_control');
        if ($provider === $control) {
            throw new RuntimeException('Provider authentication and control roles must differ.');
        }

        DB::transaction(function () use ($provider, $control): void {
            $bad = DB::selectOne(<<<'SQL'
                SELECT count(*) AS count FROM provider_control_operations o
                LEFT JOIN provider_approval_requests a ON a.id = o.approval_request_id
                WHERE o.action_key = 'company.provision' AND (
                    a.id IS NULL OR a.operation_id IS DISTINCT FROM o.id
                    OR a.requester_provider_user_id IS DISTINCT FROM o.requester_provider_user_id
                    OR a.target_id IS DISTINCT FROM o.target_tenant_id
                    OR a.action_key IS DISTINCT FROM o.action_key
                    OR a.intent_digest IS DISTINCT FROM o.intent_digest
                    OR (o.status = 'READY' AND a.status <> 'APPROVED')
                    OR (o.status = 'SUCCEEDED' AND (a.status <> 'APPROVED' OR a.consumed_operation_id IS DISTINCT FROM o.id))
                )
            SQL);
            if ((int) $bad->count !== 0) {
                throw new RuntimeException('Legacy provision operation/approval binding contradicts revision-1 backfill.');
            }
            $badDecisions = DB::selectOne(<<<'SQL'
                SELECT count(*) AS count FROM provider_approval_decisions d
                JOIN provider_approval_requests a ON a.id = d.approval_request_id
                LEFT JOIN provider_control_operations o ON o.id = a.operation_id
                WHERE a.action_key = 'company.provision' AND (
                    o.id IS NULL OR o.action_key <> 'company.provision'
                    OR o.intent_digest IS DISTINCT FROM a.intent_digest
                    OR (d.decision = 'APPROVE' AND a.status NOT IN ('APPROVED','REVOKED'))
                    OR (d.decision = 'REJECT' AND a.status <> 'REJECTED')
                    OR (d.decision = 'REVOKE' AND a.status <> 'REVOKED')
                )
            SQL);
            if ((int) $badDecisions->count !== 0) {
                throw new RuntimeException('Legacy provision decision contradicts revision-1 backfill.');
            }

            DB::statement('ALTER TABLE provider_control_operations ADD COLUMN current_revision bigint NOT NULL DEFAULT 1 CHECK (current_revision >= 1)');
            DB::statement('ALTER TABLE provider_approval_requests ADD COLUMN review_revision bigint NULL CHECK (review_revision >= 1)');
            DB::statement('ALTER TABLE provider_approval_decisions ADD COLUMN decision_revision bigint NULL CHECK (decision_revision >= 1)');
            DB::statement(<<<'SQL'
                UPDATE provider_approval_requests a SET review_revision = 1
                FROM provider_control_operations o
                WHERE a.operation_id = o.id AND o.action_key = 'company.provision'
            SQL);
            DB::statement(<<<'SQL'
                UPDATE provider_approval_decisions d SET decision_revision = 1
                FROM provider_approval_requests a JOIN provider_control_operations o ON o.id = a.operation_id
                WHERE d.approval_request_id = a.id AND o.action_key = 'company.provision'
            SQL);

            DB::statement(<<<'SQL'
                CREATE TABLE provider_provision_revisions (
                    operation_id uuid NOT NULL REFERENCES provider_control_operations(id) ON DELETE RESTRICT,
                    revision bigint NOT NULL CHECK (revision >= 1),
                    intent_digest char(64) NOT NULL CHECK (intent_digest ~ '^[a-f0-9]{64}$'),
                    requester_provider_user_id uuid NOT NULL REFERENCES provider_users(id) ON DELETE RESTRICT,
                    changed_fields jsonb NOT NULL CHECK (
                        jsonb_typeof(changed_fields) = 'array'
                        AND jsonb_array_length(changed_fields) <= 5
                        AND changed_fields <@ '["display_name","canonical_slug","timezone","founder_email","first_admin_display_name"]'::jsonb
                    ),
                    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                    PRIMARY KEY (operation_id, revision)
                )
            SQL);
            DB::statement(<<<'SQL'
                INSERT INTO provider_provision_revisions
                    (operation_id, revision, intent_digest, requester_provider_user_id, changed_fields, created_at)
                SELECT id, 1, intent_digest, requester_provider_user_id, '[]'::jsonb, created_at
                FROM provider_control_operations WHERE action_key = 'company.provision'
            SQL);
            DB::statement('REVOKE ALL ON provider_provision_revisions FROM PUBLIC');
            DB::statement(<<<'SQL'
                CREATE OR REPLACE FUNCTION deny_provider_provision_revision_mutation() RETURNS trigger
                LANGUAGE plpgsql SECURITY INVOKER AS $$
                BEGIN
                    RAISE EXCEPTION 'Provider provision revision history is immutable' USING ERRCODE = '55000';
                END
                $$
            SQL);
            DB::statement('REVOKE ALL ON FUNCTION deny_provider_provision_revision_mutation() FROM PUBLIC');
            DB::statement(<<<'SQL'
                CREATE TRIGGER provider_provision_revision_immutable
                BEFORE UPDATE OR DELETE ON provider_provision_revisions
                FOR EACH ROW EXECUTE FUNCTION deny_provider_provision_revision_mutation()
            SQL);
            DB::statement('ALTER TABLE provider_provision_revisions ENABLE ROW LEVEL SECURITY');
            DB::statement('ALTER TABLE provider_provision_revisions FORCE ROW LEVEL SECURITY');
            DB::statement("CREATE POLICY provider_provision_revision_read ON provider_provision_revisions FOR SELECT TO {$control} USING (current_setting('app.context_mode', true) = 'PROVIDER_CONTROL' AND current_setting('app.provider_capability', true) = 'company.provision' AND app_provider_control_actor_allowed() AND requester_provider_user_id = app_provider_control_setting_uuid('app.provider_user_id') AND EXISTS (SELECT 1 FROM provider_control_operations o WHERE o.id = provider_provision_revisions.operation_id AND o.action_key = 'company.provision' AND o.requester_provider_user_id = provider_provision_revisions.requester_provider_user_id))");
            DB::statement("CREATE POLICY provider_provision_revision_insert ON provider_provision_revisions FOR INSERT TO {$control} WITH CHECK (current_setting('app.context_mode', true) = 'PROVIDER_CONTROL' AND current_setting('app.provider_capability', true) = 'company.provision' AND app_provider_control_actor_allowed() AND requester_provider_user_id = app_provider_control_setting_uuid('app.provider_user_id') AND EXISTS (SELECT 1 FROM provider_control_operations o WHERE o.id = provider_provision_revisions.operation_id AND o.action_key = 'company.provision' AND o.requester_provider_user_id = provider_provision_revisions.requester_provider_user_id AND o.status = 'PENDING_APPROVAL' AND o.current_revision = provider_provision_revisions.revision AND o.intent_digest = provider_provision_revisions.intent_digest))");
            DB::statement("GRANT SELECT (operation_id, revision, intent_digest, requester_provider_user_id, changed_fields, created_at), INSERT (operation_id, revision, intent_digest, requester_provider_user_id, changed_fields, created_at) ON provider_provision_revisions TO {$control}");
            DB::statement("GRANT SELECT (id, approval_request_id, display_name, canonical_slug, timezone, founder_email, first_admin_display_name, intent_digest, current_revision, status, expires_at) ON provider_control_operations TO {$provider}");

            $this->extendAudit();
        });
    }

    public function down(): void
    {
        throw new RuntimeException('Versioned Provider approval history is forward-only; use a reviewed forward correction.');
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

    private function extendAudit(): void
    {
        DB::statement('DROP POLICY security_audit_provider_control_insert ON security_audit_events');
        DB::statement(<<<'SQL'
            CREATE POLICY security_audit_provider_control_insert ON security_audit_events FOR INSERT
            WITH CHECK (
                outcome = 'SUCCESS' AND actor_type = 'PROVIDER_USER'
                AND actor_id = app_provider_control_setting_uuid('app.provider_user_id')
                AND source_channel = 'PROVIDER'
                AND current_setting('app.context_mode', true) IN ('PROVIDER_CONTROL','PROVIDER_CONTROL_REQUEST')
                AND app_provider_control_actor_allowed()
                AND ((tenant_id IS NULL AND event_type IN (
                    'provider.control_operation.created','provider.control_operation.cancelled',
                    'provider.control_operation.edited','provider.approval.requested',
                    'provider.approval.approved','provider.approval.rejected','provider.approval.revoked'))
                    OR (tenant_id IS NOT NULL AND target_id = tenant_id::text
                        AND event_type IN ('tenant.provisioning.executed','tenant.recovery.executed')
                        AND app_provider_control_tenant_allowed(tenant_id)))
            )
        SQL);
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
                            'provider.control_operation.edited') AND target_type = 'provider_control_operation'))))
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
                    ELSE metadata = '{}'::jsonb
                END)
        SQL);
    }
};
