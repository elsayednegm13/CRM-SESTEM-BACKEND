<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/**
 * Control: close the audit gap flagged in docs/STATUS.md -- role create/grants-changed/archive
 * were not audited. tenant_staff_security_events (migration 2026_10_11_000025) is staff-targeted
 * by schema (target_staff_user_id NOT NULL), with no row shape for a role-level event that has
 * no specific staff target. This widens it to support both: target_staff_user_id becomes
 * nullable, a new nullable target_role_id is added, and a CHECK ties exactly one of them to the
 * event's category. No RLS change needed -- the existing policy never referenced either target
 * column, only tenant/actor.
 */
return new class extends Migration
{
    public function up(): void
    {
        DB::statement('ALTER TABLE tenant_staff_security_events ALTER COLUMN target_staff_user_id DROP NOT NULL');
        DB::statement('ALTER TABLE tenant_staff_security_events ADD COLUMN target_role_id uuid NULL');
        DB::statement('ALTER TABLE tenant_staff_security_events ADD CONSTRAINT tsse_target_role_fk '.
            'FOREIGN KEY (tenant_id, target_role_id) REFERENCES roles (tenant_id, id) ON DELETE RESTRICT');

        DB::statement('ALTER TABLE tenant_staff_security_events DROP CONSTRAINT tsse_event_type_check');
        DB::statement("ALTER TABLE tenant_staff_security_events ADD CONSTRAINT tsse_event_type_check CHECK (event_type IN (".
            "'tenant_staff.created', 'tenant_staff.email_changed', 'tenant_staff.disabled', 'tenant_staff.reactivated', ".
            "'tenant_staff.password_set', 'tenant_staff.password_reset_completed', 'tenant_staff.role_assigned', ".
            "'tenant_staff.role_revoked', 'tenant_staff.permission_granted', 'tenant_staff.permission_revoked', ".
            "'tenant_staff.auth_denied', 'tenant_staff.role_created', 'tenant_staff.role_grants_changed', ".
            "'tenant_staff.role_archived'))");

        DB::statement("ALTER TABLE tenant_staff_security_events ADD CONSTRAINT tsse_target_check CHECK (".
            "(event_type IN ('tenant_staff.role_created', 'tenant_staff.role_grants_changed', 'tenant_staff.role_archived') ".
            "AND target_role_id IS NOT NULL AND target_staff_user_id IS NULL) ".
            "OR (event_type NOT IN ('tenant_staff.role_created', 'tenant_staff.role_grants_changed', 'tenant_staff.role_archived') ".
            "AND target_staff_user_id IS NOT NULL AND target_role_id IS NULL))");
    }

    public function down(): void
    {
        throw new RuntimeException('Forward-only migration; see docs/DECISIONS.md.');
    }
};
