<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('tenant_staff_membership_roles', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->uuid('tenant_id');
            $table->uuid('membership_id');
            $table->uuid('role_id');
            $table->uuid('assigned_by_membership_id')->nullable();
            $table->uuid('assigned_by_provider_operation_id')->nullable();
            $table->timestampTz('assigned_at')->useCurrent();
            $table->timestampTz('revoked_at')->nullable();
            $table->uuid('revoked_by_membership_id')->nullable();
            $table->timestampsTz();

            $table->foreign('tenant_id', 'tsmr_tenant_fk')->references('id')->on('tenants')->restrictOnDelete();
            $table->foreign(['tenant_id', 'membership_id'], 'tsmr_membership_fk')
                ->references(['tenant_id', 'id'])->on('tenant_staff_memberships')->restrictOnDelete();
            $table->foreign(['tenant_id', 'role_id'], 'tsmr_role_fk')
                ->references(['tenant_id', 'id'])->on('roles')->restrictOnDelete();
            $table->foreign(['tenant_id', 'assigned_by_membership_id'], 'tsmr_assigner_fk')
                ->references(['tenant_id', 'id'])->on('tenant_staff_memberships')->restrictOnDelete();
            $table->foreign('assigned_by_provider_operation_id', 'tsmr_provider_operation_fk')
                ->references('id')->on('provider_control_operations')->restrictOnDelete();
            $table->foreign(['tenant_id', 'revoked_by_membership_id'], 'tsmr_revoker_fk')
                ->references(['tenant_id', 'id'])->on('tenant_staff_memberships')->restrictOnDelete();
            $table->index(['tenant_id', 'membership_id'], 'tsmr_member_lookup_idx');
        });

        DB::statement("ALTER TABLE tenant_staff_membership_roles ADD CONSTRAINT tsmr_assignment_actor_check CHECK (num_nonnulls(assigned_by_membership_id, assigned_by_provider_operation_id) = 1)");
        DB::statement("ALTER TABLE tenant_staff_membership_roles ADD CONSTRAINT tsmr_revocation_pair_check CHECK ((revoked_at IS NULL AND revoked_by_membership_id IS NULL) OR (revoked_at IS NOT NULL AND revoked_by_membership_id IS NOT NULL))");
        DB::statement("CREATE UNIQUE INDEX tsmr_active_role_unique ON tenant_staff_membership_roles (tenant_id, membership_id, role_id) WHERE revoked_at IS NULL");

        DB::statement(<<<'SQL'
            CREATE OR REPLACE FUNCTION tenant_staff_membership_role_guard() RETURNS trigger
            LANGUAGE plpgsql
            AS $$
            DECLARE
                role_is_active boolean;
            BEGIN
                IF TG_OP = 'INSERT' THEN
                    IF NEW.revoked_at IS NOT NULL OR NEW.revoked_by_membership_id IS NOT NULL THEN
                        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'new role assignment must begin active';
                    END IF;
                    IF NEW.assigned_by_provider_operation_id IS NOT NULL AND NOT EXISTS (
                        SELECT 1 FROM provider_control_operations operation
                        WHERE operation.id = NEW.assigned_by_provider_operation_id
                          AND operation.action_key = 'company.provision'
                          AND operation.target_tenant_id = NEW.tenant_id
                    ) THEN
                        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'provider operation does not provision this tenant';
                    END IF;
                    SELECT status = 'ACTIVE' INTO role_is_active
                    FROM roles WHERE tenant_id = NEW.tenant_id AND id = NEW.role_id;
                    IF role_is_active IS DISTINCT FROM true THEN
                        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'only an active same-tenant role may be assigned';
                    END IF;
                    RETURN NEW;
                END IF;

                IF OLD.revoked_at IS NOT NULL
                    OR NEW.revoked_at IS NULL
                    OR NEW.revoked_by_membership_id IS NULL
                    OR NEW.id IS DISTINCT FROM OLD.id
                    OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
                    OR NEW.membership_id IS DISTINCT FROM OLD.membership_id
                    OR NEW.role_id IS DISTINCT FROM OLD.role_id
                    OR NEW.assigned_by_membership_id IS DISTINCT FROM OLD.assigned_by_membership_id
                    OR NEW.assigned_by_provider_operation_id IS DISTINCT FROM OLD.assigned_by_provider_operation_id
                    OR NEW.assigned_at IS DISTINCT FROM OLD.assigned_at THEN
                    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'role assignment is immutable; revoke once instead';
                END IF;
                RETURN NEW;
            END
            $$
        SQL);
        DB::statement(<<<'SQL'
            CREATE TRIGGER tenant_staff_membership_role_guard_trigger
            BEFORE INSERT OR UPDATE ON tenant_staff_membership_roles
            FOR EACH ROW EXECUTE FUNCTION tenant_staff_membership_role_guard()
        SQL);
        DB::statement(<<<'SQL'
            CREATE OR REPLACE FUNCTION tenant_staff_membership_role_delete_deny() RETURNS trigger
            LANGUAGE plpgsql
            AS $$
            BEGIN
                RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'role assignment history is retained; revoke instead';
            END
            $$
        SQL);
        DB::statement(<<<'SQL'
            CREATE TRIGGER tenant_staff_membership_role_delete_deny_trigger
            BEFORE DELETE ON tenant_staff_membership_roles
            FOR EACH ROW EXECUTE FUNCTION tenant_staff_membership_role_delete_deny()
        SQL);

        Schema::create('tenant_staff_permission_grants', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->uuid('tenant_id');
            $table->uuid('membership_id');
            $table->string('permission_key', 100);
            $table->string('scope', 16)->nullable();
            $table->uuid('granted_by_membership_id');
            $table->timestampTz('granted_at')->useCurrent();
            $table->timestampTz('revoked_at')->nullable();
            $table->uuid('revoked_by_membership_id')->nullable();
            $table->timestampsTz();

            $table->foreign('tenant_id', 'tspg_tenant_fk')->references('id')->on('tenants')->restrictOnDelete();
            $table->foreign(['tenant_id', 'membership_id'], 'tspg_membership_fk')
                ->references(['tenant_id', 'id'])->on('tenant_staff_memberships')->restrictOnDelete();
            $table->foreign('permission_key', 'tspg_permission_fk')->references('key')->on('permissions')->restrictOnDelete();
            $table->foreign(['tenant_id', 'granted_by_membership_id'], 'tspg_grantor_fk')
                ->references(['tenant_id', 'id'])->on('tenant_staff_memberships')->restrictOnDelete();
            $table->foreign(['tenant_id', 'revoked_by_membership_id'], 'tspg_revoker_fk')
                ->references(['tenant_id', 'id'])->on('tenant_staff_memberships')->restrictOnDelete();
            $table->index(['tenant_id', 'membership_id', 'permission_key'], 'tspg_member_permission_idx');
        });

        DB::statement("ALTER TABLE tenant_staff_permission_grants ADD CONSTRAINT tspg_scope_check CHECK (scope IS NULL OR scope IN ('ALL_TENANT', 'TEAM', 'ASSIGNED', 'SELF', 'NONE'))");
        DB::statement("ALTER TABLE tenant_staff_permission_grants ADD CONSTRAINT tspg_revocation_pair_check CHECK ((revoked_at IS NULL AND revoked_by_membership_id IS NULL) OR (revoked_at IS NOT NULL AND revoked_by_membership_id IS NOT NULL))");
        DB::statement("CREATE UNIQUE INDEX tspg_active_permission_scope_unique ON tenant_staff_permission_grants (tenant_id, membership_id, permission_key, COALESCE(scope, '')) WHERE revoked_at IS NULL");

        DB::statement(<<<'SQL'
            CREATE OR REPLACE FUNCTION tenant_staff_permission_grant_guard() RETURNS trigger
            LANGUAGE plpgsql
            AS $$
            DECLARE
                permission_record record;
            BEGIN
                IF TG_OP = 'INSERT' THEN
                    IF NEW.revoked_at IS NOT NULL OR NEW.revoked_by_membership_id IS NOT NULL THEN
                        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'new direct grant must begin active';
                    END IF;
                    SELECT status, scopeable, allowed_scopes, delegable
                    INTO permission_record
                    FROM permissions WHERE key = NEW.permission_key;
                    IF NOT FOUND THEN
                        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'direct grant permission is not registered';
                    END IF;
                    IF permission_record.status <> 'ACTIVE' OR permission_record.delegable IS DISTINCT FROM true THEN
                        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'direct grant requires an active delegable catalog permission';
                    END IF;
                    IF (permission_record.scopeable AND (NEW.scope IS NULL OR NOT (permission_record.allowed_scopes @> jsonb_build_array(NEW.scope))))
                        OR (NOT permission_record.scopeable AND NEW.scope IS NOT NULL) THEN
                        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'direct grant scope is invalid for the permission catalog';
                    END IF;
                    RETURN NEW;
                END IF;

                IF OLD.revoked_at IS NOT NULL
                    OR NEW.revoked_at IS NULL
                    OR NEW.revoked_by_membership_id IS NULL
                    OR NEW.id IS DISTINCT FROM OLD.id
                    OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
                    OR NEW.membership_id IS DISTINCT FROM OLD.membership_id
                    OR NEW.permission_key IS DISTINCT FROM OLD.permission_key
                    OR NEW.scope IS DISTINCT FROM OLD.scope
                    OR NEW.granted_by_membership_id IS DISTINCT FROM OLD.granted_by_membership_id
                    OR NEW.granted_at IS DISTINCT FROM OLD.granted_at THEN
                    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'direct grant is immutable; revoke once instead';
                END IF;
                RETURN NEW;
            END
            $$
        SQL);
        DB::statement(<<<'SQL'
            CREATE TRIGGER tenant_staff_permission_grant_guard_trigger
            BEFORE INSERT OR UPDATE ON tenant_staff_permission_grants
            FOR EACH ROW EXECUTE FUNCTION tenant_staff_permission_grant_guard()
        SQL);
        DB::statement(<<<'SQL'
            CREATE OR REPLACE FUNCTION tenant_staff_permission_grant_delete_deny() RETURNS trigger
            LANGUAGE plpgsql
            AS $$
            BEGIN
                RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'direct grant history is retained; revoke instead';
            END
            $$
        SQL);
        DB::statement(<<<'SQL'
            CREATE TRIGGER tenant_staff_permission_grant_delete_deny_trigger
            BEFORE DELETE ON tenant_staff_permission_grants
            FOR EACH ROW EXECUTE FUNCTION tenant_staff_permission_grant_delete_deny()
        SQL);

        $staffActor = "app_rls_context_mode() = 'TENANT' AND tenant_id = app_rls_current_tenant_id() AND EXISTS (SELECT 1 FROM tenant_staff_memberships actor WHERE actor.tenant_id = tenant_staff_membership_roles.tenant_id AND actor.staff_user_id = app_rls_current_user_id() AND actor.status = 'ACTIVE')";
        DB::statement('ALTER TABLE tenant_staff_membership_roles ENABLE ROW LEVEL SECURITY');
        DB::statement('ALTER TABLE tenant_staff_membership_roles FORCE ROW LEVEL SECURITY');
        DB::statement("CREATE POLICY tenant_staff_membership_roles_actor_scope ON tenant_staff_membership_roles FOR ALL USING ({$staffActor}) WITH CHECK ({$staffActor} AND ((revoked_at IS NULL AND assigned_by_membership_id IN (SELECT actor.id FROM tenant_staff_memberships actor WHERE actor.tenant_id = tenant_staff_membership_roles.tenant_id AND actor.staff_user_id = app_rls_current_user_id() AND actor.status = 'ACTIVE') AND assigned_by_provider_operation_id IS NULL) OR (revoked_at IS NOT NULL AND revoked_by_membership_id IN (SELECT actor.id FROM tenant_staff_memberships actor WHERE actor.tenant_id = tenant_staff_membership_roles.tenant_id AND actor.staff_user_id = app_rls_current_user_id() AND actor.status = 'ACTIVE'))))");
        DB::statement('REVOKE ALL ON TABLE tenant_staff_membership_roles FROM PUBLIC');

        $grantActor = "app_rls_context_mode() = 'TENANT' AND tenant_id = app_rls_current_tenant_id() AND EXISTS (SELECT 1 FROM tenant_staff_memberships actor WHERE actor.tenant_id = tenant_staff_permission_grants.tenant_id AND actor.staff_user_id = app_rls_current_user_id() AND actor.status = 'ACTIVE')";
        DB::statement('ALTER TABLE tenant_staff_permission_grants ENABLE ROW LEVEL SECURITY');
        DB::statement('ALTER TABLE tenant_staff_permission_grants FORCE ROW LEVEL SECURITY');
        DB::statement("CREATE POLICY tenant_staff_permission_grants_actor_scope ON tenant_staff_permission_grants FOR ALL USING ({$grantActor}) WITH CHECK ({$grantActor} AND ((revoked_at IS NULL AND granted_by_membership_id IN (SELECT actor.id FROM tenant_staff_memberships actor WHERE actor.tenant_id = tenant_staff_permission_grants.tenant_id AND actor.staff_user_id = app_rls_current_user_id() AND actor.status = 'ACTIVE')) OR (revoked_at IS NOT NULL AND revoked_by_membership_id IN (SELECT actor.id FROM tenant_staff_memberships actor WHERE actor.tenant_id = tenant_staff_permission_grants.tenant_id AND actor.staff_user_id = app_rls_current_user_id() AND actor.status = 'ACTIVE'))))");
        DB::statement('REVOKE ALL ON TABLE tenant_staff_permission_grants FROM PUBLIC');
    }

    public function down(): void
    {
        throw new LogicException('FND-ID-01 migrations are forward-only; restore from an approved snapshot instead.');
    }
};
