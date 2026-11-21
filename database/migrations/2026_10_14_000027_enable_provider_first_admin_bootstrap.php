<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        DB::statement(<<<'SQL'
            DO $roles$
            DECLARE
                role_oid oid;
                unsafe_role boolean;
            BEGIN
                SELECT oid,
                       rolcanlogin OR rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolreplication
                INTO role_oid, unsafe_role
                FROM pg_catalog.pg_roles
                WHERE rolname = 'daleel_provider_first_admin_writer';

                IF role_oid IS NULL OR unsafe_role IS DISTINCT FROM false THEN
                    RAISE EXCEPTION 'Required first-admin writer group role is absent or unsafe'
                        USING ERRCODE = '55000';
                END IF;

                IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members WHERE member = role_oid) THEN
                    RAISE EXCEPTION 'First-admin writer group role must not inherit any other database role'
                        USING ERRCODE = '55000';
                END IF;

                IF has_schema_privilege('daleel_provider_first_admin_writer', 'public', 'CREATE') THEN
                    RAISE EXCEPTION 'First-admin writer group role must not create objects in public'
                        USING ERRCODE = '55000';
                END IF;

                IF EXISTS (
                    SELECT 1 FROM information_schema.table_privileges
                    WHERE grantee = 'daleel_provider_first_admin_writer' AND table_schema = 'public'
                      AND table_name IN ('tenants', 'roles', 'role_permissions', 'tenant_staff_users',
                          'tenant_staff_memberships', 'tenant_staff_membership_roles', 'tenant_staff_security_events',
                          'role_templates', 'role_template_permissions', 'permissions')
                ) OR EXISTS (
                    SELECT 1 FROM information_schema.column_privileges
                    WHERE grantee = 'daleel_provider_first_admin_writer' AND table_schema = 'public'
                      AND table_name IN ('tenants', 'roles', 'role_permissions', 'tenant_staff_users',
                          'tenant_staff_memberships', 'tenant_staff_membership_roles', 'tenant_staff_security_events',
                          'role_templates', 'role_template_permissions', 'permissions')
                ) THEN
                    RAISE EXCEPTION 'First-admin writer group role has unexpected pre-existing table or column privileges'
                        USING ERRCODE = '55000';
                END IF;
            END
            $roles$
        SQL);

        Schema::table('provider_control_operations', function (Blueprint $table): void {
            $table->string('first_admin_display_name', 160)->nullable();
        });
        DB::statement("ALTER TABLE provider_control_operations ADD CONSTRAINT provider_control_first_admin_name_check CHECK (first_admin_display_name IS NULL OR length(btrim(first_admin_display_name)) BETWEEN 1 AND 160)");

        DB::statement('GRANT USAGE ON SCHEMA public TO daleel_provider_first_admin_writer');
        DB::statement('GRANT SELECT (id, slug, status) ON public.tenants TO daleel_provider_first_admin_writer');
        DB::statement('GRANT UPDATE (status, updated_at) ON public.tenants TO daleel_provider_first_admin_writer');
        DB::statement('GRANT SELECT (id, tenant_id, canonical_email, display_email, display_name, status, auth_version, created_at, updated_at) ON public.tenant_staff_users TO daleel_provider_first_admin_writer');
        DB::statement('GRANT INSERT (id, tenant_id, canonical_email, display_email, display_name, password_hash, status, auth_version, created_at, updated_at) ON public.tenant_staff_users TO daleel_provider_first_admin_writer');
        DB::statement('GRANT SELECT (id, tenant_id, staff_user_id, status, authorization_version, created_by_provider_operation_id) ON public.tenant_staff_memberships TO daleel_provider_first_admin_writer');
        DB::statement('GRANT INSERT (id, tenant_id, staff_user_id, status, authorization_version, joined_at, created_by_membership_id, created_by_provider_operation_id, created_at, updated_at) ON public.tenant_staff_memberships TO daleel_provider_first_admin_writer');
        DB::statement('GRANT SELECT (id, tenant_id, membership_id, role_id, assigned_by_membership_id, assigned_by_provider_operation_id, revoked_at) ON public.tenant_staff_membership_roles TO daleel_provider_first_admin_writer');
        DB::statement('GRANT INSERT (id, tenant_id, membership_id, role_id, assigned_by_membership_id, assigned_by_provider_operation_id, assigned_at, revoked_at, revoked_by_membership_id, created_at, updated_at) ON public.tenant_staff_membership_roles TO daleel_provider_first_admin_writer');
        DB::statement('GRANT SELECT (id, tenant_id, display_name, normalized_name, status, source_template_id, version, archived_at) ON public.roles TO daleel_provider_first_admin_writer');
        DB::statement('GRANT INSERT (id, tenant_id, display_name, normalized_name, status, source_template_id, version, archived_at, created_at, updated_at) ON public.roles TO daleel_provider_first_admin_writer');
        DB::statement('GRANT SELECT (tenant_id, role_id, permission_key, scope) ON public.role_permissions TO daleel_provider_first_admin_writer');
        DB::statement('GRANT INSERT (tenant_id, role_id, permission_key, scope) ON public.role_permissions TO daleel_provider_first_admin_writer');
        DB::statement('GRANT SELECT (id, code, version, status) ON public.role_templates TO daleel_provider_first_admin_writer');
        DB::statement('GRANT SELECT (template_id, permission_key, scope) ON public.role_template_permissions TO daleel_provider_first_admin_writer');
        DB::statement('GRANT SELECT (key, status, scopeable, allowed_scopes, delegable) ON public.permissions TO daleel_provider_first_admin_writer');
        DB::statement('GRANT INSERT (id, occurred_at, tenant_id, event_type, outcome, request_id, actor_membership_id, provider_operation_id, target_staff_user_id, metadata) ON public.tenant_staff_security_events TO daleel_provider_first_admin_writer');

        DB::statement(<<<'SQL'
            CREATE POLICY tenants_provider_first_admin_insert_guard
            ON public.tenants AS RESTRICTIVE FOR INSERT TO daleel_provider_first_admin_writer
            WITH CHECK (
                current_setting('app.context_mode', true) = 'PROVIDER_CONTROL'
                AND current_setting('app.provider_action', true) = 'company.provision'
                AND app_provider_control_tenant_allowed(id)
                AND status = 'PROVISIONING' AND legal_name IS NULL
                AND default_locale = 'en' AND archived_at IS NULL
                AND EXISTS (
                    SELECT 1 FROM public.provider_control_operations operation
                    WHERE operation.id = app_provider_control_setting_uuid('app.provider_operation_id')
                      AND operation.action_key = 'company.provision'
                      AND operation.status = 'READY'
                      AND operation.target_tenant_id = tenants.id
                      AND operation.display_name = tenants.display_name
                      AND operation.canonical_slug = tenants.slug
                      AND operation.timezone = tenants.timezone
                      AND operation.expires_at > transaction_timestamp()
                )
            )
        SQL);

        DB::statement(<<<'SQL'
            CREATE POLICY roles_provider_first_admin_insert_guard
            ON public.roles AS RESTRICTIVE FOR INSERT TO daleel_provider_first_admin_writer
            WITH CHECK (
                current_setting('app.context_mode', true) = 'PROVIDER_CONTROL'
                AND current_setting('app.provider_action', true) = 'company.provision'
                AND app_provider_control_tenant_allowed(tenant_id)
                AND normalized_name = 'company_admin' AND status = 'ACTIVE'
                AND version = 1 AND archived_at IS NULL
                AND EXISTS (
                    SELECT 1 FROM public.provider_control_operations operation
                    JOIN public.role_templates template
                      ON template.id = roles.source_template_id
                    WHERE operation.id = app_provider_control_setting_uuid('app.provider_operation_id')
                      AND operation.action_key = 'company.provision'
                      AND operation.status = 'READY'
                      AND operation.target_tenant_id = roles.tenant_id
                      AND template.code = 'company_admin' AND template.version = 1
                      AND template.status = 'ACTIVE'
                )
            )
        SQL);

        DB::statement(<<<'SQL'
            CREATE POLICY role_permissions_provider_first_admin_insert_guard
            ON public.role_permissions AS RESTRICTIVE FOR INSERT TO daleel_provider_first_admin_writer
            WITH CHECK (
                current_setting('app.context_mode', true) = 'PROVIDER_CONTROL'
                AND current_setting('app.provider_action', true) = 'company.provision'
                AND app_provider_control_tenant_allowed(tenant_id)
                AND EXISTS (
                    SELECT 1
                    FROM public.provider_control_operations operation
                    JOIN public.roles role
                      ON role.tenant_id = role_permissions.tenant_id
                     AND role.id = role_permissions.role_id
                    JOIN public.role_templates template
                      ON template.id = role.source_template_id
                    JOIN public.role_template_permissions template_grant
                      ON template_grant.template_id = template.id
                     AND template_grant.permission_key = role_permissions.permission_key
                     AND template_grant.scope IS NOT DISTINCT FROM role_permissions.scope
                    WHERE operation.id = app_provider_control_setting_uuid('app.provider_operation_id')
                      AND operation.action_key = 'company.provision'
                      AND operation.status = 'READY'
                      AND operation.target_tenant_id = role_permissions.tenant_id
                      AND role.normalized_name = 'company_admin' AND role.status = 'ACTIVE'
                      AND role.version = 1 AND role.archived_at IS NULL
                      AND template.code = 'company_admin' AND template.version = 1
                      AND template.status = 'ACTIVE'
                )
            )
        SQL);

        DB::statement(<<<'SQL'
            CREATE POLICY tenant_staff_users_provider_first_admin_select
            ON public.tenant_staff_users FOR SELECT TO daleel_provider_first_admin_writer
            USING (
                current_setting('app.context_mode', true) = 'PROVIDER_CONTROL'
                AND current_setting('app.provider_action', true) = 'company.provision'
                AND app_provider_control_tenant_allowed(tenant_id)
                AND EXISTS (
                    SELECT 1 FROM public.provider_control_operations operation
                    WHERE operation.id = app_provider_control_setting_uuid('app.provider_operation_id')
                      AND operation.action_key = 'company.provision' AND operation.status IN ('READY', 'SUCCEEDED')
                      AND operation.target_tenant_id = tenant_staff_users.tenant_id
                      AND operation.founder_email = tenant_staff_users.canonical_email
                      AND operation.first_admin_display_name = tenant_staff_users.display_name
                )
            )
        SQL);
        DB::statement(<<<'SQL'
            CREATE POLICY tenant_staff_users_provider_first_admin_insert
            ON public.tenant_staff_users FOR INSERT TO daleel_provider_first_admin_writer
            WITH CHECK (
                current_setting('app.context_mode', true) = 'PROVIDER_CONTROL'
                AND current_setting('app.provider_action', true) = 'company.provision'
                AND app_provider_control_tenant_allowed(tenant_id)
                AND status = 'ACTIVE' AND auth_version = 1
                AND EXISTS (
                    SELECT 1 FROM public.provider_control_operations operation
                    WHERE operation.id = app_provider_control_setting_uuid('app.provider_operation_id')
                      AND operation.action_key = 'company.provision' AND operation.status = 'READY'
                      AND operation.target_tenant_id = tenant_staff_users.tenant_id
                      AND operation.founder_email = tenant_staff_users.canonical_email
                      AND operation.first_admin_display_name = tenant_staff_users.display_name
                )
            )
        SQL);

        DB::statement(<<<'SQL'
            CREATE POLICY tenant_staff_memberships_provider_first_admin_select
            ON public.tenant_staff_memberships FOR SELECT TO daleel_provider_first_admin_writer
            USING (
                current_setting('app.context_mode', true) = 'PROVIDER_CONTROL'
                AND current_setting('app.provider_action', true) = 'company.provision'
                AND app_provider_control_tenant_allowed(tenant_id)
                AND created_by_provider_operation_id = app_provider_control_setting_uuid('app.provider_operation_id')
                AND created_by_membership_id IS NULL
                AND status = 'ACTIVE'
                AND EXISTS (
                    SELECT 1 FROM public.provider_control_operations operation
                    WHERE operation.id = created_by_provider_operation_id
                      AND operation.action_key = 'company.provision' AND operation.status IN ('READY', 'SUCCEEDED')
                      AND operation.target_tenant_id = tenant_staff_memberships.tenant_id
                      AND EXISTS (
                          SELECT 1 FROM public.tenant_staff_users staff
                          WHERE staff.tenant_id = tenant_staff_memberships.tenant_id
                            AND staff.id = tenant_staff_memberships.staff_user_id
                            AND staff.canonical_email = operation.founder_email
                            AND staff.display_name = operation.first_admin_display_name
                      )
                )
            )
        SQL);
        DB::statement(<<<'SQL'
            CREATE POLICY tenant_staff_memberships_provider_first_admin_insert
            ON public.tenant_staff_memberships FOR INSERT TO daleel_provider_first_admin_writer
            WITH CHECK (
                current_setting('app.context_mode', true) = 'PROVIDER_CONTROL'
                AND current_setting('app.provider_action', true) = 'company.provision'
                AND app_provider_control_tenant_allowed(tenant_id)
                AND created_by_provider_operation_id = app_provider_control_setting_uuid('app.provider_operation_id')
                AND created_by_membership_id IS NULL AND status = 'ACTIVE'
                AND authorization_version = 1
                AND EXISTS (
                    SELECT 1 FROM public.provider_control_operations operation
                    JOIN public.tenant_staff_users staff
                      ON staff.tenant_id = tenant_staff_memberships.tenant_id
                     AND staff.id = tenant_staff_memberships.staff_user_id
                    WHERE operation.id = created_by_provider_operation_id
                      AND operation.action_key = 'company.provision' AND operation.status = 'READY'
                      AND operation.target_tenant_id = tenant_staff_memberships.tenant_id
                      AND staff.status = 'ACTIVE'
                      AND staff.canonical_email = operation.founder_email
                      AND staff.display_name = operation.first_admin_display_name
                )
            )
        SQL);

        DB::statement(<<<'SQL'
            CREATE POLICY tenant_staff_membership_roles_provider_first_admin_select
            ON public.tenant_staff_membership_roles FOR SELECT TO daleel_provider_first_admin_writer
            USING (
                current_setting('app.context_mode', true) = 'PROVIDER_CONTROL'
                AND current_setting('app.provider_action', true) = 'company.provision'
                AND app_provider_control_tenant_allowed(tenant_id)
                AND assigned_by_provider_operation_id = app_provider_control_setting_uuid('app.provider_operation_id')
                AND assigned_by_membership_id IS NULL AND revoked_at IS NULL
            )
        SQL);
        DB::statement(<<<'SQL'
            CREATE POLICY tenant_staff_membership_roles_provider_first_admin_insert
            ON public.tenant_staff_membership_roles FOR INSERT TO daleel_provider_first_admin_writer
            WITH CHECK (
                current_setting('app.context_mode', true) = 'PROVIDER_CONTROL'
                AND current_setting('app.provider_action', true) = 'company.provision'
                AND app_provider_control_tenant_allowed(tenant_id)
                AND assigned_by_provider_operation_id = app_provider_control_setting_uuid('app.provider_operation_id')
                AND assigned_by_membership_id IS NULL AND revoked_at IS NULL
                AND revoked_by_membership_id IS NULL
                AND EXISTS (
                    SELECT 1 FROM public.provider_control_operations operation
                    JOIN public.tenant_staff_memberships membership
                      ON membership.tenant_id = tenant_staff_membership_roles.tenant_id
                     AND membership.id = tenant_staff_membership_roles.membership_id
                    JOIN public.roles role
                      ON role.tenant_id = tenant_staff_membership_roles.tenant_id
                     AND role.id = tenant_staff_membership_roles.role_id
                    JOIN public.role_templates template ON template.id = role.source_template_id
                    WHERE operation.id = assigned_by_provider_operation_id
                      AND operation.action_key = 'company.provision' AND operation.status = 'READY'
                      AND operation.target_tenant_id = tenant_staff_membership_roles.tenant_id
                      AND membership.status = 'ACTIVE'
                      AND membership.created_by_provider_operation_id = operation.id
                      AND role.normalized_name = 'company_admin' AND role.status = 'ACTIVE'
                      AND role.version = 1 AND role.archived_at IS NULL
                      AND template.code = 'company_admin' AND template.version = 1
                      AND template.status = 'ACTIVE'
                )
            )
        SQL);

        DB::statement(<<<'SQL'
            CREATE POLICY tenant_staff_security_events_provider_first_admin_insert
            ON public.tenant_staff_security_events FOR INSERT TO daleel_provider_first_admin_writer
            WITH CHECK (
                current_setting('app.context_mode', true) = 'PROVIDER_CONTROL'
                AND current_setting('app.provider_action', true) = 'company.provision'
                AND app_provider_control_tenant_allowed(tenant_id)
                AND event_type = 'tenant_staff.created' AND outcome = 'SUCCESS'
                AND actor_membership_id IS NULL
                AND provider_operation_id = app_provider_control_setting_uuid('app.provider_operation_id')
                AND metadata = '{}'::jsonb
                AND EXISTS (
                    SELECT 1 FROM public.provider_control_operations operation
                    JOIN public.tenant_staff_users staff
                      ON staff.tenant_id = tenant_staff_security_events.tenant_id
                     AND staff.id = tenant_staff_security_events.target_staff_user_id
                    JOIN public.tenant_staff_memberships membership
                      ON membership.tenant_id = staff.tenant_id AND membership.staff_user_id = staff.id
                    WHERE operation.id = provider_operation_id
                      AND operation.action_key = 'company.provision' AND operation.status = 'READY'
                      AND operation.target_tenant_id = tenant_staff_security_events.tenant_id
                      AND operation.founder_email = staff.canonical_email
                      AND operation.first_admin_display_name = staff.display_name
                      AND staff.status = 'ACTIVE' AND membership.status = 'ACTIVE'
                      AND membership.created_by_provider_operation_id = operation.id
                )
            )
        SQL);

        DB::statement(<<<'SQL'
            CREATE POLICY tenants_provider_first_admin_activate
            ON public.tenants FOR UPDATE TO daleel_provider_first_admin_writer
            USING (
                current_setting('app.context_mode', true) = 'PROVIDER_CONTROL'
                AND current_setting('app.provider_action', true) = 'company.provision'
                AND app_provider_control_tenant_allowed(id)
                AND status = 'PROVISIONING'
                AND EXISTS (
                    SELECT 1 FROM public.provider_control_operations operation
                    WHERE operation.id = app_provider_control_setting_uuid('app.provider_operation_id')
                      AND operation.action_key = 'company.provision' AND operation.status = 'READY'
                      AND operation.target_tenant_id = tenants.id
                      AND operation.canonical_slug = tenants.slug
                )
            )
            WITH CHECK (
                current_setting('app.context_mode', true) = 'PROVIDER_CONTROL'
                AND current_setting('app.provider_action', true) = 'company.provision'
                AND app_provider_control_tenant_allowed(id)
                AND status = 'ACTIVE'
                AND EXISTS (
                    SELECT 1 FROM public.provider_control_operations operation
                    WHERE operation.id = app_provider_control_setting_uuid('app.provider_operation_id')
                      AND operation.action_key = 'company.provision' AND operation.status = 'READY'
                      AND operation.target_tenant_id = tenants.id
                      AND operation.canonical_slug = tenants.slug
                )
                AND EXISTS (
                    SELECT 1 FROM public.tenant_hostnames host
                    WHERE host.tenant_id = tenants.id AND host.tenant_slug = tenants.slug
                )
                AND EXISTS (
                    SELECT 1
                    FROM public.provider_control_operations operation
                    JOIN public.tenant_staff_users staff
                      ON staff.tenant_id = tenants.id
                     AND staff.canonical_email = operation.founder_email
                     AND staff.display_name = operation.first_admin_display_name
                    JOIN public.tenant_staff_memberships membership
                      ON membership.tenant_id = staff.tenant_id AND membership.staff_user_id = staff.id
                    JOIN public.tenant_staff_membership_roles assignment
                      ON assignment.tenant_id = membership.tenant_id AND assignment.membership_id = membership.id
                    JOIN public.roles role
                      ON role.tenant_id = assignment.tenant_id AND role.id = assignment.role_id
                    JOIN public.role_templates template ON template.id = role.source_template_id
                    JOIN public.role_permissions grant_row
                      ON grant_row.tenant_id = role.tenant_id AND grant_row.role_id = role.id
                    JOIN public.permissions permission ON permission.key = grant_row.permission_key
                    WHERE operation.id = app_provider_control_setting_uuid('app.provider_operation_id')
                      AND operation.action_key = 'company.provision' AND operation.status = 'READY'
                      AND operation.target_tenant_id = tenants.id
                      AND staff.status = 'ACTIVE' AND staff.auth_version = 1
                      AND membership.status = 'ACTIVE'
                      AND membership.created_by_provider_operation_id = operation.id
                      AND assignment.assigned_by_provider_operation_id = operation.id
                      AND assignment.revoked_at IS NULL
                      AND role.normalized_name = 'company_admin' AND role.status = 'ACTIVE'
                      AND role.version = 1 AND role.archived_at IS NULL
                      AND template.code = 'company_admin' AND template.version = 1
                      AND template.status = 'ACTIVE'
                      AND grant_row.permission_key = 'company.administer'
                      AND grant_row.scope = 'ALL_TENANT'
                      AND permission.status = 'ACTIVE' AND permission.scopeable
                      AND permission.allowed_scopes @> '["ALL_TENANT"]'::jsonb
                      AND NOT EXISTS (
                          SELECT 1 FROM public.role_template_permissions expected_grant
                          WHERE expected_grant.template_id = template.id
                            AND NOT EXISTS (
                                SELECT 1 FROM public.role_permissions actual_grant
                                WHERE actual_grant.tenant_id = role.tenant_id
                                  AND actual_grant.role_id = role.id
                                  AND actual_grant.permission_key = expected_grant.permission_key
                                  AND actual_grant.scope IS NOT DISTINCT FROM expected_grant.scope
                            )
                      )
                      AND NOT EXISTS (
                          SELECT 1 FROM public.role_permissions actual_grant
                          WHERE actual_grant.tenant_id = role.tenant_id AND actual_grant.role_id = role.id
                            AND NOT EXISTS (
                                SELECT 1 FROM public.role_template_permissions expected_grant
                                WHERE expected_grant.template_id = template.id
                                  AND expected_grant.permission_key = actual_grant.permission_key
                                  AND expected_grant.scope IS NOT DISTINCT FROM actual_grant.scope
                            )
                      )
                      AND NOT EXISTS (
                          SELECT 1
                          FROM public.role_template_permissions expected_grant
                          LEFT JOIN public.permissions expected_permission
                            ON expected_permission.key = expected_grant.permission_key
                          WHERE expected_grant.template_id = template.id
                            AND (
                                expected_permission.key IS NULL
                                OR expected_permission.status <> 'ACTIVE'
                                OR (expected_permission.scopeable AND (
                                    expected_grant.scope IS NULL
                                    OR NOT (expected_permission.allowed_scopes @> jsonb_build_array(expected_grant.scope))
                                ))
                                OR (NOT expected_permission.scopeable AND (
                                    expected_grant.scope IS NOT NULL
                                    OR expected_permission.allowed_scopes <> '[]'::jsonb
                                ))
                            )
                      )
                )
            )
        SQL);

        DB::statement(<<<'SQL'
            CREATE POLICY tenants_provider_first_admin_activation_guard
            ON public.tenants AS RESTRICTIVE FOR UPDATE TO daleel_provider_first_admin_writer
            USING (
                current_setting('app.context_mode', true) = 'PROVIDER_CONTROL'
                AND current_setting('app.provider_action', true) = 'company.provision'
                AND status = 'PROVISIONING'
                AND EXISTS (
                    SELECT 1 FROM public.provider_control_operations operation
                    WHERE operation.id = app_provider_control_setting_uuid('app.provider_operation_id')
                      AND operation.action_key = 'company.provision' AND operation.status = 'READY'
                      AND operation.target_tenant_id = tenants.id
                      AND operation.canonical_slug = tenants.slug
                )
            )
            WITH CHECK (
                current_setting('app.context_mode', true) = 'PROVIDER_CONTROL'
                AND current_setting('app.provider_action', true) = 'company.provision'
                AND status = 'ACTIVE'
                AND EXISTS (
                    SELECT 1 FROM public.provider_control_operations operation
                    JOIN public.tenant_staff_users staff
                      ON staff.tenant_id = tenants.id
                     AND staff.canonical_email = operation.founder_email
                     AND staff.display_name = operation.first_admin_display_name
                    JOIN public.tenant_staff_memberships membership
                      ON membership.tenant_id = staff.tenant_id AND membership.staff_user_id = staff.id
                    JOIN public.tenant_staff_membership_roles assignment
                      ON assignment.tenant_id = membership.tenant_id AND assignment.membership_id = membership.id
                    JOIN public.roles role
                      ON role.tenant_id = assignment.tenant_id AND role.id = assignment.role_id
                    JOIN public.role_templates template ON template.id = role.source_template_id
                    JOIN public.role_permissions grant_row
                      ON grant_row.tenant_id = role.tenant_id AND grant_row.role_id = role.id
                    JOIN public.permissions permission ON permission.key = grant_row.permission_key
                    WHERE operation.id = app_provider_control_setting_uuid('app.provider_operation_id')
                      AND operation.action_key = 'company.provision' AND operation.status = 'READY'
                      AND operation.target_tenant_id = tenants.id
                      AND operation.canonical_slug = tenants.slug
                      AND staff.status = 'ACTIVE' AND staff.auth_version = 1
                      AND membership.status = 'ACTIVE'
                      AND membership.created_by_provider_operation_id = operation.id
                      AND assignment.assigned_by_provider_operation_id = operation.id
                      AND assignment.revoked_at IS NULL
                      AND role.normalized_name = 'company_admin' AND role.status = 'ACTIVE'
                      AND role.version = 1 AND role.archived_at IS NULL
                      AND template.code = 'company_admin' AND template.version = 1
                      AND template.status = 'ACTIVE'
                      AND grant_row.permission_key = 'company.administer'
                      AND grant_row.scope = 'ALL_TENANT'
                      AND permission.status = 'ACTIVE' AND permission.scopeable
                      AND permission.allowed_scopes @> '["ALL_TENANT"]'::jsonb
                      AND NOT EXISTS (
                          SELECT 1 FROM public.role_template_permissions expected_grant
                          WHERE expected_grant.template_id = template.id
                            AND NOT EXISTS (
                                SELECT 1 FROM public.role_permissions actual_grant
                                WHERE actual_grant.tenant_id = role.tenant_id
                                  AND actual_grant.role_id = role.id
                                  AND actual_grant.permission_key = expected_grant.permission_key
                                  AND actual_grant.scope IS NOT DISTINCT FROM expected_grant.scope
                            )
                      )
                      AND NOT EXISTS (
                          SELECT 1 FROM public.role_permissions actual_grant
                          WHERE actual_grant.tenant_id = role.tenant_id AND actual_grant.role_id = role.id
                            AND NOT EXISTS (
                                SELECT 1 FROM public.role_template_permissions expected_grant
                                WHERE expected_grant.template_id = template.id
                                  AND expected_grant.permission_key = actual_grant.permission_key
                                  AND expected_grant.scope IS NOT DISTINCT FROM actual_grant.scope
                            )
                      )
                      AND NOT EXISTS (
                          SELECT 1
                          FROM public.role_template_permissions expected_grant
                          LEFT JOIN public.permissions expected_permission
                            ON expected_permission.key = expected_grant.permission_key
                          WHERE expected_grant.template_id = template.id
                            AND (
                                expected_permission.key IS NULL
                                OR expected_permission.status <> 'ACTIVE'
                                OR (expected_permission.scopeable AND (
                                    expected_grant.scope IS NULL
                                    OR NOT (expected_permission.allowed_scopes @> jsonb_build_array(expected_grant.scope))
                                ))
                                OR (NOT expected_permission.scopeable AND (
                                    expected_grant.scope IS NOT NULL
                                    OR expected_permission.allowed_scopes <> '[]'::jsonb
                                ))
                            )
                      )
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
                    WHEN 'tenant.provisioning.executed' THEN
                        metadata = '{}'::jsonb OR (
                            metadata ?? 'founder_invitation_id'
                            AND metadata - 'founder_invitation_id' = '{}'::jsonb
                            AND jsonb_typeof(metadata->'founder_invitation_id') = 'string'
                            AND pg_input_is_valid(metadata->>'founder_invitation_id','uuid')
                        )
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
        throw new RuntimeException('Provider first-admin RLS is a security invariant; use a reviewed forward correction.');
    }
};
