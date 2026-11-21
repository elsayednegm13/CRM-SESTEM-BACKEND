-- Sandbox-only role separation. Keep the legacy shared bootstrap on
-- daleel_tenant_runtime for FLAG=OFF; actor logins inherit only this group.
BEGIN;
CREATE ROLE daleel_f06scope_actor_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
GRANT USAGE ON SCHEMA public TO daleel_f06scope_actor_runtime;
GRANT SELECT (id, status) ON public.tenants TO daleel_f06scope_actor_runtime;
GRANT SELECT (id, tenant_id, canonical_email, display_email, display_name, status, auth_version) ON public.tenant_staff_users TO daleel_f06scope_actor_runtime;
GRANT SELECT (id, tenant_id, staff_user_id, status, authorization_version) ON public.tenant_staff_memberships TO daleel_f06scope_actor_runtime;
GRANT SELECT (tenant_id, membership_id, role_id, revoked_at) ON public.tenant_staff_membership_roles TO daleel_f06scope_actor_runtime;
GRANT SELECT (tenant_id, membership_id, permission_key, scope, revoked_at) ON public.tenant_staff_permission_grants TO daleel_f06scope_actor_runtime;
GRANT SELECT (id, tenant_id, display_name, normalized_name, status, version, archived_at) ON public.roles TO daleel_f06scope_actor_runtime;
GRANT SELECT (tenant_id, role_id, permission_key, scope) ON public.role_permissions TO daleel_f06scope_actor_runtime;
GRANT SELECT (key, scopeable, allowed_scopes, delegable, status) ON public.permissions TO daleel_f06scope_actor_runtime;
GRANT SELECT (id, tenant_id, name, phone, email, city, country, source, campaign, pipeline_stage, interest_level, estimated_value_minor, status, assigned_membership_id, created_by_membership_id, last_contacted_at, created_at, updated_at) ON public.leads TO daleel_f06scope_actor_runtime;
GRANT INSERT (id, tenant_id, name, phone, email, city, country, source, campaign, pipeline_stage, interest_level, estimated_value_minor, status, assigned_membership_id, created_by_membership_id, last_contacted_at, created_at, updated_at) ON public.leads TO daleel_f06scope_actor_runtime;
GRANT UPDATE (name, phone, email, city, country, source, campaign, pipeline_stage, interest_level, estimated_value_minor, status, last_contacted_at, updated_at) ON public.leads TO daleel_f06scope_actor_runtime;
GRANT daleel_f06scope_actor_runtime TO daleel_f06i02_actor_a1 WITH ADMIN FALSE, INHERIT TRUE, SET FALSE;
GRANT daleel_f06scope_actor_runtime TO daleel_f06i02_actor_a2 WITH ADMIN FALSE, INHERIT TRUE, SET FALSE;
GRANT daleel_f06scope_actor_runtime TO daleel_f06i02_actor_b1 WITH ADMIN FALSE, INHERIT TRUE, SET FALSE;
GRANT daleel_f06scope_actor_runtime TO daleel_f06i03_actor_a4 WITH ADMIN FALSE, INHERIT TRUE, SET FALSE;
REVOKE daleel_tenant_runtime FROM daleel_f06i02_actor_a1, daleel_f06i02_actor_a2, daleel_f06i02_actor_b1, daleel_f06i03_actor_a4;
COMMIT;
