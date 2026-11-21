-- SECURITY-F06-LARAVEL-IMPLEMENT-02: synthetic fixture data on the REAL product
-- schema (38/38 real migrations applied). Not a migration; sandbox-only data.
BEGIN;

INSERT INTO public.tenant_registry_domains (mapping_version, base_domain, environment_scope, is_active)
VALUES (1, 'f06i02.localhost', 'LOCAL_TEST', true);

INSERT INTO public.tenants (id, display_name, slug, status, timezone, default_locale, created_at, updated_at) VALUES
    ('11111111-1111-1111-1111-111111111111', 'Tenant A (sandbox)', 'tenant-a', 'ACTIVE', 'UTC', 'en', now(), now()),
    ('22222222-2222-2222-2222-222222222222', 'Tenant B (sandbox)', 'tenant-b', 'ACTIVE', 'UTC', 'en', now(), now());

INSERT INTO public.tenant_hostnames (tenant_id, tenant_slug, base_domain, hostname, mapping_version, created_at) VALUES
    ('11111111-1111-1111-1111-111111111111', 'tenant-a', 'f06i02.localhost', 'tenant-a.f06i02.localhost', 1, now()),
    ('22222222-2222-2222-2222-222222222222', 'tenant-b', 'f06i02.localhost', 'tenant-b.f06i02.localhost', 1, now());

INSERT INTO public.tenant_staff_users (id, tenant_id, canonical_email, display_email, display_name, password_hash, status, auth_version, created_at, updated_at) VALUES
    ('aaaaaaa1-0000-0000-0000-000000000001', '11111111-1111-1111-1111-111111111111', 'a1@tenant-a.sandbox', 'A1@Tenant-A.sandbox', 'Actor A1', :'hash_login_a1', 'ACTIVE', 1, now(), now()),
    ('aaaaaaa2-0000-0000-0000-000000000002', '11111111-1111-1111-1111-111111111111', 'a2@tenant-a.sandbox', 'A2@Tenant-A.sandbox', 'Actor A2', :'hash_login_a2', 'ACTIVE', 1, now(), now()),
    ('aaaaaaa3-0000-0000-0000-000000000003', '11111111-1111-1111-1111-111111111111', 'a3@tenant-a.sandbox', 'A3@Tenant-A.sandbox', 'Actor A3 (suspended)', :'hash_login_a1', 'DISABLED', 1, now(), now()),
    ('bbbbbbb1-0000-0000-0000-000000000001', '22222222-2222-2222-2222-222222222222', 'b1@tenant-b.sandbox', 'B1@Tenant-B.sandbox', 'Actor B1', :'hash_login_b1', 'ACTIVE', 1, now(), now());

-- created_by_membership_id vs created_by_provider_operation_id: the check constraint
-- requires exactly one non-null, and a BEFORE INSERT trigger
-- (tenant_staff_membership_creator_valid) additionally requires that any
-- created_by_provider_operation_id resolve to a real company.provision operation
-- targeting the same tenant, and that any created_by_membership_id resolve to an
-- ACTIVE same-tenant membership whose staff_user_id equals app_rls_current_user_id().
-- A synthetic founding provider_users + provider_control_operations row is created
-- per tenant (legitimate shape, not a shortcut) so each tenant's first membership
-- can be created_by that operation; the second membership in tenant A is then
-- created_by the first (with app.user_id set to the first membership's staff user).
INSERT INTO public.provider_users (id, email, password, status, auth_version, authorization_version, created_at, updated_at) VALUES
    ('f0000001-0000-0000-0000-000000000001', 'founder@f06i02.sandbox', '$argon2id$v=19$m=65536,t=4,p=1$ZmFrZXNhbHRmYWtlc2FsdA$ZmFrZWhhc2hmYWtlaGFzaGZha2VoYXNoZmFrZWhhc2g', 'ACTIVE', 1, 1, now(), now());

INSERT INTO public.provider_control_operations
    (id, action_key, requester_provider_user_id, idempotency_key_hash, intent_digest, target_tenant_id,
     status, display_name, canonical_slug, timezone, founder_email, reason, ticket_reference, expires_at, created_at, updated_at)
VALUES
    ('f0000002-0000-0000-0000-00000000000a', 'company.provision', 'f0000001-0000-0000-0000-000000000001',
     repeat('a', 64), repeat('1', 64), '11111111-1111-1111-1111-111111111111',
     'PENDING_APPROVAL', 'Tenant A (sandbox)', 'tenant-a', 'UTC', 'a1@tenant-a.sandbox',
     'SECURITY-F06-LARAVEL-IMPLEMENT-02 synthetic fixture', 'SANDBOX-F06I02-A', now() + interval '1 day', now(), now()),
    ('f0000002-0000-0000-0000-00000000000b', 'company.provision', 'f0000001-0000-0000-0000-000000000001',
     repeat('b', 64), repeat('2', 64), '22222222-2222-2222-2222-222222222222',
     'PENDING_APPROVAL', 'Tenant B (sandbox)', 'tenant-b', 'UTC', 'b1@tenant-b.sandbox',
     'SECURITY-F06-LARAVEL-IMPLEMENT-02 synthetic fixture', 'SANDBOX-F06I02-B', now() + interval '1 day', now(), now());

INSERT INTO public.tenant_staff_memberships (id, tenant_id, staff_user_id, status, authorization_version, joined_at, created_by_provider_operation_id, created_at, updated_at) VALUES
    ('a1111111-0000-0000-0000-00000000a001', '11111111-1111-1111-1111-111111111111', 'aaaaaaa1-0000-0000-0000-000000000001', 'ACTIVE', 1, now(), 'f0000002-0000-0000-0000-00000000000a', now(), now()),
    ('b1111111-0000-0000-0000-00000000b001', '22222222-2222-2222-2222-222222222222', 'bbbbbbb1-0000-0000-0000-000000000001', 'ACTIVE', 1, now(), 'f0000002-0000-0000-0000-00000000000b', now(), now());

-- Second/third memberships in tenant A are created_by the first (A1), which now exists.
SELECT set_config('app.user_id', 'aaaaaaa1-0000-0000-0000-000000000001', false);
INSERT INTO public.tenant_staff_memberships (id, tenant_id, staff_user_id, status, authorization_version, joined_at, created_by_membership_id, created_at, updated_at) VALUES
    ('a1111111-0000-0000-0000-00000000a002', '11111111-1111-1111-1111-111111111111', 'aaaaaaa2-0000-0000-0000-000000000002', 'ACTIVE', 1, now(), 'a1111111-0000-0000-0000-00000000a001', now(), now()),
    ('a1111111-0000-0000-0000-00000000a003', '11111111-1111-1111-1111-111111111111', 'aaaaaaa3-0000-0000-0000-000000000003', 'SUSPENDED', 1, now(), 'a1111111-0000-0000-0000-00000000a001', now(), now());
SELECT set_config('app.user_id', '', false);

-- Roles: ALL_TENANT (A1, B1) and SELF (A2) for leads.view/leads.manage.
INSERT INTO public.roles (id, tenant_id, display_name, normalized_name, status, version, created_at, updated_at) VALUES
    ('ea000001-0000-0000-0000-00000000000a', '11111111-1111-1111-1111-111111111111', 'Sandbox All-Tenant', 'sandbox_all_tenant', 'ACTIVE', 1, now(), now()),
    ('ea000002-0000-0000-0000-00000000000a', '11111111-1111-1111-1111-111111111111', 'Sandbox Self', 'sandbox_self', 'ACTIVE', 1, now(), now()),
    ('ea000001-0000-0000-0000-00000000000b', '22222222-2222-2222-2222-222222222222', 'Sandbox All-Tenant', 'sandbox_all_tenant', 'ACTIVE', 1, now(), now());

INSERT INTO public.role_permissions (tenant_id, role_id, permission_key, scope) VALUES
    ('11111111-1111-1111-1111-111111111111', 'ea000001-0000-0000-0000-00000000000a', 'leads.view', 'ALL_TENANT'),
    ('11111111-1111-1111-1111-111111111111', 'ea000001-0000-0000-0000-00000000000a', 'leads.manage', 'ALL_TENANT'),
    ('11111111-1111-1111-1111-111111111111', 'ea000002-0000-0000-0000-00000000000a', 'leads.view', 'SELF'),
    ('11111111-1111-1111-1111-111111111111', 'ea000002-0000-0000-0000-00000000000a', 'leads.manage', 'SELF'),
    ('22222222-2222-2222-2222-222222222222', 'ea000001-0000-0000-0000-00000000000b', 'leads.view', 'ALL_TENANT'),
    ('22222222-2222-2222-2222-222222222222', 'ea000001-0000-0000-0000-00000000000b', 'leads.manage', 'ALL_TENANT');

INSERT INTO public.tenant_staff_membership_roles (id, tenant_id, membership_id, role_id, assigned_by_membership_id, assigned_at, created_at, updated_at) VALUES
    ('ea010001-0000-0000-0000-000000000001', '11111111-1111-1111-1111-111111111111', 'a1111111-0000-0000-0000-00000000a001', 'ea000001-0000-0000-0000-00000000000a', 'a1111111-0000-0000-0000-00000000a001', now(), now(), now()),
    ('ea010001-0000-0000-0000-000000000002', '11111111-1111-1111-1111-111111111111', 'a1111111-0000-0000-0000-00000000a002', 'ea000002-0000-0000-0000-00000000000a', 'a1111111-0000-0000-0000-00000000a001', now(), now(), now()),
    ('ea010001-0000-0000-0000-000000000003', '22222222-2222-2222-2222-222222222222', 'b1111111-0000-0000-0000-00000000b001', 'ea000001-0000-0000-0000-00000000000b', 'b1111111-0000-0000-0000-00000000b001', now(), now(), now());

-- Leads: A1-created (ALL_TENANT), A2-created (SELF visible to A2 only among SELF/ASSIGNED),
-- B1-created (tenant B).
INSERT INTO public.leads (id, tenant_id, name, pipeline_stage, status, assigned_membership_id, created_by_membership_id, created_at, updated_at) VALUES
    ('c0000001-0000-0000-0000-000000000001', '11111111-1111-1111-1111-111111111111', 'Lead A owned by A1', 'new', 'ACTIVE', 'a1111111-0000-0000-0000-00000000a001', 'a1111111-0000-0000-0000-00000000a001', now(), now()),
    ('c0000002-0000-0000-0000-000000000002', '11111111-1111-1111-1111-111111111111', 'Lead A owned by A2', 'new', 'ACTIVE', 'a1111111-0000-0000-0000-00000000a002', 'a1111111-0000-0000-0000-00000000a002', now(), now()),
    ('c0000003-0000-0000-0000-000000000003', '22222222-2222-2222-2222-222222222222', 'Lead B owned by B1', 'new', 'ACTIVE', 'b1111111-0000-0000-0000-00000000b001', 'b1111111-0000-0000-0000-00000000b001', now(), now());

COMMIT;
