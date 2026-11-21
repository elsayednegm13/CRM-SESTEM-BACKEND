-- F06 POC — 003: synthetic fixtures only. No real tenant/customer data.
-- Run as superuser against daleel_f06_poc01_synthetic ONLY, after 001+002.

BEGIN;

-- Tenant A staff: A1 ordinary ACTIVE, A2 ACTIVE admin (higher privilege).
INSERT INTO poc_staff_memberships (tenant_id, staff_id, status, is_admin) VALUES
    ('11111111-1111-1111-1111-111111111111', 'aaaaaaaa-0000-0000-0000-00000000a001', 'ACTIVE', false),
    ('11111111-1111-1111-1111-111111111111', 'aaaaaaaa-0000-0000-0000-00000000a002', 'ACTIVE', true),
    ('11111111-1111-1111-1111-111111111111', 'aaaaaaaa-0000-0000-0000-00000000a003', 'SUSPENDED', false);

-- Tenant B staff: B1 ACTIVE.
INSERT INTO poc_staff_memberships (tenant_id, staff_id, status, is_admin) VALUES
    ('22222222-2222-2222-2222-222222222222', 'bbbbbbbb-0000-0000-0000-00000000b001', 'ACTIVE', false);

-- Leads, baseline schema (vulnerable-by-design, today's pattern).
INSERT INTO leads_baseline (id, tenant_id, name, assigned_staff_id) VALUES
    ('a0000000-0000-0000-0000-00000000000a', '11111111-1111-1111-1111-111111111111', 'Lead A (baseline)', 'aaaaaaaa-0000-0000-0000-00000000a001'),
    ('b0000000-0000-0000-0000-00000000000b', '22222222-2222-2222-2222-222222222222', 'Lead B (baseline)', 'bbbbbbbb-0000-0000-0000-00000000b001');

-- Leads, fixed schema (tenant-anchored via role).
INSERT INTO leads_fixed (id, tenant_id, name, assigned_staff_id) VALUES
    ('a1111111-0000-0000-0000-00000000000a', '11111111-1111-1111-1111-111111111111', 'Lead A (fixed)', 'aaaaaaaa-0000-0000-0000-00000000a001'),
    ('b1111111-0000-0000-0000-00000000000b', '22222222-2222-2222-2222-222222222222', 'Lead B (fixed)', 'bbbbbbbb-0000-0000-0000-00000000b001');

-- Actor-bound capability: only A2 (admin) of tenant A is granted
-- 'company.administer'. A1 (ordinary) must not see this row unless it can
-- successfully impersonate A2's staff_id via the app.user_id GUC (T06).
INSERT INTO poc_actor_bound_grants (tenant_id, grantee_staff_id, capability) VALUES
    ('11111111-1111-1111-1111-111111111111', 'aaaaaaaa-0000-0000-0000-00000000a002', 'company.administer');

COMMIT;
