-- ============================================================================
-- F06 ACTOR POC (POC02) — 002: synthetic fixtures. No real data of any kind.
-- Run as superuser after 001, on the POC02 sandbox only.
-- ============================================================================

BEGIN;

-- tenant A = 11111111-1111-1111-1111-111111111111
-- tenant B = 22222222-2222-2222-2222-222222222222

INSERT INTO actor_identity_map (role_name, tenant_id, actor_id, actor_status, is_admin) VALUES
    ('poc02_a1', '11111111-1111-1111-1111-111111111111', 'aaaaaaaa-0000-0000-0000-00000000a001', 'ACTIVE',    false),
    ('poc02_a2', '11111111-1111-1111-1111-111111111111', 'aaaaaaaa-0000-0000-0000-00000000a002', 'ACTIVE',    true),
    ('poc02_a3', '11111111-1111-1111-1111-111111111111', 'aaaaaaaa-0000-0000-0000-00000000a003', 'SUSPENDED', false),
    ('poc02_a4', '11111111-1111-1111-1111-111111111111', 'aaaaaaaa-0000-0000-0000-00000000a004', 'ACTIVE',    false),
    ('poc02_b1', '22222222-2222-2222-2222-222222222222', 'bbbbbbbb-0000-0000-0000-00000000b001', 'ACTIVE',    false);

-- leads_actor: A1 owns 2, A2 owns 1, A4 owns 1, B1 owns 1.
-- So: A1 sees 2 (own), A2 sees 4 (admin over all of tenant A), A4 sees 1,
--     B1 sees 1, A3 (suspended) sees 0.
INSERT INTO leads_actor (id, tenant_id, owner_actor_id, name) VALUES
    ('10000000-0000-0000-0000-0000000000a1', '11111111-1111-1111-1111-111111111111', 'aaaaaaaa-0000-0000-0000-00000000a001', 'Lead A1-one'),
    ('10000000-0000-0000-0000-0000000000a2', '11111111-1111-1111-1111-111111111111', 'aaaaaaaa-0000-0000-0000-00000000a001', 'Lead A1-two'),
    ('20000000-0000-0000-0000-0000000000a2', '11111111-1111-1111-1111-111111111111', 'aaaaaaaa-0000-0000-0000-00000000a002', 'Lead A2-private'),
    ('40000000-0000-0000-0000-0000000000a4', '11111111-1111-1111-1111-111111111111', 'aaaaaaaa-0000-0000-0000-00000000a004', 'Lead A4-private'),
    ('b0000000-0000-0000-0000-0000000000b1', '22222222-2222-2222-2222-222222222222', 'bbbbbbbb-0000-0000-0000-00000000b001', 'Lead B1-private');

-- Admin-restricted row: exactly one, in tenant A, for A2.
INSERT INTO admin_grants (tenant_id, grantee_actor_id, capability) VALUES
    ('11111111-1111-1111-1111-111111111111', 'aaaaaaaa-0000-0000-0000-00000000a002', 'company.administer');

COMMIT;
