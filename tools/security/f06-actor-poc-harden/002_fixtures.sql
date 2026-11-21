-- ============================================================================
-- F06 ACTOR POC — HARDENED (POC03) — 002: synthetic fixtures only.
-- No real data, no secrets. Run as superuser after 001 and 003.
-- Fixed ids are used so the harness can assert exact values.
-- ============================================================================

BEGIN;

-- tenant A = 11111111-1111-1111-1111-111111111111
-- tenant B = 22222222-2222-2222-2222-222222222222
INSERT INTO actor_identity_map (role_name, tenant_id, actor_id, actor_status, is_admin) VALUES
    ('h01_a1', '11111111-1111-1111-1111-111111111111', 'aaaaaaaa-0000-0000-0000-00000000a001', 'ACTIVE',    false),
    ('h01_a2', '11111111-1111-1111-1111-111111111111', 'aaaaaaaa-0000-0000-0000-00000000a002', 'ACTIVE',    true),
    ('h01_a3', '11111111-1111-1111-1111-111111111111', 'aaaaaaaa-0000-0000-0000-00000000a003', 'SUSPENDED', false),
    ('h01_a4', '11111111-1111-1111-1111-111111111111', 'aaaaaaaa-0000-0000-0000-00000000a004', 'ACTIVE',    false),
    ('h01_b1', '22222222-2222-2222-2222-222222222222', 'bbbbbbbb-0000-0000-0000-00000000b001', 'ACTIVE',    false);

-- leads_actor: A1 owns 2, A2 owns 1 (the "hidden" row), A4 owns 1, B1 owns 1.
-- id is normally DB-generated; fixtures set it explicitly as superuser so the
-- harness can reference the hidden row by a known id (clients cannot supply
-- id — see the INSERT column grants in 001).
INSERT INTO leads_actor (id, tenant_id, owner_actor_id, code, name) VALUES
    ('10000000-0000-0000-0000-0000000000a1', '11111111-1111-1111-1111-111111111111', 'aaaaaaaa-0000-0000-0000-00000000a001', 'A1-C1', 'Lead A1-one'),
    ('10000000-0000-0000-0000-0000000000a2', '11111111-1111-1111-1111-111111111111', 'aaaaaaaa-0000-0000-0000-00000000a001', 'A1-C2', 'Lead A1-two'),
    ('20000000-0000-0000-0000-0000000000a2', '11111111-1111-1111-1111-111111111111', 'aaaaaaaa-0000-0000-0000-00000000a002', 'A2-SECRET', 'Lead A2-private'),
    ('40000000-0000-0000-0000-0000000000a4', '11111111-1111-1111-1111-111111111111', 'aaaaaaaa-0000-0000-0000-00000000a004', 'A4-C1', 'Lead A4-private'),
    ('b0000000-0000-0000-0000-0000000000b1', '22222222-2222-2222-2222-222222222222', 'bbbbbbbb-0000-0000-0000-00000000b001', 'B1-C1', 'Lead B1-private');

INSERT INTO admin_grants (tenant_id, grantee_actor_id, capability) VALUES
    ('11111111-1111-1111-1111-111111111111', 'aaaaaaaa-0000-0000-0000-00000000a002', 'company.administer');

-- Same logical rows in the two weaker comparison models.
INSERT INTO leads_baseline_guc (id, tenant_id, owner_actor_id, name) VALUES
    ('10000000-0000-0000-0000-0000000000a1', '11111111-1111-1111-1111-111111111111', 'aaaaaaaa-0000-0000-0000-00000000a001', 'Lead A1-one'),
    ('20000000-0000-0000-0000-0000000000a2', '11111111-1111-1111-1111-111111111111', 'aaaaaaaa-0000-0000-0000-00000000a002', 'Lead A2-private'),
    ('b0000000-0000-0000-0000-0000000000b1', '22222222-2222-2222-2222-222222222222', 'bbbbbbbb-0000-0000-0000-00000000b001', 'Lead B1-private');

INSERT INTO leads_tenant_only (id, tenant_id, owner_actor_id, name) VALUES
    ('10000000-0000-0000-0000-0000000000a1', '11111111-1111-1111-1111-111111111111', 'aaaaaaaa-0000-0000-0000-00000000a001', 'Lead A1-one'),
    ('20000000-0000-0000-0000-0000000000a2', '11111111-1111-1111-1111-111111111111', 'aaaaaaaa-0000-0000-0000-00000000a002', 'Lead A2-private'),
    ('b0000000-0000-0000-0000-0000000000b1', '22222222-2222-2222-2222-222222222222', 'bbbbbbbb-0000-0000-0000-00000000b001', 'Lead B1-private');

COMMIT;
