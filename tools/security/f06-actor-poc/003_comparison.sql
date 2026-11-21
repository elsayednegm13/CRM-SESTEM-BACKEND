-- ============================================================================
-- F06 ACTOR POC (POC02) — 003: the two weaker models, for differential proof.
--
-- Purpose (AT13): show on one database, side by side, that
--   (a) baseline_vulnerable  — GUC-anchored tenant, shared role  -> cross-tenant
--                              AND cross-actor exposure;
--   (b) tenant_only_fixed    — per-tenant LOGIN anchor (POC01's model)
--                              -> cross-tenant blocked, cross-ACTOR still open;
--   (c) tenant_plus_actor    — 001_schema_roles.sql
--                              -> both blocked.
--
-- Run as superuser after 001+002, on the POC02 sandbox only.
-- ============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
-- (a) baseline_vulnerable: exactly the product's current shape for leads
--     (migration 2026_10_23_000036_create_leads.php): tenant-only predicate
--     read from a GUC, no actor condition at all.
-- ---------------------------------------------------------------------------
CREATE TABLE leads_baseline_guc (
    id             uuid PRIMARY KEY,
    tenant_id      uuid NOT NULL,
    owner_actor_id uuid NOT NULL,
    name           text NOT NULL
);
ALTER TABLE leads_baseline_guc OWNER TO poc02_owner;
ALTER TABLE leads_baseline_guc ENABLE ROW LEVEL SECURITY;
ALTER TABLE leads_baseline_guc FORCE ROW LEVEL SECURITY;
CREATE POLICY leads_baseline_guc_all ON leads_baseline_guc FOR ALL
    USING (
        current_setting('app.context_mode', true) = 'TENANT'
        AND tenant_id = current_setting('app.tenant_id', true)::uuid
    )
    WITH CHECK (
        current_setting('app.context_mode', true) = 'TENANT'
        AND tenant_id = current_setting('app.tenant_id', true)::uuid
    );
REVOKE ALL ON TABLE leads_baseline_guc FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE leads_baseline_guc TO poc02_tenant_a_shared;

-- ---------------------------------------------------------------------------
-- (b) tenant_only_fixed: POC01's anchor — the role pins the tenant, but there
--     is still no actor condition, so every actor served by that one role sees
--     every row of the tenant.
-- ---------------------------------------------------------------------------
CREATE TABLE leads_tenant_only (
    id             uuid PRIMARY KEY,
    tenant_id      uuid NOT NULL,
    owner_actor_id uuid NOT NULL,
    name           text NOT NULL
);
ALTER TABLE leads_tenant_only OWNER TO poc02_owner;
ALTER TABLE leads_tenant_only ENABLE ROW LEVEL SECURITY;
ALTER TABLE leads_tenant_only FORCE ROW LEVEL SECURITY;
CREATE POLICY leads_tenant_only_a ON leads_tenant_only FOR ALL
    TO poc02_tenant_a_shared
    USING (tenant_id = '11111111-1111-1111-1111-111111111111'::uuid)
    WITH CHECK (tenant_id = '11111111-1111-1111-1111-111111111111'::uuid);
REVOKE ALL ON TABLE leads_tenant_only FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE leads_tenant_only TO poc02_tenant_a_shared;

-- Same logical rows in all three models so the comparison is apples to apples.
INSERT INTO leads_baseline_guc (id, tenant_id, owner_actor_id, name) VALUES
    ('10000000-0000-0000-0000-0000000000a1', '11111111-1111-1111-1111-111111111111', 'aaaaaaaa-0000-0000-0000-00000000a001', 'Lead A1-one'),
    ('20000000-0000-0000-0000-0000000000a2', '11111111-1111-1111-1111-111111111111', 'aaaaaaaa-0000-0000-0000-00000000a002', 'Lead A2-private'),
    ('b0000000-0000-0000-0000-0000000000b1', '22222222-2222-2222-2222-222222222222', 'bbbbbbbb-0000-0000-0000-00000000b001', 'Lead B1-private');

INSERT INTO leads_tenant_only (id, tenant_id, owner_actor_id, name) VALUES
    ('10000000-0000-0000-0000-0000000000a1', '11111111-1111-1111-1111-111111111111', 'aaaaaaaa-0000-0000-0000-00000000a001', 'Lead A1-one'),
    ('20000000-0000-0000-0000-0000000000a2', '11111111-1111-1111-1111-111111111111', 'aaaaaaaa-0000-0000-0000-00000000a002', 'Lead A2-private'),
    ('b0000000-0000-0000-0000-0000000000b1', '22222222-2222-2222-2222-222222222222', 'bbbbbbbb-0000-0000-0000-00000000b001', 'Lead B1-private');

COMMIT;
