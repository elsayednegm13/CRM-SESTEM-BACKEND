-- F06 POC — 001: baseline (today's pattern), reproduces the GUC-anchored RLS
-- design used in production for `leads` (migration 2026_10_23_000036_create_leads.php)
-- and the tenant-only RLS predicate style from migration 2026_10_06_000008.
-- SCOPED_EQUIVALENT schema, not a replay of real migrations.
-- Run as superuser against daleel_f06_poc01_synthetic ONLY.

BEGIN;

-- One shared LOGIN role for every tenant, exactly like today's single
-- daleel_tenant_runtime-backed credential: NOSUPERUSER/NOBYPASSRLS/NOINHERIT,
-- no CREATE on schema public, no table ownership.
DO $guard$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'poc_runtime_shared') THEN
        RAISE EXCEPTION 'poc_runtime_shared already exists — refusing to reuse a role in a fresh sandbox';
    END IF;
END
$guard$;

CREATE ROLE poc_runtime_shared LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS
    PASSWORD :'baseline_shared_pw';

CREATE TABLE leads_baseline (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    assigned_staff_id uuid NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE leads_baseline ENABLE ROW LEVEL SECURITY;
ALTER TABLE leads_baseline FORCE ROW LEVEL SECURITY;

-- Exactly the real predicate shape: tenant-only, GUC-anchored, no actor check.
CREATE POLICY leads_baseline_tenant_select ON leads_baseline
    FOR SELECT USING (
        current_setting('app.context_mode', true) = 'TENANT'
        AND tenant_id = current_setting('app.tenant_id', true)::uuid
    );
CREATE POLICY leads_baseline_tenant_insert ON leads_baseline
    FOR INSERT WITH CHECK (
        current_setting('app.context_mode', true) = 'TENANT'
        AND tenant_id = current_setting('app.tenant_id', true)::uuid
    );
CREATE POLICY leads_baseline_tenant_update ON leads_baseline
    FOR UPDATE USING (
        current_setting('app.context_mode', true) = 'TENANT'
        AND tenant_id = current_setting('app.tenant_id', true)::uuid
    ) WITH CHECK (
        current_setting('app.context_mode', true) = 'TENANT'
        AND tenant_id = current_setting('app.tenant_id', true)::uuid
    );
CREATE POLICY leads_baseline_tenant_delete ON leads_baseline
    FOR DELETE USING (
        current_setting('app.context_mode', true) = 'TENANT'
        AND tenant_id = current_setting('app.tenant_id', true)::uuid
    );

REVOKE ALL ON TABLE leads_baseline FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE leads_baseline TO poc_runtime_shared;

COMMIT;
