-- F06 POC — 002: candidate fix (C1-style tenant anchor).
-- Replaces the GUC anchor (current_setting('app.tenant_id', true)) with a
-- per-tenant LOGIN role anchor (current_user via `TO <role>` on the policy).
-- Run as superuser against daleel_f06_poc01_synthetic ONLY, after 001.

BEGIN;

DO $guard$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname IN ('poc_runtime_tenant_a', 'poc_runtime_tenant_b')) THEN
        RAISE EXCEPTION 'poc_runtime_tenant_a/b already exist — refusing to reuse a role in a fresh sandbox';
    END IF;
END
$guard$;

-- Two independent LOGIN roles, one per tenant. No membership, no inheritance,
-- no shared secret between them. This is the actual anchor: cannot be
-- rewritten by any SQL statement the way a GUC can.
CREATE ROLE poc_runtime_tenant_a LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS
    PASSWORD :'tenant_a_pw';
CREATE ROLE poc_runtime_tenant_b LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS
    PASSWORD :'tenant_b_pw';

-- Fixed, well-known fixture tenant ids (synthetic only) so policies can be
-- written as literal comparisons instead of a lookup table an attacker
-- could try to pivot through.
-- Tenant A = 11111111-1111-1111-1111-111111111111
-- Tenant B = 22222222-2222-2222-2222-222222222222

CREATE TABLE leads_fixed (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    assigned_staff_id uuid NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE leads_fixed ENABLE ROW LEVEL SECURITY;
ALTER TABLE leads_fixed FORCE ROW LEVEL SECURITY;

-- No policy here ever references current_setting('app.tenant_id', ...).
-- The anchor is exclusively `TO <role>` (current_user), which the
-- connection authenticated as cannot change mid-session without a fresh
-- password-authenticated connection as a *different* role.
CREATE POLICY leads_fixed_tenant_a ON leads_fixed
    FOR ALL TO poc_runtime_tenant_a
    USING (tenant_id = '11111111-1111-1111-1111-111111111111'::uuid)
    WITH CHECK (tenant_id = '11111111-1111-1111-1111-111111111111'::uuid);

CREATE POLICY leads_fixed_tenant_b ON leads_fixed
    FOR ALL TO poc_runtime_tenant_b
    USING (tenant_id = '22222222-2222-2222-2222-222222222222'::uuid)
    WITH CHECK (tenant_id = '22222222-2222-2222-2222-222222222222'::uuid);

REVOKE ALL ON TABLE leads_fixed FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE leads_fixed TO poc_runtime_tenant_a;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE leads_fixed TO poc_runtime_tenant_b;

-- --------------------------------------------------------------------------
-- Actor layer: deliberately NOT anchored on current_user. Mirrors the real
-- product's actor-bound tables (tenant_staff_membership_roles /
-- tenant_staff_permission_grants, migration 2026_10_11_000024), which trust
-- current_setting('app.user_id', true) — still a forgeable GUC on whichever
-- connection holds it. This is here so T06 can demonstrate, honestly, that
-- the tenant anchor fix above does NOT by itself close actor impersonation
-- inside the same tenant.
-- --------------------------------------------------------------------------

CREATE TABLE poc_staff_memberships (
    tenant_id uuid NOT NULL,
    staff_id uuid NOT NULL,
    status text NOT NULL CHECK (status IN ('ACTIVE', 'SUSPENDED')),
    is_admin boolean NOT NULL DEFAULT false,
    PRIMARY KEY (tenant_id, staff_id)
);
ALTER TABLE poc_staff_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE poc_staff_memberships FORCE ROW LEVEL SECURITY;
CREATE POLICY poc_staff_memberships_tenant_a ON poc_staff_memberships
    FOR SELECT TO poc_runtime_tenant_a
    USING (tenant_id = '11111111-1111-1111-1111-111111111111'::uuid);
CREATE POLICY poc_staff_memberships_tenant_b ON poc_staff_memberships
    FOR SELECT TO poc_runtime_tenant_b
    USING (tenant_id = '22222222-2222-2222-2222-222222222222'::uuid);
REVOKE ALL ON TABLE poc_staff_memberships FROM PUBLIC;
GRANT SELECT ON TABLE poc_staff_memberships TO poc_runtime_tenant_a;
GRANT SELECT ON TABLE poc_staff_memberships TO poc_runtime_tenant_b;

CREATE TABLE poc_actor_bound_grants (
    tenant_id uuid NOT NULL,
    grantee_staff_id uuid NOT NULL,
    capability text NOT NULL,
    PRIMARY KEY (tenant_id, grantee_staff_id, capability)
);
ALTER TABLE poc_actor_bound_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE poc_actor_bound_grants FORCE ROW LEVEL SECURITY;

-- Actor-bound predicate: tenant anchored via role (safe, fixed above) AND
-- "am I an ACTIVE member of this tenant" via the still-forgeable GUC
-- app.user_id — same structure as the real product's strongest existing
-- layer. Expected to be insufficient against an attacker who can set
-- app.user_id to a *different* ACTIVE staff id of the SAME tenant (T06).
CREATE POLICY poc_actor_bound_grants_tenant_a ON poc_actor_bound_grants
    FOR SELECT TO poc_runtime_tenant_a
    USING (
        tenant_id = '11111111-1111-1111-1111-111111111111'::uuid
        AND EXISTS (
            SELECT 1 FROM poc_staff_memberships actor
            WHERE actor.tenant_id = poc_actor_bound_grants.tenant_id
              AND actor.staff_id = current_setting('app.user_id', true)::uuid
              AND actor.status = 'ACTIVE'
        )
    );
CREATE POLICY poc_actor_bound_grants_tenant_b ON poc_actor_bound_grants
    FOR SELECT TO poc_runtime_tenant_b
    USING (
        tenant_id = '22222222-2222-2222-2222-222222222222'::uuid
        AND EXISTS (
            SELECT 1 FROM poc_staff_memberships actor
            WHERE actor.tenant_id = poc_actor_bound_grants.tenant_id
              AND actor.staff_id = current_setting('app.user_id', true)::uuid
              AND actor.status = 'ACTIVE'
        )
    );
REVOKE ALL ON TABLE poc_actor_bound_grants FROM PUBLIC;
GRANT SELECT ON TABLE poc_actor_bound_grants TO poc_runtime_tenant_a;
GRANT SELECT ON TABLE poc_actor_bound_grants TO poc_runtime_tenant_b;

COMMIT;
