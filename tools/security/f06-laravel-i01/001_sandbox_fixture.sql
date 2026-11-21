-- SECURITY-F06-LARAVEL-IMPLEMENT-01 : isolated sandbox fixture (SCOPED_EQUIVALENT)
-- NOT a product migration. Not applied to any protected/product database.
-- Schema mirrors the real tenants/tenant_staff_users/tenant_staff_memberships/leads
-- shape closely enough to exercise RLS + actor-login identity, but is a synthetic
-- fixture, not a replay of migrations 001-038. SCHEMA_FIDELITY=SCOPED_EQUIVALENT.

BEGIN;

CREATE SCHEMA IF NOT EXISTS public;

-- ---------------------------------------------------------------------------
-- Roles
-- ---------------------------------------------------------------------------
DO $roles$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'daleel_f06i01_owner') THEN
        CREATE ROLE daleel_f06i01_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'daleel_f06i01_bootstrap_resolver') THEN
        -- Owner of the SECURITY DEFINER bootstrap-lookup function only. NOLOGIN.
        CREATE ROLE daleel_f06i01_bootstrap_resolver NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'daleel_f06i01_bootstrap_client') THEN
        -- LOGIN role used only by TrustedActorBootstrapVerifier's dedicated connection.
        -- Password is set separately below (psql :'var' substitution does not cross DO $$ bodies).
        CREATE ROLE daleel_f06i01_bootstrap_client LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD NULL;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'daleel_f06i01_actor_group') THEN
        -- NOLOGIN group role carrying the actor privilege set (precedent: daleel_tenant_auth_lookup /
        -- daleel_provider_first_admin_writer pattern already used in the product codebase).
        CREATE ROLE daleel_f06i01_actor_group NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'daleel_f06i01_actor_a1') THEN
        CREATE ROLE daleel_f06i01_actor_a1 LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS
            IN ROLE daleel_f06i01_actor_group PASSWORD NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'daleel_f06i01_actor_a2') THEN
        CREATE ROLE daleel_f06i01_actor_a2 LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS
            IN ROLE daleel_f06i01_actor_group PASSWORD NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'daleel_f06i01_actor_b1') THEN
        CREATE ROLE daleel_f06i01_actor_b1 LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS
            IN ROLE daleel_f06i01_actor_group PASSWORD NULL;
    END IF;
    -- A3: deliberately NOT given a LOGIN role / NOT mapped -> must deny before data SQL (GATE-06).
END
$roles$;

-- Passwords set here (outside dollar-quoted bodies) so psql's :'var' substitution applies.
ALTER ROLE daleel_f06i01_bootstrap_client PASSWORD :'bootstrap_client_password';
ALTER ROLE daleel_f06i01_actor_a1 PASSWORD :'actor_a1_password';
ALTER ROLE daleel_f06i01_actor_a2 PASSWORD :'actor_a2_password';
ALTER ROLE daleel_f06i01_actor_b1 PASSWORD :'actor_b1_password';

-- Safety assertions on the actor roles (mirrors migration 037's NOLOGIN/bypassrls guard pattern).
DO $guard$
DECLARE r record;
BEGIN
    FOR r IN SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, rolbypassrls, rolcanlogin
             FROM pg_roles WHERE rolname IN ('daleel_f06i01_actor_a1','daleel_f06i01_actor_a2','daleel_f06i01_actor_b1')
    LOOP
        IF r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolbypassrls THEN
            RAISE EXCEPTION 'actor role % has excess privilege', r.rolname;
        END IF;
        IF NOT r.rolcanlogin THEN
            RAISE EXCEPTION 'actor role % must be able to log in', r.rolname;
        END IF;
    END LOOP;
END
$guard$;

-- ---------------------------------------------------------------------------
-- Tables (owned by daleel_f06i01_owner; actor roles never own objects)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.f06i01_tenants (
    id uuid PRIMARY KEY,
    status text NOT NULL
);
ALTER TABLE public.f06i01_tenants OWNER TO daleel_f06i01_owner;

CREATE TABLE IF NOT EXISTS public.f06i01_tenant_staff_users (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES public.f06i01_tenants(id),
    status text NOT NULL,
    auth_version integer NOT NULL
);
ALTER TABLE public.f06i01_tenant_staff_users OWNER TO daleel_f06i01_owner;
ALTER TABLE public.f06i01_tenant_staff_users ADD CONSTRAINT f06i01_tsu_tenant_id_id_unique UNIQUE (tenant_id, id);

CREATE TABLE IF NOT EXISTS public.f06i01_tenant_staff_memberships (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    staff_user_id uuid NOT NULL,
    status text NOT NULL,
    authorization_version integer NOT NULL,
    scope text NOT NULL DEFAULT 'SELF', -- ALL_TENANT | ASSIGNED | SELF (mirrors ResourceScope enum)
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, staff_user_id) REFERENCES public.f06i01_tenant_staff_users(tenant_id, id)
);
ALTER TABLE public.f06i01_tenant_staff_memberships OWNER TO daleel_f06i01_owner;

-- actor_sql_identity_map: PROPOSED_NOT_CREATED table name from the design doc, built here
-- only inside this sandbox fixture. Not writable by any actor role.
CREATE TABLE IF NOT EXISTS public.actor_sql_identity_map (
    tenant_id uuid NOT NULL,
    membership_id uuid NOT NULL,
    sql_role_name text NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, membership_id),
    FOREIGN KEY (tenant_id, membership_id) REFERENCES public.f06i01_tenant_staff_memberships(tenant_id, id)
);
ALTER TABLE public.actor_sql_identity_map OWNER TO daleel_f06i01_owner;

-- leads fixture: 18 columns mirroring migration 2026_10_23_000036_create_leads.php,
-- composite FKs to memberships(tenant_id, id), 3 non-unique indexes, no UNIQUE constraint.
CREATE TABLE IF NOT EXISTS public.f06i01_leads (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    phone text,
    email text,
    city text,
    country text,
    source text,
    campaign text,
    pipeline_stage text NOT NULL,
    interest_level text,
    estimated_value_minor bigint,
    status text NOT NULL,
    assigned_membership_id uuid,
    created_by_membership_id uuid NOT NULL,
    last_contacted_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, assigned_membership_id) REFERENCES public.f06i01_tenant_staff_memberships(tenant_id, id),
    FOREIGN KEY (tenant_id, created_by_membership_id) REFERENCES public.f06i01_tenant_staff_memberships(tenant_id, id)
);
ALTER TABLE public.f06i01_leads OWNER TO daleel_f06i01_owner;
CREATE INDEX IF NOT EXISTS f06i01_leads_tenant_idx ON public.f06i01_leads (tenant_id);
CREATE INDEX IF NOT EXISTS f06i01_leads_assigned_idx ON public.f06i01_leads (tenant_id, assigned_membership_id);
CREATE INDEX IF NOT EXISTS f06i01_leads_status_idx ON public.f06i01_leads (tenant_id, status);

-- ---------------------------------------------------------------------------
-- Synthetic data (two tenants: A, B)
-- ---------------------------------------------------------------------------
INSERT INTO public.f06i01_tenants (id, status) VALUES
    ('11111111-1111-1111-1111-111111111111', 'ACTIVE'),
    ('22222222-2222-2222-2222-222222222222', 'ACTIVE')
ON CONFLICT DO NOTHING;

INSERT INTO public.f06i01_tenant_staff_users (id, tenant_id, status, auth_version) VALUES
    ('aaaaaaa1-0000-0000-0000-000000000001', '11111111-1111-1111-1111-111111111111', 'ACTIVE', 1),
    ('aaaaaaa2-0000-0000-0000-000000000002', '11111111-1111-1111-1111-111111111111', 'ACTIVE', 1),
    ('bbbbbbb1-0000-0000-0000-000000000001', '22222222-2222-2222-2222-222222222222', 'ACTIVE', 1),
    ('aaaaaaa3-0000-0000-0000-000000000003', '11111111-1111-1111-1111-111111111111', 'SUSPENDED', 1)
ON CONFLICT DO NOTHING;

INSERT INTO public.f06i01_tenant_staff_memberships (id, tenant_id, staff_user_id, status, authorization_version, scope) VALUES
    ('a1111111-0000-0000-0000-00000000a001', '11111111-1111-1111-1111-111111111111', 'aaaaaaa1-0000-0000-0000-000000000001', 'ACTIVE', 1, 'ALL_TENANT'),
    ('a1111111-0000-0000-0000-00000000a002', '11111111-1111-1111-1111-111111111111', 'aaaaaaa2-0000-0000-0000-000000000002', 'ACTIVE', 1, 'SELF'),
    ('b1111111-0000-0000-0000-00000000b001', '22222222-2222-2222-2222-222222222222', 'bbbbbbb1-0000-0000-0000-000000000001', 'ACTIVE', 1, 'ALL_TENANT'),
    ('a1111111-0000-0000-0000-00000000a003', '11111111-1111-1111-1111-111111111111', 'aaaaaaa3-0000-0000-0000-000000000003', 'SUSPENDED', 1, 'SELF')
ON CONFLICT DO NOTHING;

-- A3 (suspended) is intentionally NOT present in actor_sql_identity_map.
INSERT INTO public.actor_sql_identity_map (tenant_id, membership_id, sql_role_name) VALUES
    ('11111111-1111-1111-1111-111111111111', 'a1111111-0000-0000-0000-00000000a001', 'daleel_f06i01_actor_a1'),
    ('11111111-1111-1111-1111-111111111111', 'a1111111-0000-0000-0000-00000000a002', 'daleel_f06i01_actor_a2'),
    ('22222222-2222-2222-2222-222222222222', 'b1111111-0000-0000-0000-00000000b001', 'daleel_f06i01_actor_b1')
ON CONFLICT DO NOTHING;

INSERT INTO public.f06i01_leads
    (id, tenant_id, name, pipeline_stage, status, assigned_membership_id, created_by_membership_id)
VALUES
    ('c0000001-0000-0000-0000-000000000001', '11111111-1111-1111-1111-111111111111', 'Lead A owned by A1', 'NEW', 'OPEN',
        'a1111111-0000-0000-0000-00000000a001', 'a1111111-0000-0000-0000-00000000a001'),
    ('c0000002-0000-0000-0000-000000000002', '11111111-1111-1111-1111-111111111111', 'Lead A owned by A2', 'NEW', 'OPEN',
        'a1111111-0000-0000-0000-00000000a002', 'a1111111-0000-0000-0000-00000000a002'),
    ('c0000003-0000-0000-0000-000000000003', '22222222-2222-2222-2222-222222222222', 'Lead B owned by B1', 'NEW', 'OPEN',
        'b1111111-0000-0000-0000-00000000b001', 'b1111111-0000-0000-0000-00000000b001')
ON CONFLICT DO NOTHING;

-- ---------------------------------------------------------------------------
-- SECURITY DEFINER bootstrap-lookup function (read-only, narrow scope)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.f06i01_bootstrap_lookup(
    p_tenant_id uuid, p_staff_user_id uuid, p_membership_id uuid,
    p_auth_version integer, p_authorization_version integer
) RETURNS TABLE(sql_role_name text) AS $fn$
BEGIN
    -- session_user (not current_user) must be checked: inside SECURITY DEFINER,
    -- current_user is already the function owner, not the caller.
    IF session_user <> 'daleel_f06i01_bootstrap_client' THEN
        RAISE EXCEPTION 'bootstrap lookup is restricted to the bootstrap client role';
    END IF;

    RETURN QUERY
    SELECT m.sql_role_name
    FROM public.f06i01_tenants t
    JOIN public.f06i01_tenant_staff_users u ON u.tenant_id = t.id
    JOIN public.f06i01_tenant_staff_memberships ms ON ms.tenant_id = t.id AND ms.staff_user_id = u.id
    JOIN public.actor_sql_identity_map m ON m.tenant_id = ms.tenant_id AND m.membership_id = ms.id
    WHERE t.id = p_tenant_id AND t.status = 'ACTIVE'
      AND u.id = p_staff_user_id AND u.status = 'ACTIVE' AND u.auth_version = p_auth_version
      AND ms.id = p_membership_id AND ms.status = 'ACTIVE' AND ms.authorization_version = p_authorization_version;
END;
$fn$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

ALTER FUNCTION public.f06i01_bootstrap_lookup OWNER TO daleel_f06i01_bootstrap_resolver;
REVOKE ALL ON FUNCTION public.f06i01_bootstrap_lookup FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.f06i01_bootstrap_lookup TO daleel_f06i01_bootstrap_client;
-- SECURITY DEFINER executes as the owner; the owner needs direct SELECT on the
-- tables the function reads (narrowly, read-only, no write grants anywhere).
GRANT SELECT ON public.f06i01_tenants, public.f06i01_tenant_staff_users,
    public.f06i01_tenant_staff_memberships, public.actor_sql_identity_map
    TO daleel_f06i01_bootstrap_resolver;

-- Bootstrap client may ONLY execute the function above; no direct table access.
REVOKE ALL ON public.f06i01_tenants, public.f06i01_tenant_staff_users,
    public.f06i01_tenant_staff_memberships, public.actor_sql_identity_map, public.f06i01_leads
    FROM daleel_f06i01_bootstrap_client;

-- ---------------------------------------------------------------------------
-- Actor group privileges (column-scoped; mirrors migration 037's grant contract)
-- ---------------------------------------------------------------------------
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM daleel_f06i01_actor_group;
GRANT USAGE ON SCHEMA public TO daleel_f06i01_actor_group, daleel_f06i01_bootstrap_client;
GRANT SELECT (id, tenant_id, name, phone, email, city, country, source, campaign, pipeline_stage,
              interest_level, estimated_value_minor, status, assigned_membership_id,
              created_by_membership_id, last_contacted_at, created_at, updated_at),
      INSERT (id, tenant_id, name, phone, email, city, country, source, campaign, pipeline_stage,
              interest_level, estimated_value_minor, status, assigned_membership_id,
              created_by_membership_id),
      UPDATE (name, phone, email, city, country, source, campaign, pipeline_stage, interest_level,
              estimated_value_minor, status, assigned_membership_id, last_contacted_at, updated_at)
    ON public.f06i01_leads TO daleel_f06i01_actor_group;
GRANT SELECT ON public.f06i01_tenant_staff_memberships TO daleel_f06i01_actor_group;
-- Actor group explicitly has NO access to actor_sql_identity_map (cannot read/alter its own mapping).
REVOKE ALL ON SCHEMA public FROM daleel_f06i01_actor_group; -- no CREATE
GRANT USAGE ON SCHEMA public TO daleel_f06i01_actor_group;

-- ---------------------------------------------------------------------------
-- Row Level Security keyed on session_user via actor_sql_identity_map (NOT GUC)
-- ---------------------------------------------------------------------------
-- Actor roles have no direct grant on actor_sql_identity_map (cannot read/alter their
-- own mapping). The RLS policy therefore resolves session_user -> tenant_id through a
-- narrow SECURITY DEFINER function rather than a raw subquery against that table.
CREATE OR REPLACE FUNCTION public.f06i01_actor_tenant_id() RETURNS uuid AS $fn$
    SELECT m.tenant_id FROM public.actor_sql_identity_map m WHERE m.sql_role_name = session_user;
$fn$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public;
ALTER FUNCTION public.f06i01_actor_tenant_id OWNER TO daleel_f06i01_owner;
REVOKE ALL ON FUNCTION public.f06i01_actor_tenant_id FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.f06i01_actor_tenant_id TO daleel_f06i01_actor_group;

ALTER TABLE public.f06i01_leads ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.f06i01_leads FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS f06i01_leads_tenant_boundary ON public.f06i01_leads;
CREATE POLICY f06i01_leads_tenant_boundary ON public.f06i01_leads
    USING (tenant_id = public.f06i01_actor_tenant_id())
    WITH CHECK (tenant_id = public.f06i01_actor_tenant_id());

-- NOTE (intentional, documented): this policy enforces the TENANT boundary only.
-- It does NOT enforce ALL_TENANT/ASSIGNED/SELF -- an actor role with SELECT grant can,
-- via arbitrary SQL, read/update any row within ITS OWN tenant regardless of
-- assigned_membership_id. That is ACTOR_SCOPE_ARBITRARY_SQL=OPEN, proven by GATE-05.

COMMIT;
