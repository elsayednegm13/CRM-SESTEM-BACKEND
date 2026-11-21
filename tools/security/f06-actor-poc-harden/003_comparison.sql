-- ============================================================================
-- F06 ACTOR POC — HARDENED (POC03) — 003: the two weaker models, kept for the
-- differential proof (GUC anchor vs tenant-only anchor vs tenant+actor anchor).
-- Run as superuser after 001, before 002 (002 loads rows into these tables).
-- ============================================================================

BEGIN;

-- (a) Today's product shape for leads: tenant-only predicate read from a GUC.
CREATE TABLE leads_baseline_guc (
    id             uuid PRIMARY KEY,
    tenant_id      uuid NOT NULL,
    owner_actor_id uuid NOT NULL,
    name           text NOT NULL
);
ALTER TABLE leads_baseline_guc OWNER TO h01_owner;
ALTER TABLE leads_baseline_guc ENABLE ROW LEVEL SECURITY;
ALTER TABLE leads_baseline_guc FORCE ROW LEVEL SECURITY;
CREATE POLICY leads_baseline_guc_all ON leads_baseline_guc FOR ALL
    USING (current_setting('app.context_mode', true) = 'TENANT'
           AND tenant_id = current_setting('app.tenant_id', true)::uuid)
    WITH CHECK (current_setting('app.context_mode', true) = 'TENANT'
                AND tenant_id = current_setting('app.tenant_id', true)::uuid);
REVOKE ALL ON TABLE leads_baseline_guc FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE leads_baseline_guc TO h01_shared_a;

-- (b) POC01's anchor: role pins the tenant, but no actor condition at all.
CREATE TABLE leads_tenant_only (
    id             uuid PRIMARY KEY,
    tenant_id      uuid NOT NULL,
    owner_actor_id uuid NOT NULL,
    name           text NOT NULL
);
ALTER TABLE leads_tenant_only OWNER TO h01_owner;
ALTER TABLE leads_tenant_only ENABLE ROW LEVEL SECURITY;
ALTER TABLE leads_tenant_only FORCE ROW LEVEL SECURITY;
CREATE POLICY leads_tenant_only_a ON leads_tenant_only FOR ALL
    TO h01_shared_a
    USING (tenant_id = '11111111-1111-1111-1111-111111111111'::uuid)
    WITH CHECK (tenant_id = '11111111-1111-1111-1111-111111111111'::uuid);
REVOKE ALL ON TABLE leads_tenant_only FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE leads_tenant_only TO h01_shared_a;

-- ---------------------------------------------------------------------------
-- Fingerprint: data + ownership + roles + memberships + ACLs (table AND
-- column) + policies + constraints + triggers + function security. Fails
-- closed: any error propagates, and the harness checks rc before comparing.
-- Superuser only.
-- ---------------------------------------------------------------------------
CREATE FUNCTION h01_fingerprint() RETURNS text
    LANGUAGE sql STABLE SECURITY INVOKER SET search_path = pg_catalog, public AS $$
    SELECT md5(string_agg(part, '|' ORDER BY part)) FROM (
        SELECT 'L:'||id||','||tenant_id||','||owner_actor_id||','||code||','||name AS part
          FROM public.leads_actor
        UNION ALL SELECT 'M:'||role_name||','||tenant_id||','||actor_id||','||actor_status||','||is_admin
          FROM public.actor_identity_map
        UNION ALL SELECT 'G:'||tenant_id||','||grantee_actor_id||','||capability
          FROM public.admin_grants
        UNION ALL SELECT 'BG:'||id||','||tenant_id||','||owner_actor_id||','||name
          FROM public.leads_baseline_guc
        UNION ALL SELECT 'TO:'||id||','||tenant_id||','||owner_actor_id||','||name
          FROM public.leads_tenant_only
        UNION ALL SELECT 'R:'||rolname||','||rolsuper||','||rolbypassrls||','||rolcreatedb||','
                           ||rolcreaterole||','||rolinherit||','||rolcanlogin||','||rolreplication
          FROM pg_roles WHERE rolname LIKE 'h01%'
        UNION ALL SELECT 'AM:'||m.roleid::regrole::text||','||m.member::regrole::text||','||m.admin_option
          FROM pg_auth_members m
          WHERE m.roleid::regrole::text LIKE 'h01%' OR m.member::regrole::text LIKE 'h01%'
        UNION ALL SELECT 'C:'||c.relname||','||c.relowner::regrole::text||','||c.relrowsecurity||','
                           ||c.relforcerowsecurity||','||coalesce(c.relacl::text,'-')
          FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
          WHERE n.nspname='public' AND c.relkind='r'
        UNION ALL SELECT 'A:'||c.relname||','||a.attname||','||coalesce(a.attacl::text,'-')
          FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid
          JOIN pg_namespace n ON n.oid=c.relnamespace
          WHERE n.nspname='public' AND c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped
        UNION ALL SELECT 'P:'||p.polrelid::regclass::text||','||p.polname||','||p.polcmd::text||','
                           ||coalesce(pg_get_expr(p.polqual,p.polrelid),'-')||','
                           ||coalesce(pg_get_expr(p.polwithcheck,p.polrelid),'-')||','
                           ||coalesce(array_to_string(p.polroles::regrole[],'+'),'-')
          FROM pg_policy p
        UNION ALL SELECT 'K:'||con.conrelid::regclass::text||','||con.conname||','||pg_get_constraintdef(con.oid)
          FROM pg_constraint con JOIN pg_class c ON c.oid=con.conrelid
          JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'
        UNION ALL SELECT 'T:'||t.tgrelid::regclass::text||','||t.tgname||','||t.tgenabled::text||','||pg_get_triggerdef(t.oid)
          FROM pg_trigger t WHERE NOT t.tgisinternal
        UNION ALL SELECT 'F:'||p.proname||','||p.prosecdef||','||p.proowner::regrole::text||','
                           ||coalesce(p.proacl::text,'-')||','||coalesce(array_to_string(p.proconfig,'+'),'-')
          FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public'
    ) s
$$;
REVOKE ALL ON FUNCTION h01_fingerprint() FROM PUBLIC;

COMMIT;
