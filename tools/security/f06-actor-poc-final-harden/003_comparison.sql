-- ============================================================================
-- F06 ACTOR POC — FINAL HARDEN (POC04) — 003: comparison models + fingerprint
-- ----------------------------------------------------------------------------
-- F3: the fingerprint is widened and its coverage is DECLARED, component by
--     component, so "FULL" is never claimed loosely. Any component that fails
--     to extract raises, so the fingerprint fails closed.
-- F4: fh_effective_public_execute() uses acldefault() when proacl IS NULL, so
--     a function left with PostgreSQL's default ACL (EXECUTE to PUBLIC) is
--     detected instead of silently passing.
--
-- Run as superuser after 001 and before 002.
-- ============================================================================

BEGIN;

-- (a) today's product shape: tenant-only predicate read from a GUC
CREATE TABLE leads_baseline_guc (
    id             uuid PRIMARY KEY,
    tenant_id      uuid NOT NULL,
    owner_actor_id uuid NOT NULL,
    name           text NOT NULL
);
ALTER TABLE leads_baseline_guc OWNER TO fh_owner;
ALTER TABLE leads_baseline_guc ENABLE ROW LEVEL SECURITY;
ALTER TABLE leads_baseline_guc FORCE ROW LEVEL SECURITY;
CREATE POLICY leads_baseline_guc_all ON leads_baseline_guc FOR ALL
    USING (current_setting('app.context_mode', true) = 'TENANT'
           AND tenant_id = current_setting('app.tenant_id', true)::uuid)
    WITH CHECK (current_setting('app.context_mode', true) = 'TENANT'
                AND tenant_id = current_setting('app.tenant_id', true)::uuid);
REVOKE ALL ON TABLE leads_baseline_guc FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE leads_baseline_guc TO fh_shared_a;

-- (b) POC01's anchor: role pins the tenant, no actor condition
CREATE TABLE leads_tenant_only (
    id             uuid PRIMARY KEY,
    tenant_id      uuid NOT NULL,
    owner_actor_id uuid NOT NULL,
    name           text NOT NULL
);
ALTER TABLE leads_tenant_only OWNER TO fh_owner;
ALTER TABLE leads_tenant_only ENABLE ROW LEVEL SECURITY;
ALTER TABLE leads_tenant_only FORCE ROW LEVEL SECURITY;
CREATE POLICY leads_tenant_only_a ON leads_tenant_only FOR ALL
    TO fh_shared_a
    USING (tenant_id = '11111111-1111-1111-1111-111111111111'::uuid)
    WITH CHECK (tenant_id = '11111111-1111-1111-1111-111111111111'::uuid);
REVOKE ALL ON TABLE leads_tenant_only FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE leads_tenant_only TO fh_shared_a;

-- ---------------------------------------------------------------------------
-- F4: effective PUBLIC EXECUTE detector.
-- proacl IS NULL means "PostgreSQL default ACL", which for a function is
-- EXECUTE to PUBLIC. acldefault('f', proowner) materialises that default so
-- the check cannot be fooled by a NULL.
-- Returns one row per public-schema function that is effectively executable
-- by PUBLIC (grantee 0).
-- ---------------------------------------------------------------------------
CREATE FUNCTION fh_effective_public_execute()
    RETURNS TABLE (func text, acl_source text)
    LANGUAGE sql STABLE SECURITY INVOKER SET search_path = pg_catalog, public AS $$
    SELECT p.oid::regprocedure::text,
           CASE WHEN p.proacl IS NULL THEN 'default_acl' ELSE 'explicit_acl' END
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) a
    WHERE n.nspname = 'public' AND a.grantee = 0 AND a.privilege_type = 'EXECUTE'
$$;
REVOKE ALL ON FUNCTION fh_effective_public_execute() FROM PUBLIC;

-- Effective schema privileges, same NULL-default treatment.
CREATE FUNCTION fh_effective_schema_acl()
    RETURNS TABLE (nsp text, grantee text, priv text, acl_source text)
    LANGUAGE sql STABLE SECURITY INVOKER SET search_path = pg_catalog, public AS $$
    SELECT n.nspname,
           CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END,
           a.privilege_type,
           CASE WHEN n.nspacl IS NULL THEN 'default_acl' ELSE 'explicit_acl' END
    FROM pg_namespace n
    CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl, acldefault('n', n.nspowner))) a
    WHERE n.nspname = 'public'
$$;
REVOKE ALL ON FUNCTION fh_effective_schema_acl() FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- F3: fingerprint with DECLARED coverage.
--
-- COVERED (each component raises on failure, so extraction is fail-closed):
--   01 rows of leads_actor incl. created_at
--   02 rows of actor_identity_map
--   03 rows of admin_grants
--   04 rows of leads_baseline_guc
--   05 rows of leads_tenant_only
--   06 role attributes for fh%
--   07 role memberships touching fh%
--   08 table owner / ENABLE RLS / FORCE RLS / table ACL (effective, incl. default)
--   09 column ACLs (effective, incl. default)
--   10 column defaults (pg_get_expr of adbin)
--   11 column type / notnull
--   12 policies incl. polpermissive, cmd, qual, with_check, roles
--   13 constraints (definitions)
--   14 triggers (definition + enabled state + the trigger function's body)
--   15 functions: prosecdef, owner, effective ACL, proconfig, AND prosrc body
--   16 schema ACL for public (effective, incl. default)
--   17 default privileges (pg_default_acl)
--
-- NOT_COVERED (declared, not claimed): sequences and their ACLs, extensions,
--   event triggers, publications/subscriptions, large objects, FDW/servers,
--   database- and role-level SET parameters (pg_db_role_setting), statistics,
--   physical layout, and anything outside schema public.
--
-- Output: sha256 over a deterministic, ordered canonical text.
-- ---------------------------------------------------------------------------
CREATE FUNCTION fh_fingerprint() RETURNS text
    LANGUAGE sql STABLE SECURITY INVOKER SET search_path = pg_catalog, public AS $$
    SELECT encode(sha256(convert_to(string_agg(part, E'\n' ORDER BY part), 'UTF8')), 'hex')
    FROM (
        SELECT '01:'||id||','||tenant_id||','||owner_actor_id||','||code||','||name||','
               ||to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US') AS part
          FROM public.leads_actor
        UNION ALL SELECT '02:'||role_name||','||tenant_id||','||actor_id||','||actor_status||','||is_admin
          FROM public.actor_identity_map
        UNION ALL SELECT '03:'||tenant_id||','||grantee_actor_id||','||capability
          FROM public.admin_grants
        UNION ALL SELECT '04:'||id||','||tenant_id||','||owner_actor_id||','||name
          FROM public.leads_baseline_guc
        UNION ALL SELECT '05:'||id||','||tenant_id||','||owner_actor_id||','||name
          FROM public.leads_tenant_only
        UNION ALL SELECT '06:'||rolname||','||rolsuper||','||rolbypassrls||','||rolcreatedb||','
                   ||rolcreaterole||','||rolinherit||','||rolcanlogin||','||rolreplication||','
                   ||rolconnlimit||','||coalesce(array_to_string(rolconfig,'+'),'-')
          FROM pg_roles WHERE rolname LIKE 'fh%'
        UNION ALL SELECT '07:'||m.roleid::regrole::text||','||m.member::regrole::text||','
                   ||m.admin_option||','||m.grantor::regrole::text
          FROM pg_auth_members m
          WHERE m.roleid::regrole::text LIKE 'fh%' OR m.member::regrole::text LIKE 'fh%'
        UNION ALL SELECT '08:'||c.relname||','||c.relowner::regrole::text||','||c.relrowsecurity||','
                   ||c.relforcerowsecurity||','
                   ||coalesce((SELECT string_agg(
                        (CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END)
                        ||':'||a.privilege_type, ';' ORDER BY
                        (CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END),
                        a.privilege_type)
                      FROM aclexplode(COALESCE(c.relacl, acldefault('r', c.relowner))) a), '-')
          FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
          WHERE n.nspname='public' AND c.relkind='r'
        UNION ALL SELECT '09:'||c.relname||','||at.attname||','
                   ||coalesce((SELECT string_agg(
                        (CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END)
                        ||':'||a.privilege_type, ';' ORDER BY
                        (CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END),
                        a.privilege_type)
                      FROM aclexplode(at.attacl) a), '-')
          FROM pg_attribute at JOIN pg_class c ON c.oid=at.attrelid
          JOIN pg_namespace n ON n.oid=c.relnamespace
          WHERE n.nspname='public' AND c.relkind='r' AND at.attnum>0 AND NOT at.attisdropped
        UNION ALL SELECT '10:'||c.relname||','||at.attname||','
                   ||coalesce(pg_get_expr(ad.adbin, ad.adrelid), '-')
          FROM pg_attribute at JOIN pg_class c ON c.oid=at.attrelid
          JOIN pg_namespace n ON n.oid=c.relnamespace
          LEFT JOIN pg_attrdef ad ON ad.adrelid=at.attrelid AND ad.adnum=at.attnum
          WHERE n.nspname='public' AND c.relkind='r' AND at.attnum>0 AND NOT at.attisdropped
        UNION ALL SELECT '11:'||c.relname||','||at.attname||','||format_type(at.atttypid,at.atttypmod)
                   ||','||at.attnotnull
          FROM pg_attribute at JOIN pg_class c ON c.oid=at.attrelid
          JOIN pg_namespace n ON n.oid=c.relnamespace
          WHERE n.nspname='public' AND c.relkind='r' AND at.attnum>0 AND NOT at.attisdropped
        UNION ALL SELECT '12:'||p.polrelid::regclass::text||','||p.polname||','||p.polcmd::text||','
                   ||p.polpermissive||','
                   ||coalesce(pg_get_expr(p.polqual,p.polrelid),'-')||','
                   ||coalesce(pg_get_expr(p.polwithcheck,p.polrelid),'-')||','
                   ||coalesce(array_to_string(p.polroles::regrole[],'+'),'-')
          FROM pg_policy p
        UNION ALL SELECT '13:'||con.conrelid::regclass::text||','||con.conname||','
                   ||con.contype::text||','||pg_get_constraintdef(con.oid)
          FROM pg_constraint con JOIN pg_class c ON c.oid=con.conrelid
          JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'
        UNION ALL SELECT '14:'||t.tgrelid::regclass::text||','||t.tgname||','||t.tgenabled::text||','
                   ||pg_get_triggerdef(t.oid)||','||coalesce(fp.prosrc,'-')
          FROM pg_trigger t JOIN pg_proc fp ON fp.oid=t.tgfoid
          WHERE NOT t.tgisinternal
        UNION ALL SELECT '15:'||p.oid::regprocedure::text||','||p.prosecdef||','
                   ||p.proowner::regrole::text||','
                   ||coalesce((SELECT string_agg(
                        (CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END)
                        ||':'||a.privilege_type, ';' ORDER BY
                        (CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END),
                        a.privilege_type)
                      FROM aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) a), '-')
                   ||','||coalesce(array_to_string(p.proconfig,'+'),'-')
                   ||','||md5(p.prosrc)
          FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public'
        UNION ALL SELECT '16:'||n.nspname||','||n.nspowner::regrole::text||','
                   ||coalesce((SELECT string_agg(
                        (CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END)
                        ||':'||a.privilege_type, ';' ORDER BY
                        (CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END),
                        a.privilege_type)
                      FROM aclexplode(COALESCE(n.nspacl, acldefault('n', n.nspowner))) a), '-')
          FROM pg_namespace n WHERE n.nspname='public'
        UNION ALL SELECT '17:'||d.defaclrole::regrole::text||','
                   ||coalesce(d.defaclnamespace::regnamespace::text,'-')||','
                   ||d.defaclobjtype::text||','||coalesce(d.defaclacl::text,'-')
          FROM pg_default_acl d
        UNION ALL SELECT '18:COVERAGE_MARKER,components=01..17'
    ) s
$$;
REVOKE ALL ON FUNCTION fh_fingerprint() FROM PUBLIC;

COMMIT;
