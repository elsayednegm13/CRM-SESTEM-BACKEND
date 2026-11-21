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
-- F3 FIX (poc04-closeout): the prior fingerprint built each "part" by bare
-- '||','||' string concatenation of raw column values. Two adjacent
-- free-text columns (leads_actor.code, leads_actor.name in component 01)
-- can produce an IDENTICAL concatenated string from DIFFERENT underlying
-- data, e.g.:
--   A: code='x,y', name='z'   -> old text ...,x,y,z,...
--   B: code='x',   name='y,z' -> old text ...,x,y,z,...
-- This is a serialization ambiguity, not a SHA-256 collision: the bug is
-- that distinct inputs were mapped to the identical pre-image.
--
-- FIX: every component now builds its "part" as the TEXT of a
-- jsonb_build_array(...) over the typed column values (plus a leading
-- component-tag literal). JSON array serialization quotes and escapes
-- embedded commas/quotes/backslashes inside each string element and
-- preserves SQL NULL as JSON null (distinct from any string, including
-- the literal "-" the old code used as a NULL sentinel), so two different
-- field splits can never serialize to the same text. aclexplode()-derived
-- ACL lists are folded through fh_acl_list() below into a sorted jsonb
-- array of [grantee, privilege] pairs for the same reason.
-- ---------------------------------------------------------------------------
CREATE FUNCTION fh_acl_list(acl aclitem[]) RETURNS jsonb
    LANGUAGE sql STABLE SECURITY INVOKER SET search_path = pg_catalog, public AS $$
    SELECT coalesce(
        (SELECT jsonb_agg(
                   jsonb_build_array(
                       CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END,
                       a.privilege_type
                   )
                   ORDER BY (CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END),
                            a.privilege_type
                )
           FROM aclexplode(acl) a),
        '[]'::jsonb
    )
$$;
REVOKE ALL ON FUNCTION fh_acl_list(aclitem[]) FROM PUBLIC;

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
-- Output: sha256 over a deterministic, ordered canonical text built from
-- unambiguous JSON-array-encoded parts (see F3 FIX note above).
-- ---------------------------------------------------------------------------
CREATE FUNCTION fh_fingerprint() RETURNS text
    LANGUAGE sql STABLE SECURITY INVOKER SET search_path = pg_catalog, public AS $$
    SELECT encode(sha256(convert_to(string_agg(part, E'\n' ORDER BY part), 'UTF8')), 'hex')
    FROM (
        SELECT jsonb_build_array('01', id, tenant_id, owner_actor_id, code, name,
                   to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US'))::text AS part
          FROM public.leads_actor
        UNION ALL SELECT jsonb_build_array('02', role_name, tenant_id, actor_id, actor_status, is_admin)::text
          FROM public.actor_identity_map
        UNION ALL SELECT jsonb_build_array('03', tenant_id, grantee_actor_id, capability)::text
          FROM public.admin_grants
        UNION ALL SELECT jsonb_build_array('04', id, tenant_id, owner_actor_id, name)::text
          FROM public.leads_baseline_guc
        UNION ALL SELECT jsonb_build_array('05', id, tenant_id, owner_actor_id, name)::text
          FROM public.leads_tenant_only
        UNION ALL SELECT jsonb_build_array('06', rolname, rolsuper, rolbypassrls, rolcreatedb,
                   rolcreaterole, rolinherit, rolcanlogin, rolreplication, rolconnlimit,
                   coalesce(rolconfig, ARRAY[]::text[]))::text
          FROM pg_roles WHERE rolname LIKE 'fh%'
        UNION ALL SELECT jsonb_build_array('07', m.roleid::regrole::text, m.member::regrole::text,
                   m.admin_option, m.grantor::regrole::text)::text
          FROM pg_auth_members m
          WHERE m.roleid::regrole::text LIKE 'fh%' OR m.member::regrole::text LIKE 'fh%'
        UNION ALL SELECT jsonb_build_array('08', c.relname, c.relowner::regrole::text, c.relrowsecurity,
                   c.relforcerowsecurity, fh_acl_list(COALESCE(c.relacl, acldefault('r', c.relowner))))::text
          FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
          WHERE n.nspname='public' AND c.relkind='r'
        UNION ALL SELECT jsonb_build_array('09', c.relname, at.attname, fh_acl_list(at.attacl))::text
          FROM pg_attribute at JOIN pg_class c ON c.oid=at.attrelid
          JOIN pg_namespace n ON n.oid=c.relnamespace
          WHERE n.nspname='public' AND c.relkind='r' AND at.attnum>0 AND NOT at.attisdropped
        UNION ALL SELECT jsonb_build_array('10', c.relname, at.attname,
                   pg_get_expr(ad.adbin, ad.adrelid))::text
          FROM pg_attribute at JOIN pg_class c ON c.oid=at.attrelid
          JOIN pg_namespace n ON n.oid=c.relnamespace
          LEFT JOIN pg_attrdef ad ON ad.adrelid=at.attrelid AND ad.adnum=at.attnum
          WHERE n.nspname='public' AND c.relkind='r' AND at.attnum>0 AND NOT at.attisdropped
        UNION ALL SELECT jsonb_build_array('11', c.relname, at.attname,
                   format_type(at.atttypid,at.atttypmod), at.attnotnull)::text
          FROM pg_attribute at JOIN pg_class c ON c.oid=at.attrelid
          JOIN pg_namespace n ON n.oid=c.relnamespace
          WHERE n.nspname='public' AND c.relkind='r' AND at.attnum>0 AND NOT at.attisdropped
        UNION ALL SELECT jsonb_build_array('12', p.polrelid::regclass::text, p.polname, p.polcmd::text,
                   p.polpermissive, pg_get_expr(p.polqual,p.polrelid), pg_get_expr(p.polwithcheck,p.polrelid),
                   p.polroles::regrole[]::text[])::text
          FROM pg_policy p
        UNION ALL SELECT jsonb_build_array('13', con.conrelid::regclass::text, con.conname,
                   con.contype::text, pg_get_constraintdef(con.oid))::text
          FROM pg_constraint con JOIN pg_class c ON c.oid=con.conrelid
          JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'
        UNION ALL SELECT jsonb_build_array('14', t.tgrelid::regclass::text, t.tgname, t.tgenabled::text,
                   pg_get_triggerdef(t.oid), fp.prosrc)::text
          FROM pg_trigger t JOIN pg_proc fp ON fp.oid=t.tgfoid
          WHERE NOT t.tgisinternal
        UNION ALL SELECT jsonb_build_array('15', p.oid::regprocedure::text, p.prosecdef,
                   p.proowner::regrole::text, fh_acl_list(COALESCE(p.proacl, acldefault('f', p.proowner))),
                   coalesce(p.proconfig, ARRAY[]::text[]), md5(p.prosrc))::text
          FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public'
        UNION ALL SELECT jsonb_build_array('16', n.nspname, n.nspowner::regrole::text,
                   fh_acl_list(COALESCE(n.nspacl, acldefault('n', n.nspowner))))::text
          FROM pg_namespace n WHERE n.nspname='public'
        UNION ALL SELECT jsonb_build_array('17', d.defaclrole::regrole::text,
                   d.defaclnamespace::regnamespace::text, d.defaclobjtype::text, d.defaclacl::text)::text
          FROM pg_default_acl d
        UNION ALL SELECT jsonb_build_array('18', 'COVERAGE_MARKER', 'components=01..17')::text
    ) s
$$;
REVOKE ALL ON FUNCTION fh_fingerprint() FROM PUBLIC;

COMMIT;
