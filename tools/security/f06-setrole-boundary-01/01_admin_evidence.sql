\pset format unaligned
\pset fieldsep |
\pset tuples_only on
SELECT 'SERVER', current_database(), current_setting('server_version'), (SELECT count(*) FROM migrations);
SELECT 'MEMBERSHIP', parent.rolname, child.rolname, m.admin_option, m.inherit_option, m.set_option
FROM pg_auth_members m JOIN pg_roles parent ON parent.oid=m.roleid JOIN pg_roles child ON child.oid=m.member
WHERE child.rolname IN ('daleel_f06i02_actor_a1','daleel_f06i02_actor_a2','daleel_f06i02_actor_b1','daleel_tenant_runtime')
ORDER BY parent.rolname, child.rolname;
SELECT 'ROLE', rolname, rolcanlogin, rolsuper, rolbypassrls, rolcreaterole, rolinherit
FROM pg_roles WHERE rolname IN ('daleel_f06i02_actor_a1','daleel_f06i02_actor_a2','daleel_f06i02_actor_b1','daleel_tenant_runtime') ORDER BY rolname;
SELECT 'LEADS_RLS', relrowsecurity, relforcerowsecurity, pg_get_userbyid(relowner), (SELECT count(*) FROM leads) FROM pg_class WHERE oid='public.leads'::regclass;
SELECT 'LEADS_COUNTS', tenant_id, count(*) FROM public.leads GROUP BY tenant_id ORDER BY tenant_id;
SELECT 'POLICY', policyname, permissive, roles::text, cmd FROM pg_policies WHERE schemaname='public' AND tablename='leads' ORDER BY policyname;
SELECT 'MAPPING_OWNER', pg_get_userbyid(relowner) FROM pg_class WHERE oid='public.f06i02_actor_sql_identity_map'::regclass;
SELECT 'FUNCTION_OWNER', pg_get_userbyid(proowner), prosecdef FROM pg_proc WHERE oid='public.f06i02_actor_tenant_id()'::regprocedure;
SELECT 'LEADS_PRIV', r.rolname, has_table_privilege(r.rolname,'public.leads','SELECT'), has_table_privilege(r.rolname,'public.leads','UPDATE'), has_table_privilege(r.rolname,'public.leads','INSERT') FROM pg_roles r WHERE r.rolname IN ('daleel_f06i02_actor_a1','daleel_f06i02_actor_a2','daleel_f06i02_actor_b1','daleel_tenant_runtime') ORDER BY r.rolname;
