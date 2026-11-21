"""Capture redacted final catalog and compare the original full data fingerprint."""
import ast
import json
import pathlib
import sys

import bootstrap as b

runtime = pathlib.Path(sys.argv[1]).resolve(strict=True)
state = json.loads((runtime / "state.json").read_text(encoding="utf-8"))
if (state["control"], state["db"], state["port"], state["stage"]) != (b.CONTROL, b.DB, b.PORT, "fixtures_installed"):
    raise RuntimeError("Sandbox identity mismatch")
c = state["container"]
meta = json.loads(b.call(["docker", "inspect", c]).stdout)[0]
control = b.call(["docker", "exec", "-u", "postgres", c, "pg_controldata", "/var/lib/postgresql/data"]).stdout
if meta["Config"]["Labels"].get("control") != b.CONTROL or str(state["system_identifier"]) not in control:
    raise RuntimeError("Sandbox ownership mismatch")
tree = ast.parse((b.SRC / "g2_http_gate.py").read_text(encoding="utf-8"))
fp_sql = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
              and any(isinstance(t, ast.Name) and t.id == "FP" for t in n.targets))
initial = json.loads((b.SRC / "g2_http_evidence.json").read_text(encoding="utf-8"))["results"][0]["fingerprint_before"]
final = b.pg_query(c, fp_sql)
queries = {
    "migration_count": "SELECT count(*) FROM public.migrations",
    "role_set_options": "SELECT string_agg(r.rolname||':'||m.rolname||':'||a.set_option,'|' ORDER BY r.rolname,m.rolname) FROM pg_auth_members a JOIN pg_roles r ON r.oid=a.member JOIN pg_roles m ON m.oid=a.roleid WHERE r.rolname LIKE 'daleel_f06%actor%'",
    "role_membership_closure": "WITH RECURSIVE edges AS (SELECT r.rolname actor,a.roleid,a.set_option,m.rolname target FROM pg_auth_members a JOIN pg_roles r ON r.oid=a.member JOIN pg_roles m ON m.oid=a.roleid WHERE r.rolname LIKE 'daleel_f06%actor%' UNION ALL SELECT e.actor,a.roleid,a.set_option,m.rolname FROM edges e JOIN pg_auth_members a ON a.member=e.roleid JOIN pg_roles m ON m.oid=a.roleid) SELECT coalesce(string_agg(actor||':'||target||':'||set_option,'|' ORDER BY actor,target),'') FROM edges",
    "function_catalog": "SELECT p.proname||':'||r.rolname||':'||p.prosecdef||':'||coalesce(array_to_string(p.proconfig,','),'')||':'||has_function_privilege('public',p.oid,'EXECUTE') FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner WHERE p.proname IN ('f06scope_assign_lead','f06team01_direct_permission') ORDER BY p.proname",
    "authority_write_acl": "SELECT string_agg(tbl||':'||priv||':'||has_table_privilege('daleel_f06team01_actor_a5','public.'||tbl,priv),'|' ORDER BY tbl,priv) FROM (VALUES ('roles','INSERT'),('roles','UPDATE'),('roles','DELETE'),('role_permissions','INSERT'),('role_permissions','UPDATE'),('role_permissions','DELETE'),('tenant_staff_memberships','UPDATE'),('tenant_staff_permission_grants','INSERT'),('tenant_staff_permission_grants','UPDATE'),('tenant_staff_permission_grants','DELETE'),('tenant_staff_security_events','INSERT')) x(tbl,priv)",
    "rls": "SELECT string_agg(relname||':'||relrowsecurity||':'||relforcerowsecurity,'|' ORDER BY relname) FROM pg_class WHERE relname IN ('leads','tenant_staff_memberships','tenant_staff_permission_grants')",
    "policy_count": "SELECT count(*) FROM pg_policies WHERE tablename='leads'",
    "enabled_user_trigger_count": "SELECT count(*) FROM pg_trigger WHERE tgrelid IN ('public.tenant_staff_permission_grants'::regclass,'public.tenant_staff_security_events'::regclass) AND NOT tgisinternal AND tgenabled='O'",
    "public_schema_create": "SELECT has_schema_privilege('public','public','CREATE')",
    "definer_roles": "SELECT string_agg(rolname||':'||rolcanlogin||':'||rolbypassrls||':'||rolsuper,'|' ORDER BY rolname) FROM pg_roles WHERE rolname IN ('daleel_f06scope_assigner','daleel_f06team01_admin_executor')",
    "clone_assign_function_count": "SELECT count(*) FROM pg_proc WHERE proname='f06scope_assign_lead'",
}
catalog = {k: b.pg_query(c, q, db="daleel_f06compact01_e4clone" if k == "clone_assign_function_count" else b.DB)
           for k, q in queries.items()}
if initial != final or catalog["migration_count"] != "38" or catalog["policy_count"] != "9" or catalog["enabled_user_trigger_count"] != "3":
    raise RuntimeError("Final fingerprint/catalog mismatch")
if catalog["public_schema_create"] != "f" or any(not part.endswith(":false:false:false") for part in catalog["definer_roles"].split("|")):
    raise RuntimeError("Function owner or schema trust mismatch")
if any(part.endswith(":true") for part in catalog["authority_write_acl"].split("|")):
    raise RuntimeError("Actor authority write privilege detected")
if any(not part.endswith(":false") for part in catalog["role_set_options"].split("|")):
    raise RuntimeError("SET ROLE path detected")
if any(not part.endswith(":false") or ":daleel_tenant_runtime:" in part for part in catalog["role_membership_closure"].split("|")):
    raise RuntimeError("Transitive SET ROLE path detected")
evidence = {"control": b.CONTROL, "container": c, "system_identifier": state["system_identifier"],
            "port": state["port"], "full_data_fingerprint_before": initial,
            "full_data_fingerprint_after": final, "full_data_fingerprint_restored": True,
            "catalog": catalog}
(b.SRC / "final_catalog_evidence.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
print("FINAL_CATALOG=PASS FULL_FINGERPRINT_RESTORED=YES")
