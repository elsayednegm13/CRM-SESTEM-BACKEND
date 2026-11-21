"""Check every authority-writing surface as actor A4, rollback only."""
import json
import pathlib
import re
import subprocess
import sys

import bootstrap as b

runtime = pathlib.Path(sys.argv[1]).resolve(strict=True)
state = json.loads((runtime / "state.json").read_text(encoding="utf-8"))
if state["control"] != b.CONTROL or state["stage"] != "fixtures_installed" or state["db"] != b.DB or state["port"] != b.PORT:
    raise RuntimeError("wrong sandbox")
c = state["container"]
meta = json.loads(b.call(["docker", "container", "inspect", c]).stdout)[0]
if meta["Config"]["Labels"].get("control") != b.CONTROL or not meta["State"]["Running"]:
    raise RuntimeError("wrong container")
control = b.call(["docker", "exec", "-u", "postgres", c, "pg_controldata", "/var/lib/postgresql/data"]).stdout
if f"Database system identifier:           {state['system_identifier']}" not in control:
    raise RuntimeError("wrong cluster")
common = """BEGIN;
SELECT set_config('app.context_mode','TENANT',true),
set_config('app.tenant_id','11111111-1111-1111-1111-111111111111',true),
set_config('app.user_id','aaaaaaa4-0000-0000-0000-000000000004',true);
"""
cases = {
    "ROLE_PERMISSION_INSERT": "INSERT INTO public.role_permissions (tenant_id,role_id,permission_key,scope) VALUES ('11111111-1111-1111-1111-111111111111','ea000003-0000-0000-0000-00000000000a','leads.manage','ALL_TENANT');",
    "ROLE_PERMISSION_DELETE": "DELETE FROM public.role_permissions WHERE role_id='ea000003-0000-0000-0000-00000000000a';",
    "ROLE_STATUS_UPDATE": "UPDATE public.roles SET status='ACTIVE' WHERE id='ea000003-0000-0000-0000-00000000000a';",
    "MEMBERSHIP_STATUS_UPDATE": "UPDATE public.tenant_staff_memberships SET status='ACTIVE' WHERE id='a1111111-0000-0000-0000-00000000a004';",
    "MEMBERSHIP_ROLE_INSERT": "INSERT INTO public.tenant_staff_membership_roles (id,tenant_id,membership_id,role_id,assigned_by_membership_id,assigned_at,created_at,updated_at) VALUES ('e7777777-0000-0000-0000-000000000002','11111111-1111-1111-1111-111111111111','a1111111-0000-0000-0000-00000000a004','ea000001-0000-0000-0000-00000000000a','a1111111-0000-0000-0000-00000000a004',now(),now(),now());",
    "MEMBERSHIP_ROLE_REVOKE": "UPDATE public.tenant_staff_membership_roles SET revoked_at=now(),revoked_by_membership_id='a1111111-0000-0000-0000-00000000a004' WHERE membership_id='a1111111-0000-0000-0000-00000000a004';",
    "DIRECT_GRANT_INSERT": "INSERT INTO public.tenant_staff_permission_grants (id,tenant_id,membership_id,permission_key,scope,granted_by_membership_id,granted_at,created_at,updated_at) VALUES ('e7777777-0000-0000-0000-000000000001','11111111-1111-1111-1111-111111111111','a1111111-0000-0000-0000-00000000a004','leads.manage','ALL_TENANT','a1111111-0000-0000-0000-00000000a004',now(),now(),now());",
    "DIRECT_GRANT_REVOKE": "UPDATE public.tenant_staff_permission_grants SET revoked_at=now(),revoked_by_membership_id='a1111111-0000-0000-0000-00000000a004' WHERE membership_id='a1111111-0000-0000-0000-00000000a004';",
    "PERMISSION_CATALOG_UPDATE": "UPDATE public.permissions SET status='ACTIVE' WHERE key='leads.manage';",
    "ROLE_GRANT": "GRANT daleel_tenant_runtime TO daleel_f06i03_actor_a4;",
    "SCHEMA_CREATE": "CREATE TABLE public.f06scope_forbidden(id integer);",
}
before = b.pg_query(c, "SELECT md5(string_agg(t||':'||j,'|' ORDER BY t,j)) FROM (SELECT 'r' t,to_jsonb(x)::text j FROM public.role_permissions x UNION ALL SELECT 'd',to_jsonb(x)::text FROM public.tenant_staff_permission_grants x UNION ALL SELECT 'm',to_jsonb(x)::text FROM public.tenant_staff_membership_roles x UNION ALL SELECT 's',to_jsonb(x)::text FROM public.tenant_staff_memberships x UNION ALL SELECT 'p',to_jsonb(x)::text FROM public.permissions x UNION ALL SELECT 'o',to_jsonb(x)::text FROM public.roles x) v")
results = []
for name, sql in cases.items():
    p = subprocess.run(["docker", "exec", "-i", "-e", "PGPASSFILE=/tmp/scope.pgpass", c,
                        "psql", "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-v", "VERBOSITY=verbose",
                        "-h", "127.0.0.1", "-U", "daleel_f06i03_actor_a4", "-d", b.DB],
                       input=common + sql + "ROLLBACK;", text=True, capture_output=True)
    m = re.search(r"\b([0-9][0-9A-Z]{4}):", p.stderr)
    result = {"id": name, "rc": p.returncode, "sqlstate": m.group(1) if m else None}
    results.append(result)
    if result["rc"] == 0 or result["sqlstate"] != "42501":
        raise RuntimeError("authority mutation not denied: " + name + " " + str(result))
after = b.pg_query(c, "SELECT md5(string_agg(t||':'||j,'|' ORDER BY t,j)) FROM (SELECT 'r' t,to_jsonb(x)::text j FROM public.role_permissions x UNION ALL SELECT 'd',to_jsonb(x)::text FROM public.tenant_staff_permission_grants x UNION ALL SELECT 'm',to_jsonb(x)::text FROM public.tenant_staff_membership_roles x UNION ALL SELECT 's',to_jsonb(x)::text FROM public.tenant_staff_memberships x UNION ALL SELECT 'p',to_jsonb(x)::text FROM public.permissions x UNION ALL SELECT 'o',to_jsonb(x)::text FROM public.roles x) v")
if before != after:
    raise RuntimeError("authority tables changed")
evidence = {"system_identifier": state["system_identifier"], "before": before, "after": after, "results": results}
(b.SRC / "g2_negative_controls.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
print(f"G2_NEGATIVE_CONTROLS={len(results)}/{len(results)} SHA_STABLE=YES")
