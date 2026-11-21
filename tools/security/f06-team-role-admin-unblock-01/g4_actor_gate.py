"""Read and rollback-only A5 actor authority checks on this round's sandbox."""
import json
from pathlib import Path
import re
import subprocess
import sys

import bootstrap as b

runtime = Path(sys.argv[1]).resolve(strict=True)
state = json.loads((runtime / "state.json").read_text(encoding="utf-8"))
if (state["control"], state["port"], state["db"], state["stage"]) != (b.CONTROL, b.PORT, b.DB, "fixtures_installed"):
    raise RuntimeError("wrong sandbox state")
c = state["container"]
meta = json.loads(b.call(["docker", "container", "inspect", c]).stdout)[0]
if meta["Config"]["Labels"].get("control") != b.CONTROL or not meta["State"]["Running"]:
    raise RuntimeError("wrong sandbox ownership")
control = b.call(["docker", "exec", "-u", "postgres", c, "pg_controldata", "/var/lib/postgresql/data"]).stdout
if f"Database system identifier:           {state['system_identifier']}" not in control:
    raise RuntimeError("wrong cluster")


def actor(sql):
    p = subprocess.run(["docker", "exec", "-i", "-e", "PGPASSFILE=/tmp/scope.pgpass", c,
                        "psql", "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-v", "VERBOSITY=verbose",
                        "-h", "127.0.0.1", "-U", "daleel_f06team01_actor_a5", "-d", b.DB],
                       input=sql, text=True, capture_output=True)
    m = re.search(r"\b([0-9][0-9A-Z]{4}):", p.stderr)
    return {"rc": p.returncode, "sqlstate": m.group(1) if m else None,
            "lines": p.stdout.strip().splitlines()[-4:]}


fp = "SELECT md5(string_agg(k||':'||v,'|' ORDER BY k,v)) FROM (SELECT 'd' k,to_jsonb(x)::text v FROM public.tenant_staff_permission_grants x UNION ALL SELECT 'm',to_jsonb(x)::text FROM public.tenant_staff_memberships x UNION ALL SELECT 'r',to_jsonb(x)::text FROM public.roles x UNION ALL SELECT 'p',to_jsonb(x)::text FROM public.role_permissions x UNION ALL SELECT 'e',to_jsonb(x)::text FROM public.tenant_staff_security_events x) q"
before = b.pg_query(c, fp)
ctx = "BEGIN; SELECT set_config('app.context_mode','TENANT',true); SELECT set_config('app.tenant_id','11111111-1111-1111-1111-111111111111',true); SELECT set_config('app.user_id','aaaaaaa5-0000-0000-0000-000000000005',true); "
positive = actor(ctx + "SELECT session_user||'|'||current_user; SELECT actor_tenant||'|'||actor_membership||'|'||actor_user FROM public.f06scope_actor_claim(); SELECT public.f06scope_effective_scopes('leads.view')::text; ROLLBACK;")
if positive["rc"] or "{SELF}" not in positive["lines"] or not any("a1111111-0000-0000-0000-00000000a005" in x for x in positive["lines"]):
    raise RuntimeError("A5 positive SQL claim failed")
cases = {
    "SELF_GRANT_INSERT": "INSERT INTO public.tenant_staff_permission_grants(id,tenant_id,membership_id,permission_key,scope,granted_by_membership_id,granted_at,created_at,updated_at) VALUES ('e5555555-0000-0000-0000-000000000001','11111111-1111-1111-1111-111111111111','a1111111-0000-0000-0000-00000000a005','leads.view','ALL_TENANT','a1111111-0000-0000-0000-00000000a005',now(),now(),now());",
    "DIRECT_GRANT_UPDATE": "UPDATE public.tenant_staff_permission_grants SET revoked_at=now() WHERE membership_id='a1111111-0000-0000-0000-00000000a004';",
    "DIRECT_GRANT_DELETE": "DELETE FROM public.tenant_staff_permission_grants WHERE membership_id='a1111111-0000-0000-0000-00000000a004';",
    "ROLE_PERMISSION_INSERT": "INSERT INTO public.role_permissions(tenant_id,role_id,permission_key,scope) VALUES ('11111111-1111-1111-1111-111111111111','ea000005-0000-0000-0000-00000000000a','leads.manage','ALL_TENANT');",
    "ROLE_STATUS_UPDATE": "UPDATE public.roles SET status='ACTIVE' WHERE id='ea000005-0000-0000-0000-00000000000a';",
    "MEMBERSHIP_STATUS_UPDATE": "UPDATE public.tenant_staff_memberships SET authorization_version=authorization_version+1 WHERE id='a1111111-0000-0000-0000-00000000a005';",
    "MEMBERSHIP_ROLE_INSERT": "INSERT INTO public.tenant_staff_membership_roles(id,tenant_id,membership_id,role_id,assigned_by_membership_id,assigned_at,created_at,updated_at) VALUES ('e5555555-0000-0000-0000-000000000002','11111111-1111-1111-1111-111111111111','a1111111-0000-0000-0000-00000000a005','ea000001-0000-0000-0000-00000000000a','a1111111-0000-0000-0000-00000000a005',now(),now(),now());",
    "PERMISSION_METADATA_UPDATE": "UPDATE public.permissions SET delegable=true WHERE key='company.administer';",
    "SET_ROLE_LEGACY": "SET ROLE daleel_tenant_runtime;",
    "SET_ROLE_NARROW": "SET ROLE daleel_f06scope_actor_runtime;",
    "SET_ROLE_A1": "SET ROLE daleel_f06i02_actor_a1;",
}
results = []
for name, sql in cases.items():
    result = actor(ctx + sql + " ROLLBACK;")
    results.append({"id": name, "rc": result["rc"], "sqlstate": result["sqlstate"]})
    if result["rc"] != 3 or result["sqlstate"] != "42501":
        raise RuntimeError(f"authority denial failed: {name} rc={result['rc']} state={result['sqlstate']}")
after = b.pg_query(c, fp)
if before != after:
    raise RuntimeError("authority fingerprint drift")
catalog = b.pg_query(c, "SELECT m.admin_option,m.inherit_option,m.set_option FROM pg_auth_members m JOIN pg_roles a ON a.oid=m.member JOIN pg_roles g ON g.oid=m.roleid WHERE a.rolname='daleel_f06team01_actor_a5' AND g.rolname='daleel_f06scope_actor_runtime'")
if catalog != "f|t|f":
    raise RuntimeError("A5 group membership mismatch")
priv = b.pg_query(c, "SELECT has_table_privilege('daleel_f06team01_actor_a5','public.tenant_staff_permission_grants','INSERT'),has_column_privilege('daleel_f06team01_actor_a5','public.tenant_staff_permission_grants','scope','INSERT'),has_table_privilege('daleel_f06team01_actor_a5','public.roles','UPDATE'),has_column_privilege('daleel_f06team01_actor_a5','public.leads','name','UPDATE')")
if priv != "f|f|f|t":
    raise RuntimeError("A5 table/column ACL mismatch")
evidence = {"system_identifier": state["system_identifier"], "positive": positive,
            "negative_results": results, "authority_fingerprint_before": before,
            "authority_fingerprint_after": after, "membership_options": catalog, "effective_acl": priv}
(b.SRC / "g4_actor_evidence.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
print(f"G4_A5_POSITIVE=PASS DIRECT_NEGATIVE={len(results)}/{len(results)} FINGERPRINT=STABLE")
