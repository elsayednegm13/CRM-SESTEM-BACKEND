"""Transactional positive/negative direct grant checks on the owned sandbox."""
import json
from pathlib import Path
import re
import subprocess
import sys
import bootstrap as b

runtime = Path(sys.argv[1]).resolve(strict=True)
state = json.loads((runtime / "state.json").read_text(encoding="utf-8"))
if (state["control"],state["db"],state["port"],state["stage"]) != (b.CONTROL,b.DB,b.PORT,"fixtures_installed"):
    raise RuntimeError("wrong sandbox state")
c = state["container"]
meta = json.loads(b.call(["docker","container","inspect",c]).stdout)[0]
control = b.call(["docker","exec","-u","postgres",c,"pg_controldata","/var/lib/postgresql/data"]).stdout
if meta["Config"]["Labels"].get("control") != b.CONTROL or not meta["State"]["Running"] or f"Database system identifier:           {state['system_identifier']}" not in control:
    raise RuntimeError("wrong sandbox ownership")


def actor(role, body, user, tenant="11111111-1111-1111-1111-111111111111"):
    sql = ("BEGIN; SELECT set_config('app.context_mode','TENANT',true); "
           f"SELECT set_config('app.tenant_id','{tenant}',true); "
           f"SELECT set_config('app.user_id','{user}',true); " + body + " ROLLBACK;")
    p = subprocess.run(["docker","exec","-i","-e","PGPASSFILE=/tmp/scope.pgpass",c,
                        "psql","-X","-q","-A","-t","-v","ON_ERROR_STOP=1","-v","VERBOSITY=verbose",
                        "-h","127.0.0.1","-U",role,"-d",b.DB], input=sql,text=True,capture_output=True)
    m = re.search(r"\b([0-9][0-9A-Z]{4}):",p.stderr)
    return {"rc":p.returncode,"sqlstate":m.group(1) if m else None,
            "lines":p.stdout.strip().splitlines(),"error_class": "ERROR" if "ERROR:" in p.stderr else None}


fp = "SELECT md5(string_agg(k||':'||v,'|' ORDER BY k,v)) FROM (SELECT 'd' k,to_jsonb(x)::text v FROM public.tenant_staff_permission_grants x UNION ALL SELECT 'm',to_jsonb(x)::text FROM public.tenant_staff_memberships x UNION ALL SELECT 'e',to_jsonb(x)::text FROM public.tenant_staff_security_events x) q"
before = b.pg_query(c,fp)
grant_uuid = "e5555555-0000-0000-0000-000000000011"
audit_grant = "e6666666-0000-0000-0000-000000000011"
audit_revoke = "e6666666-0000-0000-0000-000000000012"
call = lambda op,target,key,scope,aid: ("SELECT public.f06team01_direct_permission(" +
    f"'{op}','{target}','{key}','{scope}','{grant_uuid}','{aid}');")
a5 = "daleel_f06team01_actor_a5"
user5 = "aaaaaaa5-0000-0000-0000-000000000005"
target4 = "a1111111-0000-0000-0000-00000000a004"
positive_sql = (call("GRANT",target4,"leads.view","SELF",audit_grant) +
                f"SELECT count(*) FROM public.tenant_staff_permission_grants WHERE membership_id='{target4}' AND permission_key='leads.view' AND scope='SELF' AND revoked_at IS NULL;"+
                f"SELECT authorization_version FROM public.tenant_staff_memberships WHERE id='{target4}';"+
                call("REVOKE",target4,"leads.view","SELF",audit_revoke)+
                f"SELECT count(*) FROM public.tenant_staff_permission_grants WHERE membership_id='{target4}' AND permission_key='leads.view' AND scope='SELF' AND revoked_at IS NULL;"+
                f"SELECT authorization_version FROM public.tenant_staff_memberships WHERE id='{target4}';"+
                "")
positive = actor(a5,positive_sql,user5)
expected_tail = ["2","1","2","3","0","3"]
if positive["rc"] != 0 or positive["lines"][-6:] != expected_tail:
    raise RuntimeError(f"positive grant/revoke failed rc={positive['rc']} state={positive['sqlstate']} tail={positive['lines'][-6:]}")
negative = []
for name,role,user,target,key,scope,tenant in [
    ("A4_NOT_MANAGER","daleel_f06i03_actor_a4","aaaaaaa4-0000-0000-0000-000000000004",target4,"leads.view","SELF","11111111-1111-1111-1111-111111111111"),
    ("A5_SELF",a5,user5,"a1111111-0000-0000-0000-00000000a005","leads.view","SELF","11111111-1111-1111-1111-111111111111"),
    ("A5_COMPANY_ADMIN",a5,user5,target4,"company.administer","ALL_TENANT","11111111-1111-1111-1111-111111111111"),
    ("A5_B_TARGET",a5,user5,"b1111111-0000-0000-0000-00000000b001","leads.view","SELF","22222222-2222-2222-2222-222222222222"),
    ("A5_SUSPENDED_TARGET",a5,user5,"a1111111-0000-0000-0000-00000000a003","leads.view","SELF","11111111-1111-1111-1111-111111111111"),
    ("A5_OVER_SCOPE",a5,user5,target4,"leads.view","ALL_TENANT","11111111-1111-1111-1111-111111111111"),
]:
    result = actor(role,call("GRANT",target,key,scope,audit_grant),user,tenant)
    negative.append({"id":name,"rc":result["rc"],"sqlstate":result["sqlstate"]})
    if result["rc"] != 3 or result["sqlstate"] != "42501":
        raise RuntimeError(f"negative gate failed {name} rc={result['rc']} state={result['sqlstate']}")
after = b.pg_query(c,fp)
if before != after:
    raise RuntimeError("SQL gate fingerprint drift")
catalog = b.pg_query(c,"SELECT r.rolname,p.prosecdef,coalesce(array_to_string(p.proconfig,','),''),EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE') FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner WHERE p.oid='public.f06team01_direct_permission(text,uuid,text,text,uuid,uuid)'::regprocedure")
if catalog != "daleel_f06team01_admin_executor|t|search_path=pg_catalog, public, pg_temp|f":
    raise RuntimeError("function owner/security/search_path/PUBLIC mismatch")
evidence = {"system_identifier":state["system_identifier"],"positive":positive,
            "negative":negative,"fingerprint_before":before,"fingerprint_after":after,"function_catalog":catalog}
(b.SRC/"g5_sql_evidence.json").write_text(json.dumps(evidence,indent=2)+"\n",encoding="utf-8")
print(f"G5_SQL_POSITIVE=GRANT_REVOKE NEGATIVE={len(negative)}/{len(negative)} FINGERPRINT=STABLE")
