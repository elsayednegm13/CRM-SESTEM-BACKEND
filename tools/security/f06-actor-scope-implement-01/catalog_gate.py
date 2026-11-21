"""Nonsecret catalog evidence for the isolated actor-scope sandbox."""
import json
import pathlib
import sys

import bootstrap as b

runtime = pathlib.Path(sys.argv[1]).resolve(strict=True)
state = json.loads((runtime / "state.json").read_text(encoding="utf-8"))
if state["control"] != b.CONTROL or state["db"] != b.DB or state["port"] != b.PORT or state["stage"] != "fixtures_installed":
    raise RuntimeError("wrong sandbox")
c = state["container"]
meta = json.loads(b.call(["docker", "container", "inspect", c]).stdout)[0]
if meta["Config"]["Labels"].get("control") != b.CONTROL or not meta["State"]["Running"]:
    raise RuntimeError("wrong container")
control = b.call(["docker", "exec", "-u", "postgres", c, "pg_controldata", "/var/lib/postgresql/data"]).stdout
if f"Database system identifier:           {state['system_identifier']}" not in control:
    raise RuntimeError("wrong cluster")


def query(q):
    return b.pg_query(c, q).splitlines()


membership = query("""SELECT member.rolname,role.rolname,am.admin_option,am.inherit_option,am.set_option
FROM pg_auth_members am JOIN pg_roles member ON member.oid=am.member JOIN pg_roles role ON role.oid=am.roleid
WHERE member.rolname IN ('daleel_f06i02_actor_a1','daleel_f06i02_actor_a2','daleel_f06i02_actor_b1','daleel_f06i03_actor_a4') ORDER BY member.rolname,role.rolname""")
if len(membership) != 4 or any(not x.endswith("|f|t|f") or "|daleel_f06scope_actor_runtime|" not in x for x in membership):
    raise RuntimeError("actor membership options/chains mismatch")
flags = query("""SELECT rolname,rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,rolbypassrls FROM pg_roles
WHERE rolname LIKE 'daleel_f06scope_%' OR rolname IN ('daleel_f06i02_actor_a1','daleel_f06i02_actor_a2','daleel_f06i02_actor_b1','daleel_f06i03_actor_a4') ORDER BY rolname""")
if any(x.split("|")[2:] != ["f", "f", "f", "f"] for x in flags):
    raise RuntimeError("excess role privilege")
owner_count = query("""SELECT (SELECT count(*) FROM pg_class WHERE relowner='daleel_f06scope_actor_runtime'::regrole)
+(SELECT count(*) FROM pg_proc WHERE proowner='daleel_f06scope_actor_runtime'::regrole)
+(SELECT count(*) FROM pg_namespace WHERE nspowner='daleel_f06scope_actor_runtime'::regrole)""")
if owner_count != ["0"]:
    raise RuntimeError("actor runtime owns objects")
priv = query("""SELECT
has_schema_privilege('daleel_f06i03_actor_a4','public','CREATE'),
has_table_privilege('daleel_f06i03_actor_a4','public.role_permissions','DELETE'),
has_column_privilege('daleel_f06i03_actor_a4','public.tenant_staff_permission_grants','scope','INSERT'),
has_column_privilege('daleel_f06i03_actor_a4','public.leads','name','UPDATE'),
has_column_privilege('daleel_f06i03_actor_a4','public.leads','assigned_membership_id','UPDATE'),
has_table_privilege('daleel_f06i03_actor_a4','public.leads','DELETE'),
has_table_privilege('daleel_f06i03_actor_a4','public.leads','TRUNCATE'),
has_table_privilege('daleel_f06i03_actor_a4','public.leads','REFERENCES')""")
if priv != ["f|f|f|t|f|f|f|f"]:
    raise RuntimeError("effective ACL mismatch")
policies = query("""SELECT policyname,permissive,roles::text,cmd FROM pg_policies
WHERE schemaname='public' AND tablename='leads' AND policyname LIKE 'f06scope_%' ORDER BY policyname""")
if len(policies) != 4 or any("|RESTRICTIVE|{daleel_f06scope_actor_runtime}|" not in x for x in policies):
    raise RuntimeError("policy scope mismatch")
force = query("SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid='public.leads'::regclass")
if force != ["t|t"]:
    raise RuntimeError("FORCE RLS missing")
functions = query("""SELECT p.oid::regprocedure::text,owner.rolname,p.prosecdef,
coalesce(array_to_string(p.proconfig,','),''),
EXISTS (SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) acl
        WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE')
FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles owner ON owner.oid=p.proowner
WHERE n.nspname='public' AND p.proname LIKE 'f06scope_%' ORDER BY 1""")
if len(functions) != 5 or any(not x.endswith("|f") or "|t|" not in x or "pg_temp" not in x for x in functions):
    raise RuntimeError("function owner/security/EXECUTE mismatch")
default_acl = query("SELECT count(*) FROM pg_default_acl")
evidence = {"system_identifier": state["system_identifier"], "membership": membership,
            "role_flags": flags, "actor_runtime_owned_object_count": int(owner_count[0]),
            "effective_acl": priv[0], "leads_policies": policies, "leads_rls_force": force[0],
            "functions": functions, "default_acl_count": int(default_acl[0])}
(b.SRC / "catalog_evidence.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
print("CATALOG_GATE=PASS ACTOR_RUNTIME_OWNERSHIP=0 FORCE_RLS=YES PUBLIC_EXECUTE_NEW=NO")
