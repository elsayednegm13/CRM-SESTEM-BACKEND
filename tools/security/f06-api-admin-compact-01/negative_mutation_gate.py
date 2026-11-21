"""Rollback-only negative controls on this round's labelled sandbox."""
import json
import pathlib
import re
import subprocess
import sys

import bootstrap as b

runtime = pathlib.Path(sys.argv[1]).resolve(strict=True)
state = json.loads((runtime / "state.json").read_text(encoding="utf-8"))
if (state["control"], state["db"], state["port"], state["stage"]) != (b.CONTROL, b.DB, b.PORT, "fixtures_installed"):
    raise RuntimeError("sandbox identity mismatch")
c = state["container"]
meta = json.loads(b.call(["docker", "container", "inspect", c]).stdout)[0]
if meta["Config"]["Labels"].get("control") != b.CONTROL or not meta["State"]["Running"]:
    raise RuntimeError("sandbox ownership mismatch")
control = b.call(["docker", "exec", "-u", "postgres", c, "pg_controldata", "/var/lib/postgresql/data"]).stdout
if f"Database system identifier:           {state['system_identifier']}" not in control:
    raise RuntimeError("cluster identifier mismatch")

def run(sql):
    p = subprocess.run(["docker", "exec", "-i", "-e", "PGPASSFILE=/tmp/scope.pgpass", c,
                        "psql", "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1",
                        "-h", "127.0.0.1", "-U", "postgres", "-d", b.DB],
                       input=sql, text=True, capture_output=True)
    if p.returncode != 0:
        raise RuntimeError("negative mutation SQL failed: " + re.sub(r"(?i)password=[^\s]+", "password=[redacted]", p.stderr[-600:]))
    return p.stdout.strip().splitlines()

before = b.pg_query(c, "SELECT md5(string_agg(to_jsonb(l)::text, '|' ORDER BY id)) FROM public.leads l")
policy_before = b.pg_query(c, "SELECT count(*) FROM pg_policies WHERE policyname='f06scope_leads_view' AND tablename='leads'")
grant_before = b.pg_query(c, "SELECT has_column_privilege('daleel_f06i03_actor_a4','public.tenant_staff_permission_grants','scope','INSERT')")
if policy_before != "1" or grant_before != "f":
    raise RuntimeError("baseline policy/ACL mismatch")
base = "SELECT set_config('app.context_mode','TENANT',true); SELECT set_config('app.tenant_id','11111111-1111-1111-1111-111111111111',true); SELECT set_config('app.user_id','aaaaaaa4-0000-0000-0000-000000000004',true);"
policy = run("BEGIN; DROP POLICY f06scope_leads_view ON public.leads; SET SESSION AUTHORIZATION daleel_f06i03_actor_a4; " + base +
             "SELECT count(*) FROM public.leads WHERE id='c0000005-0000-0000-0000-000000000005'; RESET SESSION AUTHORIZATION; ROLLBACK;")
if not policy or policy[-1] != "1":
    raise RuntimeError("policy removal was not detected as leakage")
grant = run("BEGIN; GRANT INSERT (id,tenant_id,membership_id,permission_key,scope,granted_by_membership_id,granted_at,created_at,updated_at) "
            "ON public.tenant_staff_permission_grants TO daleel_f06scope_actor_runtime; "
            "SET SESSION AUTHORIZATION daleel_f06i03_actor_a4; " + base +
            "INSERT INTO public.tenant_staff_permission_grants "
            "(id,tenant_id,membership_id,permission_key,scope,granted_by_membership_id,granted_at,created_at,updated_at) "
            "VALUES ('f0f0f0f0-0000-0000-0000-000000000001','11111111-1111-1111-1111-111111111111',"
            "'a1111111-0000-0000-0000-00000000a004','leads.manage','ALL_TENANT',"
            "'a1111111-0000-0000-0000-00000000a004',now(),now(),now()); "
            "SELECT public.f06scope_effective_scopes('leads.manage')::text; RESET SESSION AUTHORIZATION; ROLLBACK;")
if not grant or "ALL_TENANT" not in grant[-1]:
    raise RuntimeError("source grant mutation was not detected")
after = b.pg_query(c, "SELECT md5(string_agg(to_jsonb(l)::text, '|' ORDER BY id)) FROM public.leads l")
policy_after = b.pg_query(c, "SELECT count(*) FROM pg_policies WHERE policyname='f06scope_leads_view' AND tablename='leads'")
grant_after = b.pg_query(c, "SELECT has_column_privilege('daleel_f06i03_actor_a4','public.tenant_staff_permission_grants','scope','INSERT')")
if (after, policy_after, grant_after) != (before, policy_before, grant_before):
    raise RuntimeError("negative mutation was not restored")
evidence = {"system_identifier": state["system_identifier"], "policy_drop_detected": True,
            "source_grant_detected": True, "admin_session_authorization_actor_control": True,
            "all_mutations_rolled_back": True, "policy_restored": True, "acl_restored": True,
            "leads_fingerprint_before": before, "leads_fingerprint_after": after}
out = pathlib.Path(__file__).with_name("negative_mutation_evidence.json")
out.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
print("NEGATIVE_MUTATIONS=2/2 DETECTED RESTORE=PASS")
