"""S01-S07/S09 bounded SQL controls on the labelled sandbox; writes rollback."""
import json
import pathlib
import re
import subprocess
import sys

import bootstrap as b

runtime = pathlib.Path(sys.argv[1]).resolve(strict=True)
state = json.loads((runtime / "state.json").read_text(encoding="utf-8"))
if state["control"] != b.CONTROL or state["db"] != b.DB or state["port"] != b.PORT or state["stage"] != "fixtures_installed":
    raise RuntimeError("sandbox identity/stage mismatch")
c = state["container"]
meta = json.loads(b.call(["docker", "container", "inspect", c]).stdout)[0]
if meta["Config"]["Labels"].get("control") != b.CONTROL or not meta["State"]["Running"]:
    raise RuntimeError("sandbox label/state mismatch")
control = b.call(["docker", "exec", "-u", "postgres", c, "pg_controldata", "/var/lib/postgresql/data"]).stdout
if f"Database system identifier:           {state['system_identifier']}" not in control:
    raise RuntimeError("cluster mismatch")
roles = {"A1": "daleel_f06i02_actor_a1", "A2": "daleel_f06i02_actor_a2",
         "A4": "daleel_f06i03_actor_a4", "B1": "daleel_f06i02_actor_b1"}
users = {"A1": "aaaaaaa1-0000-0000-0000-000000000001", "A2": "aaaaaaa2-0000-0000-0000-000000000002",
         "A4": "aaaaaaa4-0000-0000-0000-000000000004", "B1": "bbbbbbb1-0000-0000-0000-000000000001"}
tenants = {"A1": "11111111-1111-1111-1111-111111111111", "A2": "11111111-1111-1111-1111-111111111111",
           "A4": "11111111-1111-1111-1111-111111111111", "B1": "22222222-2222-2222-2222-222222222222"}
members = {"A1": "a1111111-0000-0000-0000-00000000a001", "A2": "a1111111-0000-0000-0000-00000000a002",
           "A4": "a1111111-0000-0000-0000-00000000a004", "B1": "b1111111-0000-0000-0000-00000000b001"}
L = {"A1": "c0000001-0000-0000-0000-000000000001", "A2": "c0000002-0000-0000-0000-000000000002",
     "B1": "c0000003-0000-0000-0000-000000000003", "ASSIGNED": "c0000004-0000-0000-0000-000000000004",
     "AUTHORED": "c0000005-0000-0000-0000-000000000005", "UNASSIGNED": "c0000006-0000-0000-0000-000000000006"}
fingerprint_sql = "SELECT md5(string_agg(to_jsonb(l)::text, '|' ORDER BY id)) FROM public.leads l"
before = b.pg_query(c, fingerprint_sql)
results = []


def run(case, who, body, expect_rc=0, expect_state=None, contains=None, absent=None, spoof=None):
    t = spoof or tenants[who]
    query = ("BEGIN; SELECT set_config('app.context_mode','TENANT',true); "
             f"SELECT set_config('app.tenant_id','{t}',true); "
             f"SELECT set_config('app.user_id','{users[who]}',true); {body} ROLLBACK;")
    p = subprocess.run(["docker", "exec", "-i", "-e", "PGPASSFILE=/tmp/scope.pgpass", c,
                        "psql", "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-v", "VERBOSITY=verbose",
                        "-h", "127.0.0.1", "-U", roles[who], "-d", b.DB],
                       input=query, text=True, capture_output=True)
    m = re.search(r"\b([0-9][0-9A-Z]{4}):", p.stderr)
    sqlstate = m.group(1) if m else None
    lines = p.stdout.strip().splitlines()
    okay = (p.returncode == expect_rc and sqlstate == expect_state
            and (contains is None or contains in lines)
            and (absent is None or absent not in lines))
    results.append({"id": case, "actor": who, "rc": p.returncode, "sqlstate": sqlstate,
                    "expected": okay, "output_tail": lines[-2:]})
    if not okay:
        raise RuntimeError("SQL scope control failed: " + case + " rc=" + str(p.returncode) + " state=" + str(sqlstate))


try:
    for who, count in (("A1", "5"), ("A2", "1"), ("A4", "1"), ("B1", "1")):
        run("S01-COUNT-" + who, who, "SELECT count(*) FROM public.leads;", contains=count)
    run("S02-A4-AUTHORED-HIDDEN", "A4", f"SELECT count(*) FROM public.leads WHERE id='{L['AUTHORED']}';", contains="0")
    run("S02-A2-ASSIGNED-HIDDEN", "A2", f"SELECT count(*) FROM public.leads WHERE id='{L['ASSIGNED']}';", contains="0")
    run("S02-A4-SPOOF-B", "A4", f"SELECT count(*) FROM public.leads WHERE id='{L['B1']}';", contains="0", spoof=tenants["B1"])
    run("S02-A4-JOIN-HIDDEN", "A4", f"SELECT count(*) FROM public.leads l JOIN public.tenant_staff_memberships m ON m.tenant_id=l.tenant_id AND m.id=l.assigned_membership_id WHERE l.id='{L['AUTHORED']}';", contains="0")
    run("S03-A4-UPDATE-OWN", "A4", f"UPDATE public.leads SET name='scope-test' WHERE id='{L['ASSIGNED']}' RETURNING id;", contains=L["ASSIGNED"])
    run("S03-A4-UPDATE-OTHER", "A4", f"UPDATE public.leads SET name='scope-test' WHERE id='{L['AUTHORED']}' RETURNING id;", absent=L["AUTHORED"])
    run("S03-A2-UPDATE-OWN", "A2", f"UPDATE public.leads SET pipeline_stage='contacted' WHERE id='{L['A2']}' RETURNING id;", contains=L["A2"])
    base_id = "c8888888-0000-0000-0000-000000000001"
    def insert(tenant, assigned, creator):
        assigned_sql = "NULL" if assigned is None else "'" + assigned + "'"
        return ("INSERT INTO public.leads (id,tenant_id,name,pipeline_stage,status,assigned_membership_id,created_by_membership_id,created_at,updated_at) "
                f"VALUES ('{base_id}','{tenant}','scope-insert','new','ACTIVE',{assigned_sql},'{creator}',now(),now()) RETURNING id;")
    run("S04-A4-INSERT-OWN", "A4", insert(tenants["A4"],members["A4"],members["A4"]), contains=base_id)
    run("S04-A4-CREATOR-SPOOF", "A4", insert(tenants["A4"],members["A4"],members["A1"]), 3, "42501")
    run("S04-A4-ASSIGN-SPOOF", "A4", insert(tenants["A4"],members["A1"],members["A4"]), 3, "42501")
    run("S04-A4-NULL-ASSIGN", "A4", insert(tenants["A4"],None,members["A4"]), 3, "42501")
    run("S04-A4-TENANT-B", "A4", insert(tenants["B1"],members["B1"],members["A4"]), 3, "42501")
    run("S04-A1-NULL-ASSIGN", "A1", insert(tenants["A1"],None,members["A1"]), contains=base_id)
    for col,value in (("assigned_membership_id",members["A1"]), ("created_by_membership_id",members["A4"]),
                      ("tenant_id",tenants["B1"]), ("id",base_id)):
        run("S05-A4-DIRECT-" + col.upper(), "A4",
            f"UPDATE public.leads SET {col}='{value}' WHERE id='{L['ASSIGNED']}' RETURNING id;", 3, "42501")
    run("S05-A1-DIRECT-ASSIGN", "A1",
        f"UPDATE public.leads SET assigned_membership_id='{members['A4']}' WHERE id='{L['UNASSIGNED']}';", 3, "42501")
    run("S06-A1-DEFINER", "A1", f"SELECT public.f06scope_assign_lead('{L['UNASSIGNED']}','{members['A4']}');", contains=L["UNASSIGNED"])
    run("S06-A4-DEFINER-DENY", "A4", f"SELECT public.f06scope_assign_lead('{L['UNASSIGNED']}','{members['A4']}');", 3, "42501")
    run("S06-A2-DEFINER-DENY", "A2", f"SELECT public.f06scope_assign_lead('{L['UNASSIGNED']}','{members['A4']}');", 3, "42501")
    run("S06-A1-TARGET-B", "A1", f"SELECT public.f06scope_assign_lead('{L['UNASSIGNED']}','{members['B1']}');", 3, "42501")
    run("S07-A1-DELETE-DENY", "A1", f"DELETE FROM public.leads WHERE id='{L['A1']}';", 3, "42501")
    run("S07-A4-DELETE-DENY", "A4", f"DELETE FROM public.leads WHERE id='{L['ASSIGNED']}';", 3, "42501")
    run("S09-A4-SET-GROUP-DENY", "A4", "SET ROLE daleel_f06scope_actor_runtime;", 3, "42501")
    run("S09-A4-SET-OLD-GROUP-DENY", "A4", "SET ROLE daleel_tenant_runtime;", 3, "42501")
    run("S09-A4-SET-A1-DENY", "A4", "SET ROLE daleel_f06i02_actor_a1;", 3, "42501")
finally:
    after = b.pg_query(c, fingerprint_sql)
    evidence = {"system_identifier": state["system_identifier"], "before": before, "after": after,
                "fingerprint_unchanged": before == after, "results": results}
    (b.SRC / "sql_scope_evidence.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    if before != after:
        raise RuntimeError("Lead fingerprint changed")
print(f"SQL_SCOPE_GATE={len(results)}/{len(results)} FINGERPRINT_UNCHANGED=YES")
