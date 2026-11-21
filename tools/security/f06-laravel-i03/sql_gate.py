"""Run bounded actor SQL controls on the identity-locked I03 sandbox only."""
import hashlib
import json
import pathlib
import re
import subprocess
import sys

import bootstrap as b

runtime = pathlib.Path(sys.argv[1]).resolve(strict=True)
state = json.loads((runtime / "state.json").read_text(encoding="utf-8"))
if state["control"] != b.CONTROL or state["db"] != b.DB or state["port"] != b.PORT or state["stage"] != "fixtures_installed":
    raise RuntimeError("I03 state/stage mismatch")
container = state["container"]
meta = json.loads(b.call(["docker", "container", "inspect", container]).stdout)[0]
if meta["Config"]["Labels"].get("control") != b.CONTROL or not meta["State"]["Running"]:
    raise RuntimeError("I03 container label/state mismatch")
control = b.call(["docker", "exec", "-u", "postgres", container, "pg_controldata", "/var/lib/postgresql/data"]).stdout
if f"Database system identifier:           {state['system_identifier']}" not in control:
    raise RuntimeError("I03 system identifier drift")


def actor(role, query):
    p = subprocess.run(["docker", "exec", "-i", "-e", "PGPASSFILE=/tmp/i03.pgpass", container,
                        "psql", "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-v", "VERBOSITY=verbose",
                        "-h", "127.0.0.1", "-U", role, "-d", b.DB], input=query,
                       text=True, capture_output=True)
    state = re.search(r"\b([0-9][0-9A-Z]{4}):", p.stderr)
    return {"rc": p.returncode, "sqlstate": state.group(1) if state else None,
            "stdout": p.stdout.strip(), "error_class": p.stderr.splitlines()[0][:160] if p.stderr else None}


roles = {"A1": "daleel_f06i02_actor_a1", "A2": "daleel_f06i02_actor_a2",
         "B1": "daleel_f06i02_actor_b1", "A4": "daleel_f06i03_actor_a4"}
A = "11111111-1111-1111-1111-111111111111"
B = "22222222-2222-2222-2222-222222222222"
fingerprint_query = "SELECT md5(string_agg(to_jsonb(l)::text, '|' ORDER BY id)) FROM public.leads l"
before = b.pg_query(container, fingerprint_query)
membership = b.pg_query(container, """SELECT member.rolname||':'||am.admin_option||':'||am.inherit_option||':'||am.set_option
 FROM pg_auth_members am JOIN pg_roles member ON member.oid=am.member JOIN pg_roles role ON role.oid=am.roleid
 WHERE role.rolname='daleel_tenant_runtime' AND member.rolname IN
 ('daleel_f06i02_actor_a1','daleel_f06i02_actor_a2','daleel_f06i02_actor_b1','daleel_f06i03_actor_a4') ORDER BY member.rolname""")
policy = b.pg_query(container, """SELECT permissive||':'||array_to_string(roles,',') FROM pg_policies
 WHERE schemaname='public' AND tablename='leads' AND policyname='f06i02_leads_actor_tenant_boundary'""")
objects = b.pg_query(container, """SELECT (SELECT count(*) FROM pg_class WHERE relowner='daleel_tenant_runtime'::regrole)
 +(SELECT count(*) FROM pg_proc WHERE proowner='daleel_tenant_runtime'::regrole)
 +(SELECT count(*) FROM pg_namespace WHERE nspowner='daleel_tenant_runtime'::regrole)""")
if len(membership.splitlines()) != 4 or any(not line.endswith(":false:true:false") for line in membership.splitlines()):
    raise RuntimeError("Actor membership options mismatch: " + repr(membership.splitlines()))
if not policy.startswith("RESTRICTIVE:") or any(role not in policy for role in roles.values()) or objects != "0":
    raise RuntimeError("Actor restrictive policy or group ownership mismatch")
results = []


def run(id, who, query, expect_rc, expect_state=None, expect_output=None, expect_absent=None):
    result = actor(roles[who], query)
    good = (result["rc"] == expect_rc and result["sqlstate"] == expect_state and
            (expect_output is None or expect_output in result["stdout"].splitlines()) and
            (expect_absent is None or expect_absent not in result["stdout"].splitlines()))
    results.append({"id": id, "actor": who, "rc": result["rc"], "sqlstate": result["sqlstate"],
                    "output": result["stdout"], "expected": good, "error_class": result["error_class"]})
    print(f"{id}={'PASS' if good else 'FAIL'} rc={result['rc']} sqlstate={result['sqlstate']}", flush=True)
    if not good:
        raise RuntimeError(f"SQL control failed: {id}")


def context(tenant, user, body):
    return ("BEGIN; SELECT set_config('app.context_mode','TENANT',true); "
            f"SELECT set_config('app.tenant_id','{tenant}',true); "
            f"SELECT set_config('app.user_id','{user}',true); {body} ROLLBACK;")


try:
    for who in roles:
        run(f"SETROLE-GROUP-{who}", who, "SET ROLE daleel_tenant_runtime;", 3, "42501")
        other = roles["B1"] if who != "B1" else roles["A1"]
        run(f"SETROLE-OTHER-{who}", who, f"SET ROLE {other};", 3, "42501")
    for who, tenant, user, wanted in (("B1", B, "bbbbbbb1-0000-0000-0000-000000000001", "1"),
                                       ("A1", A, "aaaaaaa1-0000-0000-0000-000000000001", "5"),
                                       ("A4", A, "aaaaaaa4-0000-0000-0000-000000000004", "5")):
        run(f"POSITIVE-{who}", who, context(tenant, user, f"SELECT count(*) FROM leads WHERE tenant_id='{tenant}';"), 0, None, wanted)
    for who, user in (("A1", "aaaaaaa1-0000-0000-0000-000000000001"),
                      ("A4", "aaaaaaa4-0000-0000-0000-000000000004")):
        run(f"GUC-B-SELECT-{who}", who, context(B, user, f"SELECT count(*) FROM leads WHERE tenant_id='{B}';"), 0, None, "0")
        run(f"GUC-B-UPDATE-{who}", who, context(B, user, "UPDATE leads SET name='attack' WHERE id='c0000003-0000-0000-0000-000000000003' RETURNING id;"), 0,
            expect_absent="c0000003-0000-0000-0000-000000000003")
        insert = ("INSERT INTO leads (id,tenant_id,name,pipeline_stage,status,assigned_membership_id,created_by_membership_id,created_at,updated_at) "
                  f"VALUES ('c9999999-0000-0000-0000-000000000001','{B}','attack','new','ACTIVE',"
                  "'b1111111-0000-0000-0000-00000000b001','b1111111-0000-0000-0000-00000000b001',now(),now());")
        run(f"GUC-B-INSERT-{who}", who, context(B, user, insert), 3, "42501")
    run("LEGIT-A1-UPDATE", "A1", context(A, "aaaaaaa1-0000-0000-0000-000000000001",
        "UPDATE leads SET name='temporary' WHERE id='c0000001-0000-0000-0000-000000000001' RETURNING id;"), 0, None,
        "c0000001-0000-0000-0000-000000000001")
    run("LEGIT-A4-UPDATE", "A4", context(A, "aaaaaaa4-0000-0000-0000-000000000004",
        "UPDATE leads SET name='temporary' WHERE id='c0000004-0000-0000-0000-000000000004' RETURNING id;"), 0, None,
        "c0000004-0000-0000-0000-000000000004")
    for who, user, membership, suffix in (
        ("A1", "aaaaaaa1-0000-0000-0000-000000000001", "a1111111-0000-0000-0000-00000000a001", "0001"),
        ("A4", "aaaaaaa4-0000-0000-0000-000000000004", "a1111111-0000-0000-0000-00000000a004", "0004"),
    ):
        new_id = f"c9999999-0000-0000-0000-00000000{suffix}"
        insert = ("INSERT INTO leads (id,tenant_id,name,pipeline_stage,status,assigned_membership_id,created_by_membership_id,created_at,updated_at) "
                  f"VALUES ('{new_id}','{A}','temporary','new','ACTIVE','{membership}','{membership}',now(),now()) RETURNING id;")
        run(f"LEGIT-{who}-INSERT", who, context(A, user, insert), 0, None, new_id)
finally:
    after = b.pg_query(container, fingerprint_query)
    evidence = {"system_identifier": state["system_identifier"], "membership": membership.splitlines(),
                "policy": policy, "group_owned_objects": int(objects), "before": before, "after": after,
                "fingerprint_unchanged": before == after, "results": results}
    (b.SRC / "sql_gate_evidence.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print(f"FINGERPRINT_UNCHANGED={before == after} SCENARIOS={len(results)}", flush=True)
    if before != after:
        raise RuntimeError("Lead baseline changed after SQL controls")
