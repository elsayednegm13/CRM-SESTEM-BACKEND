"""Bounded two-connection READ COMMITTED suspension probe; restores fixture."""
import json
import pathlib
import subprocess
import sys
import time

import bootstrap as b

runtime = pathlib.Path(sys.argv[1]).resolve(strict=True)
state = json.loads((runtime / "state.json").read_text(encoding="utf-8"))
if (state["control"], state["db"], state["port"], state["stage"]) != (b.CONTROL, b.DB, b.PORT, "fixtures_installed"):
    raise RuntimeError("sandbox identity mismatch")
c = state["container"]
meta = json.loads(b.call(["docker", "container", "inspect", c]).stdout)[0]
control = b.call(["docker", "exec", "-u", "postgres", c, "pg_controldata", "/var/lib/postgresql/data"]).stdout
if meta["Config"]["Labels"].get("control") != b.CONTROL or not meta["State"]["Running"] or f"Database system identifier:           {state['system_identifier']}" not in control:
    raise RuntimeError("sandbox ownership mismatch")
membership = "a1111111-0000-0000-0000-00000000a004"
row_query = f"SELECT status||'|'||authorization_version FROM public.tenant_staff_memberships WHERE id='{membership}'"
before = b.pg_query(c, row_query)
if not before.startswith("ACTIVE|"):
    raise RuntimeError("fixture membership state mismatch")
old_version = int(before.split("|")[1])
leads_before = b.pg_query(c, "SELECT md5(string_agg(to_jsonb(l)::text, '|' ORDER BY id)) FROM public.leads l")

def psql(role, sql):
    return subprocess.run(["docker", "exec", "-i", "-e", "PGPASSFILE=/tmp/scope.pgpass", c,
                           "psql", "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1",
                           "-h", "127.0.0.1", "-U", role, "-d", b.DB],
                          input=sql, text=True, capture_output=True)

def admin(sql):
    p = psql("postgres", sql)
    if p.returncode:
        raise RuntimeError("admin mutation failed: " + p.stderr[-400:])

actor_sql = ("BEGIN ISOLATION LEVEL READ COMMITTED; "
             "SELECT set_config('app.context_mode','TENANT',true); "
             "SELECT set_config('app.tenant_id','11111111-1111-1111-1111-111111111111',true); "
             "SELECT set_config('app.user_id','aaaaaaa4-0000-0000-0000-000000000004',true); "
             "SELECT count(*) FROM public.leads; SELECT pg_sleep(5); "
             "SELECT count(*) FROM public.leads; COMMIT;")
actor = subprocess.Popen(["docker", "exec", "-i", "-e", "PGPASSFILE=/tmp/scope.pgpass", c,
                          "psql", "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1",
                          "-h", "127.0.0.1", "-U", "daleel_f06i03_actor_a4", "-d", b.DB],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
changed = False
try:
    actor.stdin.write(actor_sql)
    actor.stdin.close()
    time.sleep(2)
    admin(f"UPDATE public.tenant_staff_memberships SET status='SUSPENDED', authorization_version=authorization_version+1 WHERE id='{membership}';")
    changed = True
    out = actor.stdout.read()
    err = actor.stderr.read()
    rc = actor.wait(timeout=20)
    lines = [x.strip() for x in out.splitlines() if x.strip().isdigit()]
    if rc != 0 or lines[-2:] != ["1", "0"]:
        raise RuntimeError(f"unexpected open transaction outcome rc={rc} counts={lines[-2:]} stderr={err[-400:]}")
    fresh = psql("daleel_f06i03_actor_a4", "BEGIN; SELECT set_config('app.context_mode','TENANT',true); "
                 "SELECT set_config('app.tenant_id','11111111-1111-1111-1111-111111111111',true); "
                 "SELECT set_config('app.user_id','aaaaaaa4-0000-0000-0000-000000000004',true); "
                 "SELECT count(*) FROM public.leads; ROLLBACK;")
    fresh_lines = [x.strip() for x in fresh.stdout.splitlines() if x.strip().isdigit()]
    if fresh.returncode or fresh_lines[-1:] != ["0"]:
        raise RuntimeError("fresh statement did not deny suspended actor")
finally:
    if changed:
        admin(f"UPDATE public.tenant_staff_memberships SET status='ACTIVE', authorization_version={old_version} WHERE id='{membership}';")
    if actor.poll() is None:
        actor.kill()
        actor.wait()
after = b.pg_query(c, row_query)
leads_after = b.pg_query(c, "SELECT md5(string_agg(to_jsonb(l)::text, '|' ORDER BY id)) FROM public.leads l")
if (after, leads_after) != (before, leads_before):
    raise RuntimeError("fixture was not restored")
evidence = {"system_identifier": state["system_identifier"], "open_read_committed_transaction_counts": [1, 0],
            "fresh_statement_after_commit_count": 0, "actor_rc": 0,
            "membership_before_after": before, "membership_restored": True,
            "leads_fingerprint_before": leads_before, "leads_fingerprint_after": leads_after,
            "limitations": "Does not prove immediate cancellation of a running statement or credential rotation."}
pathlib.Path(__file__).with_name("revocation_evidence.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
print("S10_SUSPEND_AFTER_COMMIT=PASS S10_RUNNING_STATEMENT=NOT_VERIFIED")
