"""Bounded authorization-source write gate for this fresh sandbox only."""
import json
import pathlib
import re
import subprocess
import sys

import bootstrap as b

runtime = pathlib.Path(sys.argv[1]).resolve(strict=True)
phase = sys.argv[2]
if phase not in ("before", "after"):
    raise SystemExit("phase must be before or after")
state = json.loads((runtime / "state.json").read_text(encoding="utf-8"))
if state["control"] != b.CONTROL or state["db"] != b.DB or state["port"] != b.PORT or state["stage"] != "fixtures_installed":
    raise RuntimeError("sandbox identity/stage mismatch")
c = state["container"]
meta = json.loads(b.call(["docker", "container", "inspect", c]).stdout)[0]
if meta["Config"]["Labels"].get("control") != b.CONTROL or not meta["State"]["Running"]:
    raise RuntimeError("sandbox container mismatch")
control = b.call(["docker", "exec", "-u", "postgres", c, "pg_controldata", "/var/lib/postgresql/data"]).stdout
if f"Database system identifier:           {state['system_identifier']}" not in control:
    raise RuntimeError("sandbox cluster mismatch")


def actor(role, sql):
    p = subprocess.run(["docker", "exec", "-i", "-e", "PGPASSFILE=/tmp/scope.pgpass", c,
                        "psql", "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-v", "VERBOSITY=verbose",
                        "-h", "127.0.0.1", "-U", role, "-d", b.DB],
                       input=sql, text=True, capture_output=True)
    m = re.search(r"\b([0-9][0-9A-Z]{4}):", p.stderr)
    return {"rc": p.returncode, "sqlstate": m.group(1) if m else None,
            "lines": p.stdout.strip().splitlines()[-3:]}


fingerprint = """SELECT md5(string_agg(tab||':'||j, '|' ORDER BY tab,j)) FROM (
SELECT 'd' AS tab,to_jsonb(x)::text AS j FROM public.tenant_staff_permission_grants x
UNION ALL SELECT 'r',to_jsonb(x)::text FROM public.role_permissions x
UNION ALL SELECT 'a',to_jsonb(x)::text FROM public.tenant_staff_membership_roles x
) s"""
before = b.pg_query(c, fingerprint)
context = """BEGIN;
SELECT pg_catalog.set_config('app.context_mode','TENANT',true);
SELECT pg_catalog.set_config('app.tenant_id','11111111-1111-1111-1111-111111111111',true);
SELECT pg_catalog.set_config('app.user_id','aaaaaaa4-0000-0000-0000-000000000004',true);
"""
insert = """INSERT INTO public.tenant_staff_permission_grants
(id,tenant_id,membership_id,permission_key,scope,granted_by_membership_id,granted_at,created_at,updated_at)
VALUES ('e7777777-0000-0000-0000-000000000001','11111111-1111-1111-1111-111111111111',
'a1111111-0000-0000-0000-00000000a004','leads.manage','ALL_TENANT',
'a1111111-0000-0000-0000-00000000a004',now(),now(),now()) RETURNING permission_key,scope;
"""
attack = actor("daleel_f06i03_actor_a4", context + insert +
               "SELECT count(*) FROM public.tenant_staff_permission_grants WHERE membership_id='a1111111-0000-0000-0000-00000000a004' AND permission_key='leads.manage' AND scope='ALL_TENANT' AND revoked_at IS NULL; ROLLBACK;")
admin_context = context.replace("aaaaaaa4-0000-0000-0000-000000000004", "aaaaaaa1-0000-0000-0000-000000000001")
admin_insert = insert.replace("'a1111111-0000-0000-0000-00000000a004',now()", "'a1111111-0000-0000-0000-00000000a001',now()")
admin = actor("daleel_f06i02_shared_bootstrap", admin_context + admin_insert + "ROLLBACK;")
after = b.pg_query(c, fingerprint)
persisted = b.pg_query(c, "SELECT count(*) FROM public.tenant_staff_permission_grants WHERE id='e7777777-0000-0000-0000-000000000001'")
priv = b.pg_query(c, """SELECT has_column_privilege('daleel_f06i03_actor_a4','public.tenant_staff_permission_grants','scope','INSERT'),
has_table_privilege('daleel_f06i03_actor_a4','public.role_permissions','DELETE'),
has_column_privilege('daleel_f06i03_actor_a4','public.leads','name','UPDATE'),
has_column_privilege('daleel_f06i03_actor_a4','public.leads','assigned_membership_id','UPDATE')""")
evidence = {"phase": phase, "system_identifier": state["system_identifier"],
            "fingerprint_before": before, "fingerprint_after": after, "persisted_attack_rows": int(persisted),
            "actor_privileges_insert_grant_delete_role_update_lead_update_assignment": priv,
            "attack": {"rc": attack["rc"], "sqlstate": attack["sqlstate"], "output_tail": attack["lines"]},
            "authorized_shared_bootstrap": {"rc": admin["rc"], "sqlstate": admin["sqlstate"], "output_tail": admin["lines"]}}
(b.SRC / f"g2_auth_source_{phase}.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
if before != after or persisted != "0" or admin["rc"] != 0 or "leads.manage|ALL_TENANT" not in admin["lines"]:
    raise RuntimeError("fingerprint/authorized control failed")
if phase == "before" and (attack["rc"] != 0 or "leads.manage|ALL_TENANT" not in attack["lines"] or "1" not in attack["lines"]):
    raise RuntimeError("baseline grant escalation not reproduced")
if phase == "after" and (attack["rc"] == 0 or attack["sqlstate"] != "42501" or priv != "f|f|t|f"):
    raise RuntimeError("authorization-source deny failed")
print(f"G2_AUTH_SOURCE_{phase.upper()}=PASS attack_rc={attack['rc']} attack_sqlstate={attack['sqlstate']} admin_rc={admin['rc']} fingerprint_stable={before == after}")
