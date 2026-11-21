"""Complete newly discovered provider-role dependencies on this I03 sandbox only."""
import json
import pathlib
import secrets
import sys

import bootstrap as b

runtime = pathlib.Path(sys.argv[1]).resolve(strict=True)
state = json.loads((runtime / "state.json").read_text(encoding="utf-8"))
if state["control"] != b.CONTROL or state["db"] != b.DB or state["port"] != b.PORT or state.get("system_identifier") in b.PROTECTED_IDS:
    raise RuntimeError("I03 identity mismatch")
meta = json.loads(b.call(["docker", "container", "inspect", state["container"]]).stdout)[0]
if meta["Config"]["Labels"].get("control") != b.CONTROL or not meta["State"]["Running"]:
    raise RuntimeError("I03 container label/state mismatch")
passwords = json.loads((runtime / "secrets.json").read_text(encoding="utf-8"))
extra = {"provider_auth_password": "daleel_f06i03_provider_auth_client",
         "provider_control_password": "daleel_f06i03_provider_control_client"}
for key, role in extra.items():
    if key not in passwords:
        passwords[key] = secrets.token_urlsafe(32)
        with (runtime / "pgpass").open("a", encoding="ascii") as file:
            file.write(f"127.0.0.1:5432:*:{role}:{passwords[key]}\n")
(runtime / "secrets.json").write_text(json.dumps(passwords), encoding="utf-8")
b.install_pgpass(state["container"], runtime)
roles = ("shared_bootstrap_password", "actor_a1_password", "actor_a2_password", "actor_b1_password",
         "actor_a4_password", "auth_client_password", "hostname_resolver_password",
         "bootstrap_client_password", "unused_client_password", "provider_auth_password", "provider_control_password")
b.sql(state["container"], (b.SRC / "000_provision_roles.sql").read_text(encoding="utf-8"),
      {key: passwords[key] for key in roles})
print("PROVISION_RETRY=PASS")
