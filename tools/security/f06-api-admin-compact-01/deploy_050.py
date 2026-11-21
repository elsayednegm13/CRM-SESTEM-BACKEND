"""Apply the sandbox-only admin overlay to this round's verified cluster."""
import json
from pathlib import Path
import sys
import bootstrap as b

runtime = Path(sys.argv[1]).resolve(strict=True)
state = json.loads((runtime / "state.json").read_text(encoding="utf-8"))
if (state["control"],state["db"],state["port"],state["stage"]) != (b.CONTROL,b.DB,b.PORT,"fixtures_installed"):
    raise RuntimeError("wrong sandbox state")
c = state["container"]
meta = json.loads(b.call(["docker","container","inspect",c]).stdout)[0]
if meta["Config"]["Labels"].get("control") != b.CONTROL or not meta["State"]["Running"]:
    raise RuntimeError("wrong sandbox ownership")
control = b.call(["docker","exec","-u","postgres",c,"pg_controldata","/var/lib/postgresql/data"]).stdout
if f"Database system identifier:           {state['system_identifier']}" not in control:
    raise RuntimeError("wrong system identifier")
b.sql(c,(b.SRC/"050_direct_permission_function.sql").read_text(encoding="utf-8"))
print("ADMIN_OVERLAY_050=APPLIED_TO_OWNED_SANDBOX")
