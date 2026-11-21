"""Retry migration on the identity-locked I03 database; retain raw and redacted logs."""
import json
import pathlib
import subprocess
import sys

import bootstrap as b

runtime = pathlib.Path(sys.argv[1]).resolve(strict=True)
state = json.loads((runtime / "state.json").read_text(encoding="utf-8"))
if state["control"] != b.CONTROL or state["db"] != b.DB or state["port"] != b.PORT or state.get("system_identifier") in b.PROTECTED_IDS:
    raise RuntimeError("I03 state/identity mismatch")
passwords = json.loads((runtime / "secrets.json").read_text(encoding="utf-8"))
p = subprocess.run([str(b.PHP), "artisan", "migrate", "--force", "--no-interaction"], cwd=b.API,
                   env=b.php_env(runtime, passwords, admin=True), capture_output=True, text=True)
raw = p.stdout + p.stderr
path = runtime / "migrate-retry.raw.log"
path.write_text(raw, encoding="utf-8")
redacted = raw
for value in sorted(passwords.values(), key=len, reverse=True):
    redacted = redacted.replace(value, "[REDACTED]")
(b.SRC / "migrate-retry.redacted.log").write_text(redacted, encoding="utf-8")
print(f"MIGRATE_RC={p.returncode} RAW_LOG={path} REDACTED_LOG={b.SRC / 'migrate-retry.redacted.log'}")
sys.exit(p.returncode)
