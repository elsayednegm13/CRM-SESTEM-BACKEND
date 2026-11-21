"""Diagnostic HTTP Host probe. No credential, cookie, or business write."""
import json
import pathlib
import socket
import subprocess
import sys
import time

import bootstrap as b

runtime = pathlib.Path(sys.argv[1]).resolve(strict=True)
state = json.loads((runtime / "state.json").read_text(encoding="utf-8"))
if state["control"] != b.CONTROL or state["stage"] != "fixtures_installed":
    raise RuntimeError("I03 state mismatch")
passwords = json.loads((runtime / "secrets.json").read_text(encoding="utf-8"))
log = (runtime / "host_probe_server.raw.log").open("w", encoding="utf-8")
proc = subprocess.Popen([str(b.PHP), "artisan", "serve", "--no-reload", "--host=127.0.0.1", "--port=18081"],
                        cwd=b.API, env=b.php_env(runtime, passwords), stdout=log, stderr=subprocess.STDOUT)
try:
    for _ in range(40):
        try:
            with socket.create_connection(("127.0.0.1", 18081), timeout=1):
                break
        except OSError:
            time.sleep(0.25)
    result = subprocess.run(["curl.exe", "--noproxy", "*", "-v", "--max-time", "15", "-H",
                             "Host: tenant-a.f06i03.localhost", "-H", "Origin: http://tenant-a.f06i03.localhost:18081",
                             "-H", "Accept: application/json", "http://127.0.0.1:18081/api/v1/company/leads"],
                            cwd=b.API, capture_output=True, text=True)
    print("CURL_RC", result.returncode)
    for line in result.stderr.splitlines():
        if line.startswith("> Host:") or line.startswith("< HTTP/"):
            print(line)
    print("BODY", result.stdout[:240])
finally:
    if proc.poll() is None:
        subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], capture_output=True)
    proc.wait(timeout=10)
    log.close()
