"""Real curl/cookie/CSRF Laravel wire gate on the labelled I03 sandbox only."""
import json
import pathlib
import secrets
import socket
import subprocess
import sys
import time
import urllib.parse

import bootstrap as b

runtime = pathlib.Path(sys.argv[1]).resolve(strict=True)
state = json.loads((runtime / "state.json").read_text(encoding="utf-8"))
if state["control"] != b.CONTROL or state["stage"] != "fixtures_installed" or state["db"] != b.DB or state["port"] != b.PORT:
    raise RuntimeError("I03 state/stage mismatch")
container = state["container"]
meta = json.loads(b.call(["docker", "container", "inspect", container]).stdout)[0]
if meta["Config"]["Labels"].get("control") != b.CONTROL or not meta["State"]["Running"]:
    raise RuntimeError("I03 container label/state mismatch")
control = b.call(["docker", "exec", "-u", "postgres", container, "pg_controldata", "/var/lib/postgresql/data"]).stdout
if str(state["system_identifier"]) not in control:
    raise RuntimeError("I03 system identifier drift")
passwords = json.loads((runtime / "secrets.json").read_text(encoding="utf-8"))
PORT = 18081
RUN_ID = time.strftime("%Y%m%dT%H%M%S")
with socket.socket() as sock:
    sock.bind(("127.0.0.1", PORT))
HOSTS = {"A": "tenant-a.f06i03.localhost", "B": "tenant-b.f06i03.localhost", "BAD": "invalid.f06i03.localhost"}
IDS = {"A1": "c0000001-0000-0000-0000-000000000001",
       "A2": "c0000002-0000-0000-0000-000000000002",
       "B1": "c0000003-0000-0000-0000-000000000003",
       "A4_ASSIGNED": "c0000004-0000-0000-0000-000000000004",
       "A4_AUTHORED": "c0000005-0000-0000-0000-000000000005",
       "A_UNASSIGNED": "c0000006-0000-0000-0000-000000000006"}
DB_FINGERPRINT = "SELECT md5(string_agg(to_jsonb(l)::text, '|' ORDER BY id)) FROM public.leads l"
baseline = b.pg_query(container, DB_FINGERPRINT)
restore_sql = b.pg_query(container, """SELECT string_agg('UPDATE public.leads SET name='||quote_literal(name)||
 ',assigned_membership_id='||quote_literal(assigned_membership_id::text)||'::uuid,updated_at='||
 quote_literal(updated_at::text)||'::timestamptz WHERE id='||quote_literal(id::text)||'::uuid;', E'\\n')
 FROM public.leads WHERE id IN ('c0000004-0000-0000-0000-000000000004','c0000006-0000-0000-0000-000000000006')""")
if not restore_sql or restore_sql.count("UPDATE public.leads") != 2:
    raise RuntimeError("Cannot capture lead restoration baseline")
results = []


def request(flag, who, tenant, method, path, *, payload=None, csrf=None, cookie_override=None):
    host = HOSTS[tenant]
    jar = runtime / f"http_{RUN_ID}_{flag}_{who}.jar"
    headers = runtime / f"http_{RUN_ID}_{flag}_{who}.headers"
    body = runtime / f"http_{RUN_ID}_{flag}_{who}.body"
    argv = ["curl.exe", "--noproxy", "*", "-k", "-sS", "--max-time", "12",
            "--resolve", f"{host}:18082:127.0.0.1",
            "-D", str(headers), "-o", str(body), "-w", "%{http_code}", "-X", method,
            "-H", "Accept: application/json", "-H", f"Origin: https://{host}:18082",
            "-b", str(jar), "-c", str(jar)]
    if csrf:
        csrf_file = runtime / f"http_{RUN_ID}_{flag}_{who}.csrf.header"
        csrf_file.write_text(f"X-XSRF-TOKEN: {csrf}\n", encoding="utf-8")
        argv.extend(["-H", "@" + str(csrf_file)])
    if cookie_override:
        cookie_file = runtime / f"http_{RUN_ID}_{flag}_{who}.cookie.header"
        cookie_file.write_text(f"Cookie: {cookie_override}\n", encoding="utf-8")
        argv.extend(["-H", "@" + str(cookie_file)])
    if payload is not None:
        req_file = runtime / f"http_{RUN_ID}_{flag}_{who}.request.json"
        req_file.write_text(json.dumps(payload), encoding="utf-8")
        argv.extend(["-H", "Content-Type: application/json", "--data-binary", "@" + str(req_file)])
    argv.append(f"https://{host}:18082{path}")
    p = subprocess.run(argv, cwd=b.API, capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"curl rc={p.returncode} for {flag}/{who}/{path}")
    try:
        parsed = json.loads(body.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        parsed = None
    status = int(p.stdout.strip())
    return status, parsed, jar


def token(jar):
    for line in jar.read_text(encoding="utf-8").splitlines():
        if line and (not line.startswith("#") or line.startswith("#HttpOnly_")):
            parts = line.split("\t")
            if len(parts) >= 7 and parts[-2] == "XSRF-TOKEN":
                return urllib.parse.unquote(parts[-1])
    raise RuntimeError("XSRF cookie absent")


def session_cookie(jar):
    for line in jar.read_text(encoding="utf-8").splitlines():
        if line and (not line.startswith("#") or line.startswith("#HttpOnly_")):
            parts = line.split("\t")
            if len(parts) >= 7 and parts[-2].endswith("session"):
                return parts[-2] + "=" + parts[-1]
    raise RuntimeError("Session cookie absent")


def record(id, status, data=None, expected=None, expected_status=None):
    ids = []
    keysets = []
    canonical = []
    if isinstance(data, dict) and isinstance(data.get("data"), list):
        rows = [row for row in data["data"] if isinstance(row, dict)]
        ids = sorted(row.get("id") for row in rows)
        keysets = sorted({tuple(sorted(row.keys())) for row in rows})
        canonical = sorted([{key: row.get(key) for key in ("id", "name", "assigned_membership_id", "created_by_membership_id", "status")}
                            for row in rows], key=lambda row: row["id"])
    elif isinstance(data, dict) and isinstance(data.get("data"), dict):
        row = data["data"]
        keysets = [tuple(sorted(row.keys()))]
        canonical = [{key: row.get(key) for key in ("id", "name", "assigned_membership_id", "created_by_membership_id", "status")
                      if key in row}]
    okay = (expected is None or (status, ids) == expected) and (expected_status is None or status == expected_status)
    results.append({"id": id, "status": status, "ids": ids, "ok": okay,
                    "body_keys": sorted(data.keys()) if isinstance(data, dict) else [],
                    "data_keysets": keysets, "canonical_data": canonical})
    print(f"{id}={'PASS' if okay else 'FAIL'} status={status} rows={len(ids)}", flush=True)
    if not okay:
        raise RuntimeError(f"HTTP scenario failed: {id}")


def start(flag, *, missing_a4=False):
    env = b.php_env(runtime, passwords, flag=(flag == "ON"))
    env["CACHE_PREFIX"] = f"f06_i03_{RUN_ID}_{flag.lower()}"
    storage = runtime / f"storage_{RUN_ID}_{flag.lower()}"
    for sub in ("framework/sessions", "framework/cache/data", "framework/views", "logs"):
        (storage / sub).mkdir(parents=True, exist_ok=True)
    env["LARAVEL_STORAGE_PATH"] = str(storage)
    if missing_a4:
        env.pop("F06_ACTOR_PW_A4", None)
    log = (runtime / f"server_{RUN_ID}_{flag}.raw.log").open("w", encoding="utf-8")
    proc = subprocess.Popen([str(b.PHP), "artisan", "serve", "--no-reload", "--host=127.0.0.1", f"--port={PORT}"],
                            cwd=b.API, env=env, stdout=log, stderr=subprocess.STDOUT)
    for _ in range(40):
        if proc.poll() is not None:
            raise RuntimeError(f"Laravel serve exited before readiness: {flag}")
        try:
            with socket.create_connection(("127.0.0.1", PORT), timeout=1):
                break
        except OSError:
            time.sleep(0.25)
    else:
        raise RuntimeError("Laravel serve did not bind loopback")
    proxy_log = (runtime / f"proxy_{RUN_ID}_{flag}.raw.log").open("w", encoding="utf-8")
    proxy = subprocess.Popen([sys.executable, str(b.SRC / "tls_proxy.py"), str(runtime)],
                             cwd=b.API, stdout=proxy_log, stderr=subprocess.STDOUT)
    for _ in range(40):
        if proxy.poll() is not None:
            raise RuntimeError("I03 TLS proxy exited before readiness")
        try:
            with socket.create_connection(("127.0.0.1", 18082), timeout=1):
                return proc, log, proxy, proxy_log
        except OSError:
            time.sleep(0.25)
    raise RuntimeError("I03 TLS proxy did not bind loopback")


def stop(proc, log, proxy, proxy_log):
    if proxy.poll() is None:
        subprocess.run(["taskkill", "/PID", str(proxy.pid), "/T", "/F"], capture_output=True, text=True)
    proxy.wait(timeout=10)
    proxy_log.close()
    if proc.poll() is None:
        subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], capture_output=True, text=True)
    proc.wait(timeout=10)
    log.close()
    for port in (PORT, 18082):
        for attempt in range(40):
            with socket.socket() as sock:
                sock.settimeout(0.5)
                if sock.connect_ex(("127.0.0.1", port)) != 0:
                    break
            time.sleep(0.25)
        else:
            raise RuntimeError(f"Owned port {port} remained listening after stop")


def login(flag, who, tenant, *, password_key=None, no_csrf=False):
    status, _, jar = request(flag, who, tenant, "GET", "/sanctum/csrf-cookie")
    if status not in (200, 204):
        raise RuntimeError(f"CSRF bootstrap failed {flag}/{who}: {status}")
    csrf = None if no_csrf else token(jar)
    email = f"{who.lower().split('_')[0]}@tenant-{'a' if tenant == 'A' else 'b'}.sandbox"
    status, data, jar = request(flag, who, tenant, "POST", "/api/v1/auth/login",
                                payload={"email": email, "password": passwords[password_key or ('login_' + who.lower())]}, csrf=csrf)
    if status == 200:
        refresh_status, _, jar = request(flag, who, tenant, "GET", "/sanctum/csrf-cookie")
        if refresh_status not in (200, 204):
            raise RuntimeError("Post-login CSRF refresh failed")
        csrf = token(jar)
    return status, data, jar, csrf


def run_flag(flag):
    proc, log, proxy, proxy_log = start(flag)
    sessions = {}
    print(f"SERVER_{flag}_PID={proc.pid} PROXY_PID={proxy.pid} PORTS=127.0.0.1:{PORT},18082 APP_ENV=testing", flush=True)
    try:
        status, data, _ = request(flag, "badhost", "BAD", "GET", "/api/v1/company/leads")
        record(f"{flag}-BAD-HOST", status, data, expected_status=404)
        if status == 200:
            raise RuntimeError("Invalid Host accepted")
        status, data, _ = request(flag, "guest", "A", "GET", "/api/v1/company/leads")
        record(f"{flag}-GUEST", status, data, expected_status=401)
        if status != 401:
            raise RuntimeError("Unauthenticated Host did not return 401")
        status, data, _, _ = login(flag, "A1_nocsrf", "A", password_key="login_a1", no_csrf=True)
        record(f"{flag}-CSRF-MISSING", status, data, expected_status=419)
        if status != 419:
            raise RuntimeError("Missing CSRF token was not rejected")
        status, data, _, _ = login(flag, "A1_wrong", "A", password_key="login_a2")
        record(f"{flag}-WRONG-PASSWORD", status, data, expected_status=401)
        if status == 200:
            raise RuntimeError("Wrong password accepted")
        for who, tenant in (("A1", "A"), ("A2", "A"), ("B1", "B"), ("A4", "A")):
            status, data, jar, csrf = login(flag, who, tenant)
            record(f"{flag}-LOGIN-{who}", status, data, expected_status=200)
            if status != 200:
                raise RuntimeError(f"Login failed: {flag}/{who}")
            sessions[who] = (jar, csrf)
            status, data, _ = request(flag, who, tenant, "GET", "/api/v1/company/leads")
            expected = {"A1": sorted([IDS["A1"], IDS["A2"], IDS["A4_ASSIGNED"], IDS["A4_AUTHORED"], IDS["A_UNASSIGNED"]]),
                        "A2": [IDS["A2"]], "B1": [IDS["B1"]], "A4": [IDS["A4_ASSIGNED"]]}[who]
            record(f"{flag}-LIST-{who}", status, data, (200, expected))
            if who == "A4":
                for key, expected_status in (("A4_ASSIGNED", 200), ("A4_AUTHORED", 403), ("A_UNASSIGNED", 403)):
                    status, data, _ = request(flag, who, tenant, "GET", "/api/v1/company/leads/" + IDS[key])
                    record(f"{flag}-SHOW-{key}", status, data, expected_status=expected_status)
                    if status != expected_status:
                        raise RuntimeError(f"A4 row-scope mismatch: {key}")
                status, data, _ = request(flag, who, tenant, "PATCH", "/api/v1/company/leads/" + IDS["A4_ASSIGNED"],
                                          payload={"name": "A4 allowed update"}, csrf=csrf)
                record(f"{flag}-A4-UPDATE-ALLOWED", status, data, expected_status=200)
                if status != 200:
                    raise RuntimeError("A4 allowed update failed")
                status, data, _ = request(flag, who, tenant, "PATCH", "/api/v1/company/leads/" + IDS["A4_AUTHORED"],
                                          payload={"name": "A4 denied update"}, csrf=csrf)
                record(f"{flag}-A4-UPDATE-DENIED", status, data, expected_status=403)
                if status != 403:
                    raise RuntimeError("A4 out-of-scope update accepted")
                status, data, _ = request(flag, who, tenant, "PATCH", "/api/v1/company/leads/" + IDS["A4_ASSIGNED"] + "/assign",
                                          payload={"assigned_membership_id": "a1111111-0000-0000-0000-00000000a001"}, csrf=csrf)
                record(f"{flag}-A4-ASSIGN-DENIED", status, data, expected_status=403)
                if status != 403:
                    raise RuntimeError("A4 reassignment accepted")
            if who == "A2":
                status, data, _ = request(flag, who, tenant, "PATCH", "/api/v1/company/leads/" + IDS["A2"] + "/assign",
                                          payload={"assigned_membership_id": "a1111111-0000-0000-0000-00000000a001"}, csrf=csrf)
                record(f"{flag}-A2-ASSIGN-DENIED", status, data, expected_status=403)
                if status != 403:
                    raise RuntimeError("A2 reassignment accepted")
            if who == "B1":
                other_cookie = session_cookie(jar)
                status, data, _ = request(flag, "B1_cross", "A", "GET", "/api/v1/company/leads", cookie_override=other_cookie)
                record(f"{flag}-B1-SESSION-HOST-A", status, data)
                if status == 200:
                    raise RuntimeError("B1 session accepted on Host A")
        status, data, _, _ = login(flag, "A3", "A", password_key="login_a1")
        record(f"{flag}-A3-DENIED", status, data, expected_status=401)
        if status == 200:
            raise RuntimeError("Suspended A3 accepted")
        status, data, _ = request(flag, "A1", "A", "PATCH", "/api/v1/company/leads/" + IDS["A_UNASSIGNED"] + "/assign",
                                  payload={"assigned_membership_id": "a1111111-0000-0000-0000-00000000a004"}, csrf=sessions["A1"][1])
        record(f"{flag}-A1-ASSIGN-ALLOWED", status, data, expected_status=200)
        if status != 200:
            raise RuntimeError("A1 reassignment failed")
        status, data, _ = request(flag, "A4", "A", "GET", "/api/v1/company/leads")
        record(f"{flag}-A4-SEES-REASSIGNED", status, data, (200, sorted([IDS["A4_ASSIGNED"], IDS["A_UNASSIGNED"]])))
    finally:
        stop(proc, log, proxy, proxy_log)
        b.sql(container, "BEGIN; " + restore_sql + " COMMIT;")
        after = b.pg_query(container, DB_FINGERPRINT)
        if after != baseline:
            raise RuntimeError(f"Lead fingerprint drift after {flag}")
        print(f"BASELINE_RESTORED_{flag}=PASS", flush=True)


try:
    print(f"HTTP_RUN_ID={RUN_ID}", flush=True)
    if len(sys.argv) > 2 and sys.argv[2] == "--missing-a4":
        proc, log, proxy, proxy_log = start("ON", missing_a4=True)
        try:
            status, data, _, _ = login("ON", "A4", "A")
            record("MISSING-A4-LOGIN", status, data, expected_status=200)
            status, data, _ = request("ON", "A4", "A", "GET", "/api/v1/company/leads")
            record("MISSING-A4-LEADS", status, data)
            if status == 200:
                raise RuntimeError("A4 missing credential unexpectedly accepted")
            status, data, _, _ = login("ON", "A1", "A")
            record("MISSING-A4-A1-LOGIN", status, data, expected_status=200)
            status, data, _ = request("ON", "A1", "A", "GET", "/api/v1/company/leads")
            record("MISSING-A4-A1-LEADS", status, data, expected_status=200)
        finally:
            stop(proc, log, proxy, proxy_log)
            if b.pg_query(container, DB_FINGERPRINT) != baseline:
                raise RuntimeError("Lead fingerprint drift after missing A4 check")
    else:
        for flag in ("OFF", "ON"):
            run_flag(flag)
finally:
    (b.SRC / f"http_gate_evidence_{RUN_ID}.json").write_text(json.dumps({"system_identifier": state["system_identifier"],
        "baseline_fingerprint": baseline, "results": results}, indent=2), encoding="utf-8")
