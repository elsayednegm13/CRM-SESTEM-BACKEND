"""Real HTTPS/Laravel gate for narrowly classified F06 readiness failures."""
import hashlib
import json
import pathlib
import socket
import subprocess
import sys
import time
import urllib.parse

import bootstrap as b

runtime = pathlib.Path(sys.argv[1]).resolve(strict=True)
phase = sys.argv[2] if len(sys.argv) > 2 else "base"
state = json.loads((runtime / "state.json").read_text(encoding="utf-8"))
if (state["control"], state["db"], state["port"], state["stage"]) != (b.CONTROL, b.DB, b.PORT, "fixtures_installed"):
    raise RuntimeError("Sandbox state mismatch")
container = state["container"]
meta = json.loads(b.call(["docker", "container", "inspect", container]).stdout)[0]
control = b.call(["docker", "exec", "-u", "postgres", container, "pg_controldata", "/var/lib/postgresql/data"]).stdout
if meta["Config"]["Labels"].get("control") != b.CONTROL or not meta["State"]["Running"] or str(state["system_identifier"]) not in control:
    raise RuntimeError("Sandbox ownership mismatch")
passwords = json.loads((runtime / "secrets.json").read_text(encoding="utf-8"))
HOST = "tenant-a.f06i03.localhost"
LEAD = "c0000006-0000-0000-0000-000000000006"
A4_MEMBER = "a1111111-0000-0000-0000-00000000a004"
DIRECT = "/api/v1/company/staff/" + A4_MEMBER + "/permissions"
RUN = time.strftime("%Y%m%dT%H%M%S")
FP = "SELECT md5(string_agg(k||':'||v,'|' ORDER BY k,v)) FROM (SELECT 'l' k,to_jsonb(x)::text v FROM public.leads x UNION ALL SELECT 'u',to_jsonb(x)::text FROM public.tenant_staff_users x UNION ALL SELECT 'm',to_jsonb(x)::text FROM public.tenant_staff_memberships x UNION ALL SELECT 'r',to_jsonb(x)::text FROM public.roles x UNION ALL SELECT 'mr',to_jsonb(x)::text FROM public.tenant_staff_membership_roles x UNION ALL SELECT 'rp',to_jsonb(x)::text FROM public.role_permissions x UNION ALL SELECT 'g',to_jsonb(x)::text FROM public.tenant_staff_permission_grants x UNION ALL SELECT 'e',to_jsonb(x)::text FROM public.tenant_staff_security_events x) q"
results = []


def request(case, who, method, path, payload=None, csrf=None):
    stem = runtime / f"g2_{RUN}_{case}_{who}"
    jar, headers, body = [pathlib.Path(str(stem) + ext) for ext in (".jar", ".headers", ".body")]
    argv = ["curl.exe", "--noproxy", "*", "-k", "-sS", "--max-time", "20", "--resolve",
            f"{HOST}:18112:127.0.0.1", "-D", str(headers), "-o", str(body), "-w", "%{http_code}",
            "-X", method, "-H", "Accept: application/json", "-H", f"Origin: https://{HOST}:18112",
            "-b", str(jar), "-c", str(jar)]
    if csrf:
        argv.extend(["-H", "X-XSRF-TOKEN: " + csrf])
    if payload is not None:
        data_file = pathlib.Path(str(stem) + ".request.json")
        data_file.write_text(json.dumps(payload), encoding="utf-8")
        argv.extend(["-H", "Content-Type: application/json", "--data-binary", "@" + str(data_file)])
    argv.append(f"https://{HOST}:18112{path}")
    p = subprocess.run(argv, cwd=b.API, capture_output=True, text=True)
    if p.returncode:
        raise RuntimeError(f"curl rc={p.returncode} case={case} who={who}")
    raw = body.read_bytes()
    try:
        parsed = json.loads(raw)
    except ValueError:
        parsed = None
    return int(p.stdout.strip()), parsed, raw, jar


def token(jar):
    for line in jar.read_text(encoding="utf-8").splitlines():
        if line and (not line.startswith("#") or line.startswith("#HttpOnly_")):
            parts = line.split("\t")
            if len(parts) >= 7 and parts[-2] == "XSRF-TOKEN":
                return urllib.parse.unquote(parts[-1])
    raise RuntimeError("CSRF cookie absent")


def login(case, who):
    status, _, _, jar = request(case, who, "GET", "/sanctum/csrf-cookie")
    if status not in (200, 204):
        raise RuntimeError(f"CSRF bootstrap {case}/{who} status={status}")
    status, _, _, jar = request(case, who, "POST", "/api/v1/auth/login",
                                {"email": f"{who.lower()}@tenant-a.sandbox", "password": passwords["login_" + who.lower()]}, token(jar))
    if status != 200:
        raise RuntimeError(f"Login {case}/{who} status={status}")
    status, _, _, jar = request(case, who, "GET", "/sanctum/csrf-cookie")
    if status not in (200, 204):
        raise RuntimeError(f"CSRF refresh {case}/{who} status={status}")
    return token(jar)


def start(case, missing=None, db=None):
    env = b.php_env(runtime, passwords, flag=True)
    if missing:
        env.pop("F06_ACTOR_PW_" + missing, None)
    if db:
        env["DB_DATABASE"] = db
        for key in list(env):
            if key.endswith("_DB_DATABASE"):
                env[key] = db
    env["APP_URL"] = f"https://{HOST}:18112"
    env["CORS_ALLOWED_ORIGINS"] = f"https://{HOST}:18112"
    env["SANCTUM_STATEFUL_DOMAINS"] = f"{HOST}:18112"
    env["CACHE_PREFIX"] = f"f06_compact01_{RUN}_{case}"
    storage = runtime / f"g2_storage_{RUN}_{case}"
    for sub in ("framework/sessions", "framework/cache/data", "framework/views", "logs"):
        (storage / sub).mkdir(parents=True, exist_ok=True)
    env["LARAVEL_STORAGE_PATH"] = str(storage)
    server_log = (runtime / f"g2_server_{RUN}_{case}.raw.log").open("w", encoding="utf-8")
    proxy_log = (runtime / f"g2_proxy_{RUN}_{case}.raw.log").open("w", encoding="utf-8")
    server = subprocess.Popen([str(b.PHP), "artisan", "serve", "--no-reload", "--host=127.0.0.1", "--port=18111"],
                              cwd=b.API, env=env, stdout=server_log, stderr=subprocess.STDOUT)
    proxy = subprocess.Popen([sys.executable, str(b.SRC / "tls_proxy.py"), str(runtime)],
                             cwd=b.API, stdout=proxy_log, stderr=subprocess.STDOUT)
    for port, proc in ((18111, server), (18112, proxy)):
        for _ in range(50):
            if proc.poll() is not None:
                raise RuntimeError(f"Owned server exited port={port}")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                    break
            except OSError:
                time.sleep(0.2)
        else:
            raise RuntimeError(f"Owned server not ready port={port}")
    return server, proxy, server_log, proxy_log


def stop(processes):
    server, proxy, server_log, proxy_log = processes
    for proc in (proxy, server):
        if proc.poll() is None:
            subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], capture_output=True, text=True)
        proc.wait(timeout=10)
    server_log.close()
    proxy_log.close()


def check(case, status, data, raw, expected_status, expected_code):
    error = data.get("error") if isinstance(data, dict) else None
    if status != expected_status or not isinstance(error, dict) or error.get("code") != expected_code:
        raise RuntimeError(f"HTTP error contract failed {case}: status={status} code={error.get('code') if isinstance(error,dict) else None}")
    if set(data) != {"error", "meta"} or set(error) != {"code", "message"} or error["message"] != "The company service is temporarily unavailable.":
        raise RuntimeError(f"HTTP response shape failed {case}")
    low = raw.lower()
    for secret in list(passwords.values()) + [b"sqlstate", b"select public", b"stack trace", b"exception", b"f06scope_assign_lead", b"f06team01_direct_permission"]:
        needle = secret.encode() if isinstance(secret, str) else secret
        if needle.lower() in low:
            raise RuntimeError(f"HTTP leak detected {case}")
    results.append({"case": case, "status": status, "error_code": error["code"], "message": error["message"],
                    "body_sha256": hashlib.sha256(raw).hexdigest(), "meta_keys": sorted(data["meta"])})
    print(f"G2_HTTP_{case}={status}/{error['code']}", flush=True)


def run_case(case, who, method, path, payload, missing=None, db=None):
    before = b.pg_query(container, FP, db=db or b.DB)
    processes = start(case, missing=missing, db=db)
    try:
        csrf = login(case, who)
        status, data, raw, _ = request(case, who, method, path, payload, csrf)
        check(case, status, data, raw, 503, "ACTOR_SQL_UNAVAILABLE")
    finally:
        stop(processes)
    after = b.pg_query(container, FP, db=db or b.DB)
    if before != after:
        raise RuntimeError(f"Mutation fingerprint changed {case}")
    results[-1].update({"fingerprint_before": before, "fingerprint_after": after})


try:
    if phase == "base":
        run_case("E1_MISSING_A5", "A5", "POST", DIRECT,
                 {"permission": "leads.view", "scope": "SELF"}, missing="A5")
        run_case("E2_MISSING_A4", "A4", "GET", "/api/v1/company/leads/c0000004-0000-0000-0000-000000000004", None, missing="A4")
        run_case("E4_DIRECT_FUNCTION", "A5", "POST", DIRECT,
                 {"permission": "leads.view", "scope": "SELF"})
    elif phase == "assign_clone":
        run_case("E4_ASSIGN_FUNCTION", "A1", "PATCH", "/api/v1/company/leads/" + LEAD + "/assign",
                 {"assigned_membership_id": A4_MEMBER}, db="daleel_f06compact01_e4clone")
    elif phase == "mapping_clone":
        run_case("E3_UNMAPPED_A5", "A5", "GET", "/api/v1/company/staff", None,
                 db="daleel_f06compact01_e4clone")
    else:
        raise RuntimeError("Unknown G2 phase")
finally:
    (b.SRC / f"g2_http_{phase}_evidence.json").write_text(json.dumps({"system_identifier": state["system_identifier"], "results": results}, indent=2) + "\n", encoding="utf-8")
