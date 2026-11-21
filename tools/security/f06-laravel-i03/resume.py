"""Resume only an I03 container already created by bootstrap.py after a stopped gate.

Usage: python tools/security/f06-laravel-i03/resume.py ABSOLUTE_RUNTIME_DIR
The runtime directory contains synthetic secrets; never place it in a repository.
"""
import json
import pathlib
import re
import sys

import bootstrap as b


def main():
    if len(sys.argv) != 2:
        raise RuntimeError("Expected one absolute runtime directory")
    runtime = pathlib.Path(sys.argv[1]).resolve(strict=True)
    if not runtime.is_absolute() or b.API in runtime.parents:
        raise RuntimeError("Runtime path must be outside the repository")
    state = json.loads((runtime / "state.json").read_text(encoding="utf-8"))
    passwords = json.loads((runtime / "secrets.json").read_text(encoding="utf-8"))
    if state["control"] != b.CONTROL or pathlib.Path(state["runtime"]).resolve() != runtime or state["port"] != b.PORT or state["db"] != b.DB:
        raise RuntimeError("Runtime state does not identify this round")
    container = state["container"]
    meta = json.loads(b.call(["docker", "container", "inspect", container]).stdout)[0]
    if meta["Config"]["Labels"].get("control") != b.CONTROL or not meta["State"]["Running"]:
        raise RuntimeError("Container label/state mismatch")
    if state["network"] not in meta["NetworkSettings"]["Networks"] or not any(
        mount.get("Name") == state["volume"] and mount.get("Destination") == "/var/lib/postgresql/data"
        for mount in meta["Mounts"]):
        raise RuntimeError("Container network/volume mismatch")
    bindings = meta["HostConfig"]["PortBindings"]["5432/tcp"]
    if bindings != [{"HostIp": "127.0.0.1", "HostPort": str(b.PORT)}]:
        raise RuntimeError("Container host port mismatch")
    for kind, name in (("network", state["network"]), ("volume", state["volume"])):
        item = json.loads(b.call(["docker", kind, "inspect", name]).stdout)[0]
        if item["Labels"].get("control") != b.CONTROL:
            raise RuntimeError(f"{kind} label mismatch")
    b.install_pgpass(container, runtime)
    control = b.call(["docker", "exec", "-u", "postgres", container, "pg_controldata", "/var/lib/postgresql/data"]).stdout
    match = re.search(r"Database system identifier:\s*(\d+)", control)
    if not match or match.group(1) in b.PROTECTED_IDS:
        raise RuntimeError("New sandbox system identifier missing or protected")
    state["system_identifier"] = match.group(1)
    hba = b.call(["docker", "exec", container, "cat", "/var/lib/postgresql/data/pg_hba.conf"]).stdout
    active = [line.strip() for line in hba.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if not active or any("trust" in line.split() or line.split()[-1] != "scram-sha-256" for line in active):
        raise RuntimeError("HBA is not SCRAM-only")
    bad = b.call(["docker", "exec", "-e", "PGPASSWORD=deliberately-wrong", container, "psql", "-X", "-h", "127.0.0.1",
                  "-U", "postgres", "-d", b.DB, "-c", "SELECT 1"], allowed=tuple(range(256)))
    if bad.returncode == 0 or b.pg_query(container, "SELECT current_database()") != b.DB:
        raise RuntimeError("SCRAM negative/positive control failed")
    print(f"SYSTEM_IDENTIFIER={state['system_identifier']} HBA=SCRAM_ONLY WRONG_PASSWORD_RC={bad.returncode} GOOD_PASSWORD=PASS", flush=True)
    state["stage"] = "identity_and_hba_verified"
    (runtime / "state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")
    provision = (b.SRC / "000_provision_roles.sql").read_text(encoding="utf-8")
    roles = ("shared_bootstrap_password", "actor_a1_password", "actor_a2_password", "actor_b1_password",
             "actor_a4_password", "auth_client_password", "hostname_resolver_password",
             "bootstrap_client_password", "unused_client_password", "provider_auth_password", "provider_control_password")
    for run in (1, 2):
        b.sql(container, provision, {key: passwords[key] for key in roles})
        print(f"PROVISION_RUN_{run}=PASS", flush=True)
    state["stage"] = "roles_provisioned"
    (runtime / "state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")
    env = b.php_env(runtime, passwords, admin=True)
    migrate = b.call([str(b.PHP), "artisan", "migrate", "--force", "--no-interaction"], env=env)
    (runtime / "migrate.raw.log").write_text(migrate.stdout + migrate.stderr, encoding="utf-8")
    count = int(b.pg_query(container, "SELECT count(*) FROM public.migrations"))
    expected = len(list((b.API / "database/migrations").glob("*.php")))
    if count != expected:
        raise RuntimeError(f"Migration count mismatch {count}/{expected}")
    print(f"MIGRATIONS={count}/{expected}", flush=True)
    state["stage"] = "migrated"
    (runtime / "state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")
    hashes = {}
    for key in ("login_a1", "login_a2", "login_b1", "login_a4"):
        p = b.call([str(b.PHP), "-r", "echo password_hash(trim(fgets(STDIN)), PASSWORD_ARGON2ID);"], data=passwords[key] + "\n")
        hashes["hash_" + key] = p.stdout.strip()
    b.sql(container, (b.SRC / "001_fixture_real_schema.sql").read_text(encoding="utf-8"), hashes)
    b.sql(container, (b.SRC / "002_actor_sql_fixture.sql").read_text(encoding="utf-8"))
    state["stage"] = "fixtures_installed"
    (runtime / "state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")
    print("FIXTURES=PASS", flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"RESUME_STOP={type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
