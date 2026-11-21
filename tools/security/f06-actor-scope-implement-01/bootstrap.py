"""Create and populate only a fresh, labelled I03 PostgreSQL sandbox.

Secrets and raw process logs live in the printed OS temp directory, never here.
Run once with `python tools/security/f06-laravel-i03/bootstrap.py` from API root.
No cleanup of containers, volumes, or networks is performed by this script.
"""
import base64
import hashlib
import json
import os
import pathlib
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import time

API = pathlib.Path(__file__).resolve().parents[3]
SRC = pathlib.Path(__file__).resolve().parent
CONTROL = "SECURITY-F06-ACTOR-SCOPE-IMPLEMENT-01"
PORT = 55473
DB = "daleel_f06scope01"
PHP = pathlib.Path.home() / ".config/herd/bin/php86/php.exe"
PROTECTED_IDS = {
    "7700288866362540071", "7699972247235194919", "7700655491115700263",
    "7700667398298513446", "7700699346203131942", "7700700553592188966",
}


def call(argv, *, data=None, env=None, allowed=(0,)):
    p = subprocess.run(argv, input=data, text=True, capture_output=True, env=env, cwd=API)
    if p.returncode not in allowed:
        # Never print raw process output: psql may include test-only secrets.
        raise RuntimeError(f"command failed rc={p.returncode}: {argv[:3]}")
    return p


def vacant(kind, name):
    p = subprocess.run(["docker", kind, "inspect", name], capture_output=True)
    if p.returncode == 0:
        raise RuntimeError(f"Refusing pre-existing Docker resource {kind}/{name}")


def sql(container, source, variables=None, *, db=DB):
    prelude = ""
    for key, value in (variables or {}).items():
        if not re.fullmatch(r"[a-z][a-z0-9_]*", key) or not re.fullmatch(r"[A-Za-z0-9_./+$=,-]+", value):
            raise RuntimeError("Unsafe SQL variable")
        prelude += f"\\set {key} '{value}'\n"
    p = call(["docker", "exec", "-i", "-e", "PGPASSFILE=/tmp/scope.pgpass", container,
              "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-h", "127.0.0.1",
              "-U", "postgres", "-d", db], data=prelude + source)
    return p.stdout.strip()


def pg_query(container, query, *, db=DB):
    p = call(["docker", "exec", "-e", "PGPASSFILE=/tmp/scope.pgpass", container,
              "psql", "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-h", "127.0.0.1",
              "-U", "postgres", "-d", db, "-c", query])
    return p.stdout.strip()


def php_env(runtime, passwords, *, admin=False, flag=False):
    env = os.environ.copy()
    # Laravel's cache-path normalization on this version recognizes POSIX
    # absolute prefixes but treats a Windows C:\\ path as repository-relative.
    # Use a sibling temp directory on the same I: drive via an explicit .. path.
    cache_dir = API.parent.parent / "DALEEL-CRM-ACTOR-SCOPE-I01-RUNTIME" / runtime.name / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    relative_cache = f"../../DALEEL-CRM-ACTOR-SCOPE-I01-RUNTIME/{runtime.name}/cache"
    for key in list(env):
        if key.startswith(("DB_", "PROVIDER_DB_", "PROVIDER_CONTROL_DB_", "ONBOARDING_DB_",
                           "TENANT_HOST_DB_", "TENANT_AUTH_DB_", "TENANT_RUNTIME_DB_", "F06_BOOTSTRAP_DB_")):
            env.pop(key, None)
    env.update({
        "APP_ENV": "testing", "APP_DEBUG": "false", "APP_KEY": passwords["app_key"],
        "APP_URL": "https://tenant-a.f06i03.localhost:18082",
        "LARAVEL_STORAGE_PATH": str(runtime / "storage"),
        "APP_CONFIG_CACHE": relative_cache + "/config-absent.php",
        "APP_SERVICES_CACHE": relative_cache + "/services.php",
        "APP_PACKAGES_CACHE": relative_cache + "/packages.php",
        "SESSION_DRIVER": "file", "SESSION_SECURE_COOKIE": "false", "SESSION_DOMAIN": "",
        "SESSION_SAME_SITE": "lax", "CACHE_STORE": "file", "QUEUE_CONNECTION": "sync",
        "MAIL_MAILER": "array", "LOG_CHANNEL": "stderr", "BROADCAST_CONNECTION": "log",
        "DB_CONNECTION": "pgsql", "DB_HOST": "127.0.0.1", "DB_PORT": str(PORT),
        "DB_DATABASE": DB, "DB_USERNAME": "postgres" if admin else "daleel_f06i03_unused_client",
        "DB_PASSWORD": passwords["postgres"] if admin else passwords["unused_client_password"],
        "DB_SSLMODE": "disable", "BASE_DOMAIN": "f06i03.localhost",
        "TENANCY_ALLOW_LOCALHOST_BASE_DOMAIN": "true",
        "TENANCY_LOCAL_TEST_BASE_DOMAIN": "f06i03.localhost",
        "TENANT_STAFF_AUTH_ENABLED": "true",
        "CORS_ALLOWED_ORIGINS": "https://tenant-a.f06i03.localhost:18082,https://tenant-b.f06i03.localhost:18082",
        "SANCTUM_STATEFUL_DOMAINS": "tenant-a.f06i03.localhost:18082,tenant-b.f06i03.localhost:18082",
        "F06_ACTOR_SQL_INTEGRATION_ENABLED": "true" if flag else "false",
        "F06_ACTOR_SQL_ALLOWED_APP_ENV": "testing",
        "F06_BOOTSTRAP_LOOKUP_FUNCTION": "public.f06i02_bootstrap_lookup",
        "F06_ACTOR_PW_A1": passwords["actor_a1_password"],
        "F06_ACTOR_PW_A2": passwords["actor_a2_password"],
        "F06_ACTOR_PW_B1": passwords["actor_b1_password"],
        "F06_ACTOR_PW_A4": passwords["actor_a4_password"],
    })
    names = {
        "PROVIDER": "provider_auth_password", "PROVIDER_CONTROL": "provider_control_password",
        "ONBOARDING": "unused_client_password", "TENANT_HOST": "hostname_resolver_password",
        "TENANT_AUTH": "auth_client_password", "TENANT_RUNTIME": "shared_bootstrap_password",
        "F06_BOOTSTRAP": "bootstrap_client_password",
    }
    users = {
        "PROVIDER": "daleel_f06i03_provider_auth_client", "PROVIDER_CONTROL": "daleel_f06i03_provider_control_client",
        "ONBOARDING": "daleel_f06i03_unused_client", "TENANT_HOST": "daleel_f06i02_hostname_resolver_client",
        "TENANT_AUTH": "daleel_f06i02_auth_client", "TENANT_RUNTIME": "daleel_f06i02_shared_bootstrap",
        "F06_BOOTSTRAP": "daleel_f06i02_bootstrap_client",
    }
    for prefix, secret_key in names.items():
        env[f"{prefix}_DB_HOST"] = "127.0.0.1"
        env[f"{prefix}_DB_PORT"] = str(PORT)
        env[f"{prefix}_DB_DATABASE"] = DB
        env[f"{prefix}_DB_USERNAME"] = users[prefix]
        env[f"{prefix}_DB_PASSWORD"] = passwords[secret_key]
        env[f"{prefix}_DB_SSLMODE"] = "disable"
    return env


def install_pgpass(container, runtime):
    # Windows bind mounts present mode 0777 inside Linux, which libpq rejects.
    # Copy via stdin into this round's container and enforce mode 0600 there.
    call(["docker", "exec", "-i", "-u", "postgres", container, "sh", "-c",
          "cat > /tmp/scope.pgpass && chmod 600 /tmp/scope.pgpass"],
         data=(runtime / "pgpass").read_text(encoding="ascii"))


def main():
    if pathlib.Path.cwd().resolve() != API:
        raise RuntimeError("Run from API root")
    if (API / "bootstrap/cache/config.php").exists():
        # An explicit fresh APP_CONFIG_CACHE path avoids this file, but its
        # presence is recorded for audit rather than silently ignored.
        print("PREEXISTING_CONFIG_CACHE=YES (isolated APP_CONFIG_CACHE used)")
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", PORT))
    ident = secrets.token_hex(4)
    container = f"daleel-f06-actor-scope-i01-{ident}-pg"
    network = f"daleel-f06-actor-scope-i01-{ident}-net"
    volume = f"daleel_f06_actor_scope_i01_{ident}_pg_data"
    for kind, name in (("container", container), ("network", network), ("volume", volume)):
        vacant(kind, name)
    runtime = pathlib.Path(tempfile.mkdtemp(prefix=f"f06-scope-i01-{ident}-"))
    passwords = {key: secrets.token_urlsafe(32) for key in (
        "postgres", "shared_bootstrap_password", "actor_a1_password", "actor_a2_password",
        "actor_b1_password", "actor_a4_password", "auth_client_password",
        "hostname_resolver_password", "bootstrap_client_password", "unused_client_password",
        "provider_auth_password", "provider_control_password",
        "login_a1", "login_a2", "login_b1", "login_a4")}
    passwords["app_key"] = "base64:" + base64.b64encode(secrets.token_bytes(32)).decode()
    (runtime / "postgres_password").write_text(passwords["postgres"], encoding="ascii")
    roles = {"postgres": "postgres", "shared_bootstrap_password": "daleel_f06i02_shared_bootstrap",
             "actor_a1_password": "daleel_f06i02_actor_a1", "actor_a2_password": "daleel_f06i02_actor_a2",
             "actor_b1_password": "daleel_f06i02_actor_b1", "actor_a4_password": "daleel_f06i03_actor_a4",
             "auth_client_password": "daleel_f06i02_auth_client",
             "hostname_resolver_password": "daleel_f06i02_hostname_resolver_client",
             "bootstrap_client_password": "daleel_f06i02_bootstrap_client",
             "unused_client_password": "daleel_f06i03_unused_client",
             "provider_auth_password": "daleel_f06i03_provider_auth_client",
             "provider_control_password": "daleel_f06i03_provider_control_client"}
    (runtime / "pgpass").write_text("".join(
        f"127.0.0.1:5432:*:{role}:{passwords[key]}\n" for key, role in roles.items()), encoding="ascii")
    (runtime / "secrets.json").write_text(json.dumps(passwords), encoding="utf-8")
    for file in ("postgres_password", "pgpass", "secrets.json"):
        (runtime / file).chmod(0o600)
    for sub in ("storage/framework/sessions", "storage/framework/cache/data", "storage/framework/views", "storage/logs"):
        (runtime / sub).mkdir(parents=True, exist_ok=True)
    state = {"control": CONTROL, "container": container, "network": network, "volume": volume,
             "port": PORT, "db": DB, "runtime": str(runtime), "stage": "created_runtime_only"}
    (runtime / "state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")
    label = f"control={CONTROL}"
    call(["docker", "network", "create", "--label", label, network])
    call(["docker", "volume", "create", "--label", label, volume])
    call(["docker", "run", "-d", "--name", container, "--label", label, "--network", network,
          "--mount", f"type=volume,source={volume},target=/var/lib/postgresql/data",
          "--mount", f"type=bind,source={runtime},target=/run/secrets,readonly",
          "-e", "POSTGRES_PASSWORD_FILE=/run/secrets/postgres_password",
          "-e", f"POSTGRES_DB={DB}", "-e", "POSTGRES_HOST_AUTH_METHOD=scram-sha-256",
          "-e", "POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 --auth-local=scram-sha-256",
          "-p", f"127.0.0.1:{PORT}:5432", "postgres:16"])
    install_pgpass(container, runtime)
    print(f"RESOURCE={container} PORT=127.0.0.1:{PORT} RUNTIME={runtime}")
    for _ in range(60):
        try:
            if pg_query(container, "SELECT current_database()") == DB:
                break
        except RuntimeError:
            time.sleep(1)
    else:
        raise RuntimeError("New sandbox did not become ready")
    control = call(["docker", "exec", "-u", "postgres", container, "pg_controldata", "/var/lib/postgresql/data"]).stdout
    match = re.search(r"Database system identifier:\s*(\d+)", control)
    if not match or match.group(1) in PROTECTED_IDS:
        raise RuntimeError("New sandbox system identifier missing or protected")
    state["system_identifier"] = match.group(1)
    hba = call(["docker", "exec", container, "cat", "/var/lib/postgresql/data/pg_hba.conf"]).stdout
    active = [line.strip() for line in hba.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if not active or any("trust" in line.split() or (line.split()[0] in ("local", "host", "hostssl", "hostnossl") and line.split()[-1] != "scram-sha-256") for line in active):
        raise RuntimeError("HBA is not SCRAM-only")
    bad = call(["docker", "exec", "-e", "PGPASSWORD=deliberately-wrong", container, "psql", "-X", "-h", "127.0.0.1",
                "-U", "postgres", "-d", DB, "-c", "SELECT 1"], allowed=tuple(range(256)))
    if bad.returncode == 0:
        raise RuntimeError("Wrong password accepted")
    print(f"SYSTEM_IDENTIFIER={state['system_identifier']} HBA=SCRAM_ONLY WRONG_PASSWORD_RC={bad.returncode} GOOD_PASSWORD=PASS")
    state["stage"] = "identity_and_hba_verified"
    (runtime / "state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")
    provision = (SRC / "000_provision_roles.sql").read_text(encoding="utf-8")
    for run in (1, 2):
        sql(container, provision, {key: passwords[key] for key in roles if key != "postgres"})
        print(f"PROVISION_RUN_{run}=PASS")
    state["stage"] = "roles_provisioned"
    (runtime / "state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")
    env = php_env(runtime, passwords, admin=True)
    migrate = call([str(PHP), "artisan", "migrate", "--force", "--no-interaction"], env=env)
    (runtime / "migrate.raw.log").write_text(migrate.stdout + migrate.stderr, encoding="utf-8")
    count = int(pg_query(container, "SELECT count(*) FROM public.migrations"))
    expected = len(list((API / "database/migrations").glob("*.php")))
    if count != expected:
        raise RuntimeError(f"Migration count mismatch {count}/{expected}")
    print(f"MIGRATIONS={count}/{expected}")
    state["stage"] = "migrated"
    (runtime / "state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")
    hashes = {}
    for key in ("login_a1", "login_a2", "login_b1", "login_a4"):
        p = call([str(PHP), "-r", "echo password_hash(trim(fgets(STDIN)), PASSWORD_ARGON2ID);"], data=passwords[key] + "\n")
        hashes["hash_" + key] = p.stdout.strip()
    sql(container, (SRC / "001_fixture_real_schema.sql").read_text(encoding="utf-8"), hashes)
    sql(container, (SRC / "002_actor_sql_fixture.sql").read_text(encoding="utf-8"))
    state["stage"] = "fixtures_installed"
    (runtime / "state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")
    print("FIXTURES=PASS")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"BOOTSTRAP_STOP={type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
