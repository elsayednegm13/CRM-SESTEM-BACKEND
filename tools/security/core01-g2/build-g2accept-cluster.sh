#!/usr/bin/env bash
# CORE-01 G2 — Build the independent G2 acceptance cluster.
#
# Creates a fresh PostgreSQL 16 cluster at port 55460 (daleel-d1-g2accept-pg),
# runs all 65 migrations with correct transient provisioning, proves NOLOGIN
# fail-closed after migration 049, applies out-of-band LOGIN provisioning for
# dl_core_truntime (limited to that specific role), and seeds correct fixtures.
#
# Instruction compliance:
#   2. Independent cluster — separate data/storage/identity.
#      No other containers/volumes/networks are touched. Does NOT interact with
#      the authorized sandbox (daleel-d1t4b-sandbox-pg / port 55450).
#   3. Migrations in real order. NOLOGIN fail-closed is PROVEN (checked post-049).
#      Out-of-band LOGIN is limited to dl_core_truntime only; other locked roles
#      remain NOLOGIN (verified).
#   4. dl_host (IN daleel_hostname_resolver) is the hostname-resolution identity.
#      dl_tauth (IN daleel_tenant_auth_client) is the auth identity. Separate.
#   5. Fixtures: slugs al09-a/al09-b from creation (immutable, never UPDATE).
#      Hostname/slug/account/password constraints applied from INSERT.
#   7. No frozen acceptance tests or guard constants modified. G2SandboxGuard
#      remains frozen. New cluster requires G2AcceptClusterGuard (ENV-based sysid).
#
# NOT permitted by this script:
#   - Shared Docker delete/cleanup or protected rule changes
#   - Committing, pushing, or deploying anything
#   - Touching G3 / Production
#   - Touching daleel-d1t4b-sandbox-pg or its volumes

set -euo pipefail

readonly ACCEPT_CONTAINER="daleel-d1-g2accept-pg"
readonly ACCEPT_VOLUME="daleel-d1-g2accept-data"
readonly ACCEPT_NETWORK="daleel-d1-g2accept-net"
readonly ACCEPT_PORT=55460
readonly ACCEPT_DB="g2_accept01"    # g2_ prefix required by G2AcceptClusterGuard
readonly ACCEPT_OWNER="daleel_b10b_owner"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
API_DIR="$(cd "${SCRIPT_DIR}/../../.." && pwd)"          # daleel-crm-api
readonly PHP_IMAGE="daleel-core01-php-local:20261028"
readonly IDENTITY_FILE="${SCRIPT_DIR}/g2accept-cluster-identity.env"

# ── Safety guard: refuse if sandbox container already exists under the ACCEPT name ──
if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qx "${ACCEPT_CONTAINER}"; then
    echo "ERROR: container ${ACCEPT_CONTAINER} already exists." >&2
    echo "       Stop and remove it first, or this bootstrap would overwrite an existing cluster." >&2
    exit 1
fi

# Verify port 55460 is not already bound
if docker ps --format '{{.Ports}}' 2>/dev/null | grep -q "55460->"; then
    echo "ERROR: port 55460 is already in use by another container." >&2
    exit 1
fi

echo "[g2accept] ── Creating network, volume, container ──────────────────────" >&2
docker network create \
    --driver bridge \
    --subnet=172.99.1.0/24 \
    --gateway=172.99.1.1 \
    "${ACCEPT_NETWORK}"
docker volume  create "${ACCEPT_VOLUME}"
docker run -d \
    --name    "${ACCEPT_CONTAINER}" \
    --network "${ACCEPT_NETWORK}" \
    -v        "${ACCEPT_VOLUME}:/var/lib/postgresql/data" \
    -p        "127.0.0.1:${ACCEPT_PORT}:5432" \
    -e        POSTGRES_HOST_AUTH_METHOD=trust \
    postgres:16

# ── Wait for PostgreSQL to be ready ─────────────────────────────────────────
echo "[g2accept] Waiting for PostgreSQL..." >&2
for i in $(seq 1 30); do
    if docker exec "${ACCEPT_CONTAINER}" pg_isready -U postgres -q 2>/dev/null; then
        echo "[g2accept] PostgreSQL ready (attempt ${i})." >&2
        break
    fi
    if [ "${i}" -eq 30 ]; then
        echo "ERROR: PostgreSQL not ready after 30 attempts." >&2
        exit 1
    fi
    sleep 2
done

# ── Capture system_identifier BEFORE any role changes ────────────────────────
SYSID="$(docker exec "${ACCEPT_CONTAINER}" \
    psql -U postgres -d postgres -tAc \
    'SELECT system_identifier::text FROM pg_control_system();')"
echo "[g2accept] system_identifier=${SYSID}" >&2

# REFUSE if this is the authorized sandbox (should never happen with a new container,
# but defend against any hypothetical collision).
if [ "${SYSID}" = "7702591224362536999" ]; then
    echo "ERROR: system_identifier matches the authorized sandbox (7702591224362536999)." >&2
    echo "       Refusing to proceed — this is not an independent cluster." >&2
    exit 1
fi

# ── Generate test secrets (cluster-local, never committed) ───────────────────
SIGNING_KEY_HEX="$(openssl rand -hex 32)"
RUNTIME_PASSWORD="G2Accept_Runtime_$(openssl rand -hex 8)!"
SESSION_BINDING_KEY="$(openssl rand -hex 32)"
PROVIDER_PROOF_KEY="$(openssl rand -hex 32)"

echo "[g2accept] ── Applying cluster roles ───────────────────────────────────" >&2
docker exec -i "${ACCEPT_CONTAINER}" \
    psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
    < "${SCRIPT_DIR}/roles-core01-g2accept.sql"

# ── Create database ───────────────────────────────────────────────────────────
echo "[g2accept] Creating database ${ACCEPT_DB}..." >&2
docker exec "${ACCEPT_CONTAINER}" \
    psql -U postgres -d postgres -v ON_ERROR_STOP=1 -c \
    "CREATE DATABASE ${ACCEPT_DB} OWNER ${ACCEPT_OWNER} TEMPLATE template0 ENCODING 'UTF8';"

# ── Transient provisioning for migrations ────────────────────────────────────
# In PostgreSQL 16, ALTER ROLE requires CREATEROLE + ADMIN OPTION on the role.
# Migration 049 runs ALTER ROLE dl_provider/dl_provider_ctl/dl_core_truntime NOLOGIN
# as daleel_b10b_owner. Grant CREATEROLE + ADMIN on those roles transiently.
# CREATEROLE is revoked after migrations complete (see cleanup block below).
#
# T4b: daleel_b10b_owner has NO standing auth_lookup membership.
# Lend it transiently so migrations 026/047 can create/own auth-lookup functions.
# Migration 059: exactly 1 member of daleel_core01_authority_definer during migrate.
echo "[g2accept] Granting transient memberships and CREATEROLE for migrations..." >&2
docker exec -i "${ACCEPT_CONTAINER}" \
    psql -U postgres -d postgres -v ON_ERROR_STOP=1 <<'SQL'
-- T4b: auth_lookup membership for migrations 026/047
GRANT daleel_tenant_auth_lookup TO daleel_b10b_owner WITH INHERIT TRUE;
-- Mig 059: authority_definer admin for migration 059
GRANT daleel_core01_authority_definer TO daleel_b10b_owner WITH ADMIN TRUE, INHERIT FALSE, SET TRUE;
-- Mig 049 (PG16 ALTER ROLE requirement): CREATEROLE + ADMIN on lockdown targets
ALTER ROLE daleel_b10b_owner CREATEROLE;
GRANT dl_provider      TO daleel_b10b_owner WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;
GRANT dl_provider_ctl  TO daleel_b10b_owner WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;
GRANT dl_core_truntime TO daleel_b10b_owner WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;
SQL

# ── Run all 65 migrations ────────────────────────────────────────────────────
echo "[g2accept] ── Running migrations ──────────────────────────────────────" >&2
MSYS_NO_PATHCONV=1 docker run --rm \
    --network "container:${ACCEPT_CONTAINER}" \
    -v        "${API_DIR}:/app" \
    -w        /app \
    -e APP_ENV=testing \
    -e DB_CONNECTION=pgsql \
    -e DB_HOST=127.0.0.1    -e DB_PORT=5432 \
    -e DB_DATABASE="${ACCEPT_DB}" \
    -e DB_USERNAME="${ACCEPT_OWNER}" -e DB_PASSWORD= \
    -e PROVIDER_DB_USERNAME=dl_provider \
    -e PROVIDER_CONTROL_DB_USERNAME=dl_provider_ctl \
    -e PROVIDER_ISSUER_DB_USERNAME=dl_provider_issuer \
    -e ONBOARDING_DB_USERNAME=dl_onboarding \
    -e TENANT_HOST_DB_USERNAME=dl_host \
    -e TENANT_AUTH_DB_USERNAME=dl_tauth \
    -e TENANT_RUNTIME_DB_USERNAME=dl_core_truntime \
    -e CORE01_SQL_SIGNING_KEY="${SIGNING_KEY_HEX}" \
    -e CORE01_SQL_SIGNING_KEY_GENERATION=1 \
    -e CORE01_PROVIDER_PROOF_KEY="${PROVIDER_PROOF_KEY}" \
    -e CORE01_SESSION_BINDING_KEY="${SESSION_BINDING_KEY}" \
    -e CORE_SQL_TRUSTED_TENANT_LOGIN=dl_core_truntime \
    -e CORE_SQL_LEGACY_TENANT_LOGIN=daleel_b10b_tenant_runtime \
    "${PHP_IMAGE}" \
    php artisan migrate --force --no-ansi

# ── PROVE fail-closed: dl_core_truntime MUST be NOLOGIN after migration 049 ──
echo "[g2accept] ── Proving fail-closed contract ──────────────────────────────" >&2
NOLOGIN_CHECK="$(docker exec "${ACCEPT_CONTAINER}" \
    psql -U postgres -d postgres -tAc \
    "SELECT rolcanlogin FROM pg_roles WHERE rolname='dl_core_truntime';")"
if [ "${NOLOGIN_CHECK}" != "f" ]; then
    echo "ERROR: dl_core_truntime is LOGIN after migrations (rolcanlogin='${NOLOGIN_CHECK}') — fail-closed contract violated." >&2
    exit 1
fi
echo "[g2accept] PROVEN fail-closed: dl_core_truntime rolcanlogin=f (NOLOGIN). ✓" >&2

# Also verify other lockdown roles are NOLOGIN (migration 049 scope).
for role in dl_provider dl_provider_ctl; do
    check="$(docker exec "${ACCEPT_CONTAINER}" \
        psql -U postgres -d postgres -tAc \
        "SELECT rolcanlogin FROM pg_roles WHERE rolname='${role}';")"
    if [ "${check}" != "f" ]; then
        echo "WARNING: ${role} LOGIN status is '${check}', expected 'f' (NOLOGIN)." >&2
    else
        echo "[g2accept] PROVEN: ${role} NOLOGIN after migration 049. ✓" >&2
    fi
done

# ── Revoke transient grants (T4b security + PG16 CREATEROLE cleanup) ─────────
echo "[g2accept] Revoking transient grants (auth_lookup, admin options, CREATEROLE)..." >&2
docker exec -i "${ACCEPT_CONTAINER}" \
    psql -U postgres -d postgres -v ON_ERROR_STOP=1 <<'SQL' || {
-- T4b revocation
REVOKE daleel_tenant_auth_lookup       FROM daleel_b10b_owner;
-- Revoke ADMIN grants used for migration 049
REVOKE dl_provider                     FROM daleel_b10b_owner;
REVOKE dl_provider_ctl                 FROM daleel_b10b_owner;
REVOKE dl_core_truntime                FROM daleel_b10b_owner;
-- Revoke ADMIN grant used for migration 059 (BYPASSRLS role — critical)
REVOKE daleel_core01_authority_definer FROM daleel_b10b_owner;
-- Revoke CREATEROLE (was granted only for migration 049 lockdown step)
ALTER ROLE daleel_b10b_owner NOCREATEROLE;
SQL
    echo "WARNING: REVOKE block failed — manual cleanup required." >&2
}
RESIDUAL="$(docker exec "${ACCEPT_CONTAINER}" \
    psql -U postgres -d postgres -tAc \
    "SELECT count(*) FROM pg_auth_members m
       JOIN pg_roles r ON r.oid=m.roleid
       JOIN pg_roles o ON o.oid=m.member
     WHERE o.rolname='daleel_b10b_owner'
       AND r.rolname IN ('daleel_tenant_auth_lookup','daleel_core01_authority_definer',
                         'dl_provider','dl_provider_ctl','dl_core_truntime');")"
if [ "${RESIDUAL}" != "0" ]; then
    echo "ERROR: transient membership revocation failed (count=${RESIDUAL})." >&2
    exit 1
fi
echo "[g2accept] PROVEN: all transient memberships revoked (count=0). ✓" >&2

# Verify CREATEROLE was revoked (should be NOCREATEROLE now)
CREATEROLE_CHECK="$(docker exec "${ACCEPT_CONTAINER}" \
    psql -U postgres -d postgres -tAc \
    "SELECT rolcreaterole FROM pg_roles WHERE rolname='daleel_b10b_owner';")"
if [ "${CREATEROLE_CHECK}" != "f" ]; then
    echo "ERROR: CREATEROLE not revoked from daleel_b10b_owner (got ${CREATEROLE_CHECK})." >&2
    exit 1
fi
echo "[g2accept] PROVEN: daleel_b10b_owner NOCREATEROLE after cleanup. ✓" >&2

# ── OUT-OF-BAND: restore dl_core_truntime LOGIN (limited to this role only) ──
# Instruction 3: post-migration LOGIN is limited to the specific authorized identity.
echo "[g2accept] ── Out-of-band LOGIN provisioning for dl_core_truntime ──────" >&2
docker exec "${ACCEPT_CONTAINER}" \
    psql -U postgres -d postgres -v ON_ERROR_STOP=1 -c \
    "ALTER ROLE dl_core_truntime LOGIN PASSWORD '${RUNTIME_PASSWORD}';"

# Prove provisioning is limited to dl_core_truntime.
LOGIN_CHECK="$(docker exec "${ACCEPT_CONTAINER}" \
    psql -U postgres -d postgres -tAc \
    "SELECT rolcanlogin FROM pg_roles WHERE rolname='dl_core_truntime';")"
if [ "${LOGIN_CHECK}" != "t" ]; then
    echo "ERROR: dl_core_truntime not LOGIN after out-of-band provisioning." >&2
    exit 1
fi
echo "[g2accept] PROVEN: dl_core_truntime LOGIN restored (rolcanlogin=t). ✓" >&2

# Verify other NOLOGIN roles were NOT affected.
for role in dl_provider dl_provider_ctl; do
    check="$(docker exec "${ACCEPT_CONTAINER}" \
        psql -U postgres -d postgres -tAc \
        "SELECT rolcanlogin FROM pg_roles WHERE rolname='${role}';")"
    if [ "${check}" != "f" ]; then
        echo "ERROR: ${role} LOGIN status changed by out-of-band step — forbidden." >&2
        exit 1
    fi
done
echo "[g2accept] PROVEN: dl_provider, dl_provider_ctl remain NOLOGIN after out-of-band step. ✓" >&2

# ── Apply fixtures ────────────────────────────────────────────────────────────
echo "[g2accept] ── Seeding fixtures ─────────────────────────────────────────" >&2
docker exec -i "${ACCEPT_CONTAINER}" \
    psql -U postgres -d "${ACCEPT_DB}" -v ON_ERROR_STOP=1 \
    < "${SCRIPT_DIR}/g2accept-fixtures.sql"

# ── Write cluster identity env file ──────────────────────────────────────────
# This file is used by run-g2accept-tests.sh and must be sourced before running tests.
# It contains the cluster sysid (required by G2AcceptClusterGuard) and the test secrets.
# KEEP THIS FILE LOCAL — it contains cluster-local test credentials.
echo "[g2accept] Writing cluster identity to ${IDENTITY_FILE}..." >&2
cat > "${IDENTITY_FILE}" <<ENV
# CORE-01 G2 acceptance cluster identity — sourced by run-g2accept-tests.sh
# Generated by build-g2accept-cluster.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)
# DO NOT COMMIT — contains cluster-local test credentials.
G2_ACCEPT_CLUSTER_SYSID=${SYSID}
G2_ACCEPT_DB=${ACCEPT_DB}
G2_ACCEPT_PORT=${ACCEPT_PORT}
G2_ACCEPT_HOST=127.0.0.1
G2_ACCEPT_SUPERUSER=postgres
G2_ACCEPT_RUNTIME_PASSWORD=${RUNTIME_PASSWORD}
G2_ACCEPT_SIGNING_KEY=${SIGNING_KEY_HEX}
G2_ACCEPT_SESSION_BINDING_KEY=${SESSION_BINDING_KEY}
G2_ACCEPT_PROVIDER_PROOF_KEY=${PROVIDER_PROOF_KEY}
ENV

echo "" >&2
echo "[g2accept] ══ Bootstrap complete ═══════════════════════════════════════" >&2
echo "[g2accept]   Container : ${ACCEPT_CONTAINER} (port ${ACCEPT_PORT})" >&2
echo "[g2accept]   Database  : ${ACCEPT_DB}" >&2
echo "[g2accept]   sysid     : ${SYSID}" >&2
echo "[g2accept]   Identity  : ${IDENTITY_FILE}" >&2
echo "[g2accept]" >&2
echo "[g2accept]   Next step: bash run-g2accept-tests.sh" >&2
echo "[g2accept] ════════════════════════════════════════════════════════════" >&2
