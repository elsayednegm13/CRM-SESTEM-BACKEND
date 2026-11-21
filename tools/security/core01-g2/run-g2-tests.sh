#!/usr/bin/env bash
# CORE-01 G2 — run the service/HTTP authority tests against the isolated
# g2_core01 sandbox, inside a PHP container that SHARES the sandbox network
# namespace (connect 127.0.0.1:5432 → trust). This is the only password-free
# path: the published host port (55450) routes via NAT (192.168.65.254) and
# falls through pg_hba to scram-sha-256, which would require a dl_tauth
# password that cannot be set without a forbidden cluster-role change.
#
# No new Docker network is created, no container/network is deleted or pruned,
# and no shared Docker config is modified (condition 7). Writes only ever hit
# g2_core01; d1_fresh / d1_upgrade are never touched. The in-test G2SandboxGuard
# re-verifies system_identifier + scope live before any write.
#
# Usage:  run-g2-tests.sh '<phpunit --filter expression>'
#   e.g.  run-g2-tests.sh 'TenantAuthorityFaultInjectionTest'

set -euo pipefail

FILTER="${1:?usage: run-g2-tests.sh '<--filter expression>'}"

API_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"   # daleel-crm-api
readonly SANDBOX_CONTAINER="daleel-d1t4b-sandbox-pg"
readonly PHP_IMAGE="daleel-core01-php-local:20261028"

# PHP-side HMAC key for attempt/session binding. It has no DB counterpart (the
# DB only stores the resulting hashes), so any fixed valid 64-hex works as long
# as it is consistent within a run. This is a synthetic test-infra value.
readonly SESSION_BINDING_KEY="0f0e0d0c0b0a09080706050403020100f0e1d2c3b4a5968778695a4b3c2d1e0f"
readonly PROVIDER_PROOF_KEY="1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"

# The DB-side signing secret is authoritative; derive the PHP signing key from
# the live g2_core01 row so the two can never drift. (The service register path
# is verified DB-side; this matters for any PHP-side signing in the HTTP path.)
SIGNING_KEY_HEX="$(docker exec -i "$SANDBOX_CONTAINER" psql -U postgres -d g2_core01 -tAc \
  "SELECT encode(secret,'hex') FROM core01_sql_signing_keys WHERE id=1 AND status='ACTIVE'")"
SIGNING_KEY_HEX="$(printf '%s' "$SIGNING_KEY_HEX" | tr -d '[:space:]')"

# In-namespace target: port 5432 (the sandbox's own listener), trust auth.
# The guard independently refuses forbidden ports / protected DBs regardless
# of what is passed here.
MSYS_NO_PATHCONV=1 docker run --rm \
  --network "container:${SANDBOX_CONTAINER}" \
  -v "${API_DIR}:/app" \
  -w /app \
  -e APP_ENV=testing \
  -e DB_CONNECTION=pgsql \
  -e DB_HOST=127.0.0.1 -e DB_PORT=5432 -e DB_DATABASE=g2_core01 \
  -e DB_USERNAME=postgres -e DB_PASSWORD= \
  -e TENANT_AUTH_DB_HOST=127.0.0.1 -e TENANT_AUTH_DB_PORT=5432 -e TENANT_AUTH_DB_DATABASE=g2_core01 \
  -e TENANT_AUTH_DB_USERNAME=dl_tauth -e TENANT_AUTH_DB_PASSWORD= \
  -e TENANT_RUNTIME_DB_HOST=127.0.0.1 -e TENANT_RUNTIME_DB_PORT=5432 -e TENANT_RUNTIME_DB_DATABASE=g2_core01 \
  -e TENANT_RUNTIME_DB_USERNAME=dl_core_truntime -e TENANT_RUNTIME_DB_PASSWORD= \
  -e G2_SANDBOX_HOST=127.0.0.1 -e G2_SANDBOX_PORT=5432 -e G2_SANDBOX_DB=g2_core01 -e G2_SANDBOX_SUPERUSER=postgres \
  -e CORE01_SESSION_BINDING_KEY="${SESSION_BINDING_KEY}" \
  -e CORE01_PROVIDER_PROOF_KEY="${PROVIDER_PROOF_KEY}" \
  -e CORE01_SQL_SIGNING_KEY="${SIGNING_KEY_HEX}" \
  -e CORE01_SQL_SIGNING_KEY_GENERATION=1 \
  -e CORE_SQL_TRUSTED_TENANT_LOGIN=dl_core_truntime \
  -e CORE_SQL_LEGACY_TENANT_LOGIN=daleel_b10b_tenant_runtime \
  "${PHP_IMAGE}" \
  php artisan test --filter "${FILTER}"
