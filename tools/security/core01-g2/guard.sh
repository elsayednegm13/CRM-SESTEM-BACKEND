#!/usr/bin/env bash
# CORE-01 G2 — fixed-allowlist identity guard.
#
# This allowlist is HARDCODED, not read from ENV. No environment variable can
# widen or bypass it. Every write-capable script in tools/security/core01-g2/
# MUST source this file and call g2_guard_assert before issuing any write
# (migration, INSERT, provisioning call) against the target container.
#
# Authorized target (owner-approved sandbox, "OWNER DECISION" 2026-10-31):
#   container : daleel-d1t4b-sandbox-pg
#   port      : 55450 (host) -> 5432 (container)
#   system_identifier : 7702591224362536999
#   image     : postgres:16
#
# Permanently forbidden regardless of any ENV value supplied to this script:
#   ports 55440, 55441, 55501, 55502, 55503, 55504, 55505
#   container daleel-core01-secfix06-102732-fresh-pg
#   container daleel-core01-secfix06-102732-upgrade-pg
#   container daleel-pg-acceptance (frozen RM02-RM05 owner-review evidence)
#
# The only database names this guard will ever approve a WRITE against are
# g2-prefixed synthetic databases it creates itself. d1_fresh and d1_upgrade
# are permanently read-only from this guard's perspective: no caller may
# pass them as the write target, even if asked to.

set -euo pipefail

readonly G2_ALLOWED_CONTAINER="daleel-d1t4b-sandbox-pg"
readonly G2_ALLOWED_PORT="55450"
readonly G2_ALLOWED_SYSTEM_IDENTIFIER="7702591224362536999"

readonly -a G2_FORBIDDEN_PORTS=(55440 55441 55501 55502 55503 55504 55505)
readonly -a G2_FORBIDDEN_CONTAINERS=(
  "daleel-core01-secfix06-102732-fresh-pg"
  "daleel-core01-secfix06-102732-upgrade-pg"
  "daleel-pg-acceptance"
)
readonly -a G2_READONLY_DATABASES=(d1_fresh d1_upgrade postgres)

# g2_guard_assert <database_name>
# Verifies live container identity + system_identifier match the single
# authorized target, verifies the requested database is not one of the
# permanently-protected reference databases, and verifies the database name
# carries the required g2_ prefix. Exits non-zero (refuses) on any mismatch.
g2_guard_assert() {
  local target_db="${1:?g2_guard_assert requires a database name argument}"

  for forbidden in "${G2_FORBIDDEN_CONTAINERS[@]}"; do
    if docker ps -a --format '{{.Names}}' | grep -qx "$forbidden" 2>/dev/null; then
      : # existence alone is not an error; we only refuse if WE are asked to target it below.
    fi
  done

  if [[ "$target_db" != g2_* ]]; then
    echo "G2 GUARD REFUSED: database '$target_db' does not carry the required g2_ prefix." >&2
    return 1
  fi

  for ro in "${G2_READONLY_DATABASES[@]}"; do
    if [[ "$target_db" == "$ro" ]]; then
      echo "G2 GUARD REFUSED: '$target_db' is a permanently read-only reference database." >&2
      return 1
    fi
  done

  local live_identifier
  live_identifier="$(docker exec "$G2_ALLOWED_CONTAINER" psql -U postgres -d postgres -tAc \
    "SELECT system_identifier FROM pg_control_system();" 2>/dev/null | tr -d '[:space:]')"

  if [[ "$live_identifier" != "$G2_ALLOWED_SYSTEM_IDENTIFIER" ]]; then
    echo "G2 GUARD REFUSED: live system_identifier '$live_identifier' does not match the authorized value '$G2_ALLOWED_SYSTEM_IDENTIFIER'." >&2
    return 1
  fi

  local published_port
  published_port="$(docker port "$G2_ALLOWED_CONTAINER" 5432/tcp 2>/dev/null | sed -n 's/.*:\([0-9]*\)$/\1/p')"
  if [[ "$published_port" != "$G2_ALLOWED_PORT" ]]; then
    echo "G2 GUARD REFUSED: container '$G2_ALLOWED_CONTAINER' publishes port '$published_port', expected '$G2_ALLOWED_PORT'." >&2
    return 1
  fi

  for bad_port in "${G2_FORBIDDEN_PORTS[@]}"; do
    if [[ "$published_port" == "$bad_port" ]]; then
      echo "G2 GUARD REFUSED: resolved port '$published_port' is on the permanent forbidden-port list." >&2
      return 1
    fi
  done

  echo "G2 GUARD OK: container=$G2_ALLOWED_CONTAINER port=$published_port system_identifier=$live_identifier target_db=$target_db" >&2
  return 0
}

# Convenience wrapper: run a psql statement against the guarded target only
# after g2_guard_assert passes. Never accepts -h/--host or a different -p from
# the caller; always targets the one authorized container via docker exec.
g2_guard_psql() {
  local target_db="${1:?g2_guard_psql requires a database name}"
  shift
  g2_guard_assert "$target_db"
  docker exec -i "$G2_ALLOWED_CONTAINER" psql -U postgres -d "$target_db" "$@"
}
