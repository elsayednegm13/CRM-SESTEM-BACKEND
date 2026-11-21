#!/usr/bin/env bash
# ============================================================================
# F06 ACTOR POC (POC02) — adversarial matrix AT01..AT18
# ----------------------------------------------------------------------------
# Design rules (deliberately different from POC01's harness — see
# README_REVIEW.md for the full internal adversarial review):
#   * every query uses `psql -X -tA` so results are bare values — no parsing
#     of psql's aligned table output, no tail/grep heuristics;
#   * stdout, stderr and the exit code are captured separately per case;
#   * GUC forging uses `SET` (which emits no result rows) so the asserted
#     output is exactly the value under test;
#   * a DENY counts as a security result only if the failure is a real
#     SQL/permission error — a connection/auth failure is reported as
#     HARNESS, never as PASS;
#   * ON_ERROR_STOP=1 everywhere; every mutating adversarial case is wrapped
#     in BEGIN ... ROLLBACK;
#   * the sandbox identity (db name + system_identifier) is asserted before a
#     single test runs; a mismatch aborts with exit 98.
#
# Secrets come from the environment only and are never echoed:
#   PGPOC2_SUPERUSER_PW PGPOC2_A1_PW PGPOC2_A2_PW PGPOC2_A3_PW
#   PGPOC2_A4_PW PGPOC2_B1_PW PGPOC2_SHARED_PW
#
# Usage: HOST=127.0.0.1 PORT=5432 bash run_tests.sh
# ============================================================================
set -u

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-55443}"
DB="${DB:-daleel_f06_actor_poc02_r2a7f3_synthetic}"
EXPECT_SYSID="${EXPECT_SYSID:-7700478534754992166}"
POC2_CHILD="${POC2_CHILD:-0}"

PASS_N=0; FAIL_N=0; HARNESS_N=0
declare -a LINES

TA='11111111-1111-1111-1111-111111111111'
TB='22222222-2222-2222-2222-222222222222'
A1='aaaaaaaa-0000-0000-0000-00000000a001'
A2='aaaaaaaa-0000-0000-0000-00000000a002'
A4='aaaaaaaa-0000-0000-0000-00000000a004'
B1='bbbbbbbb-0000-0000-0000-00000000b001'
LEAD_A1='10000000-0000-0000-0000-0000000000a1'
LEAD_A2='20000000-0000-0000-0000-0000000000a2'
LEAD_A4='40000000-0000-0000-0000-0000000000a4'
LEAD_B1='b0000000-0000-0000-0000-0000000000b1'

pw_for () {
  case "$1" in
    postgres)              printf '%s' "${PGPOC2_SUPERUSER_PW:-}";;
    poc02_a1)              printf '%s' "${PGPOC2_A1_PW:-}";;
    poc02_a2)              printf '%s' "${PGPOC2_A2_PW:-}";;
    poc02_a3)              printf '%s' "${PGPOC2_A3_PW:-}";;
    poc02_a4)              printf '%s' "${PGPOC2_A4_PW:-}";;
    poc02_b1)              printf '%s' "${PGPOC2_B1_PW:-}";;
    poc02_tenant_a_shared) printf '%s' "${PGPOC2_SHARED_PW:-}";;
    *) printf '';;
  esac
}

OUT=''; ERR=''; RC=0
# -q is required: without it psql echoes command tags (SET/BEGIN/ROLLBACK/
# CREATE FUNCTION/RESET) on stdout and they end up mixed into the asserted
# value. Verified empirically before use — see README_REVIEW.md.
q () { # role sql -> sets OUT/ERR/RC
  local role="$1" sql="$2" errf
  errf=$(mktemp)
  OUT=$(PGPASSWORD="$(pw_for "$role")" psql -X -q -tA -v ON_ERROR_STOP=1 \
        -h "$HOST" -p "$PORT" -U "$role" -d "$DB" -c "$sql" 2>"$errf")
  RC=$?
  ERR=$(tr '\n' ' ' <"$errf" | cut -c1-200)
  rm -f "$errf"
}

# Two statements on ONE session but as separate implicit transactions —
# needed for commands such as DISCARD ALL that cannot run inside a block.
q2 () { # role sql1 sql2 -> sets OUT/ERR/RC
  local role="$1" sql1="$2" sql2="$3" errf
  errf=$(mktemp)
  OUT=$(PGPASSWORD="$(pw_for "$role")" psql -X -q -tA -v ON_ERROR_STOP=1 \
        -h "$HOST" -p "$PORT" -U "$role" -d "$DB" -c "$sql1" -c "$sql2" 2>"$errf")
  RC=$?
  ERR=$(tr '\n' ' ' <"$errf" | cut -c1-200)
  rm -f "$errf"
}

expect_value2 () { # id role sql1 sql2 expected
  local id="$1" role="$2" s1="$3" s2="$4" exp="$5"
  q2 "$role" "$s1" "$s2"
  if [[ $RC -ne 0 ]]; then
    if is_connection_problem; then record "$id" HARNESS "$exp" "<conn/auth>" "$RC" "$ERR"
    else record "$id" FAIL "$exp" "<sqlerror>" "$RC" "$ERR"; fi
    return
  fi
  if [[ "$OUT" == "$exp" ]]; then record "$id" PASS "$exp" "$OUT" "$RC" "as $role (2 stmts)"
  else record "$id" FAIL "$exp" "$OUT" "$RC" "as $role (2 stmts)"; fi
}

is_connection_problem () {
  case "$ERR" in
    *"connection to server"*|*"no password supplied"*|*"password authentication failed"*|\
    *"could not connect"*|*"server closed the connection"*|*"Connection refused"*) return 0;;
  esac
  return 1
}

record () { # id verdict expected actual rc evidence
  LINES+=("$(printf '%-8s %-8s exp=%-22s act=%-24s rc=%-3s %s' "$1" "$2" "$3" "$4" "$5" "$6")")
  case "$2" in
    PASS)    PASS_N=$((PASS_N+1));;
    HARNESS) HARNESS_N=$((HARNESS_N+1));;
    *)       FAIL_N=$((FAIL_N+1));;
  esac
}

expect_value () { # id role sql expected
  local id="$1" role="$2" sql="$3" exp="$4"
  q "$role" "$sql"
  if [[ $RC -ne 0 ]]; then
    if is_connection_problem; then record "$id" HARNESS "$exp" "<conn/auth>" "$RC" "$ERR"
    else record "$id" FAIL "$exp" "<sqlerror>" "$RC" "$ERR"; fi
    return
  fi
  if [[ "$OUT" == "$exp" ]]; then record "$id" PASS "$exp" "$OUT" "$RC" "as $role"
  else record "$id" FAIL "$exp" "$OUT" "$RC" "as $role"; fi
}

expect_sql_failure () { # id role sql must_contain
  local id="$1" role="$2" sql="$3" need="$4"
  q "$role" "$sql"
  if [[ $RC -eq 0 ]]; then record "$id" FAIL "sql-error" "succeeded:[$OUT]" "$RC" "as $role"; return; fi
  if is_connection_problem; then record "$id" HARNESS "sql-error" "<conn/auth>" "$RC" "$ERR"; return; fi
  if [[ -n "$need" && "$ERR" != *"$need"* ]]; then record "$id" FAIL "err~$need" "other-error" "$RC" "$ERR"; return; fi
  record "$id" PASS "sql-error" "denied" "$RC" "$ERR"
}

expect_deny_mutation () { # id role sql_returning_affected_count
  local id="$1" role="$2" sql="$3"
  q "$role" "$sql"
  if [[ $RC -ne 0 ]]; then
    if is_connection_problem; then record "$id" HARNESS "deny" "<conn/auth>" "$RC" "$ERR"
    else record "$id" PASS "deny" "rls/acl-error" "$RC" "$ERR"; fi
    return
  fi
  if [[ "$OUT" == "0" ]]; then record "$id" PASS "deny" "0 rows affected" "$RC" "as $role"
  else record "$id" FAIL "deny" "affected=[$OUT]" "$RC" "as $role"; fi
}

fingerprint () {
  q postgres "SELECT (SELECT count(*) FROM actor_identity_map)||'|'||(SELECT count(*) FROM leads_actor)||'|'||(SELECT count(*) FROM admin_grants)||'|'||(SELECT count(*) FROM leads_baseline_guc)||'|'||(SELECT count(*) FROM leads_tenant_only);"
  printf '%s' "$OUT"
}

# ---------------------------------------------------------------------------
# Identity guard — prove the target, or refuse to run anything.
# ---------------------------------------------------------------------------
q postgres "SELECT current_database()||'|'||(SELECT system_identifier::text FROM pg_control_system());"
if [[ $RC -ne 0 ]]; then
  echo "PREFLIGHT_FAILED rc=$RC err=$ERR" >&2
  echo "DB_IDENTITY_BLOCKED: no verified connection; refusing to run any test." >&2
  exit 97
fi
if [[ "$OUT" != "${DB}|${EXPECT_SYSID}" ]]; then
  echo "DB_IDENTITY_BLOCKED: got [$OUT] expected [${DB}|${EXPECT_SYSID}]" >&2
  exit 98
fi
echo "PREFLIGHT_OK target=$OUT host=$HOST port=$PORT"
echo

FP_BEFORE=$(fingerprint)
echo "FIXTURE_FINGERPRINT_BEFORE=$FP_BEFORE"
echo

# === AT01 — A1 sees only its own rows ======================================
expect_value AT01a poc02_a1 "SELECT count(*) FROM leads_actor;" "2"
expect_value AT01b poc02_a1 "SELECT count(*) FROM leads_actor WHERE id='${LEAD_A2}';" "0"

# === AT02 — A2 is admin by anchored mapping, and real admin work works =====
expect_value AT02a poc02_a2 "SELECT count(*) FROM leads_actor;" "4"
expect_value AT02b poc02_a2 "BEGIN; WITH u AS (UPDATE leads_actor SET name='admin-touched' WHERE id='${LEAD_A1}' RETURNING 1) SELECT count(*) FROM u; ROLLBACK;" "1"
expect_value AT02c poc02_a2 "BEGIN; WITH i AS (INSERT INTO admin_grants (tenant_id,grantee_actor_id,capability) VALUES ('${TA}','${A4}','reports.view') RETURNING 1) SELECT count(*) FROM i; ROLLBACK;" "1"
expect_value AT02d poc02_a2 "SELECT count(*) FROM admin_grants;" "1"

# === AT03 — B1 confined to tenant B ========================================
expect_value AT03a poc02_b1 "SELECT count(*) FROM leads_actor;" "1"
expect_value AT03b poc02_b1 "SELECT count(*) FROM leads_actor WHERE tenant_id='${TA}';" "0"

# === AT04 — A1 forges app.user_id as A2, reads admin resources =============
expect_value AT04a poc02_a1 "SET app.context_mode='TENANT'; SET app.tenant_id='${TA}'; SET app.user_id='${A2}'; SELECT count(*) FROM admin_grants;" "0"
expect_value AT04b poc02_a1 "SET app.user_id='${A2}'; SELECT count(*) FROM leads_actor WHERE id='${LEAD_A2}';" "0"
expect_value AT04c poc02_a1 "SET app.user_id='${A2}'; SELECT count(*) FROM leads_actor;" "2"

# === AT05 — A1 forges A2 and tries admin writes ============================
expect_deny_mutation AT05a poc02_a1 "BEGIN; SET app.user_id='${A2}'; WITH u AS (UPDATE admin_grants SET capability='pwned' WHERE tenant_id='${TA}' RETURNING 1) SELECT count(*) FROM u; ROLLBACK;"
expect_deny_mutation AT05b poc02_a1 "BEGIN; SET app.user_id='${A2}'; WITH i AS (INSERT INTO admin_grants (tenant_id,grantee_actor_id,capability) VALUES ('${TA}','${A1}','company.administer') RETURNING 1) SELECT count(*) FROM i; ROLLBACK;"
expect_deny_mutation AT05c poc02_a1 "BEGIN; SET app.user_id='${A2}'; WITH u AS (UPDATE leads_actor SET name='pwned' WHERE id='${LEAD_A2}' RETURNING 1) SELECT count(*) FROM u; ROLLBACK;"

# === AT06 — A1 forges tenant B + actor B1 ==================================
expect_value AT06a poc02_a1 "SET app.tenant_id='${TB}'; SET app.user_id='${B1}'; SELECT count(*) FROM leads_actor WHERE tenant_id='${TB}';" "0"
expect_deny_mutation AT06b poc02_a1 "BEGIN; SET app.tenant_id='${TB}'; SET app.user_id='${B1}'; WITH u AS (UPDATE leads_actor SET name='pwned' WHERE id='${LEAD_B1}' RETURNING 1) SELECT count(*) FROM u; ROLLBACK;"
expect_deny_mutation AT06c poc02_a1 "BEGIN; SET app.tenant_id='${TB}'; WITH i AS (INSERT INTO leads_actor (id,tenant_id,owner_actor_id,name) VALUES ('ffffffff-0000-0000-0000-00000000ffff','${TB}','${B1}','injected') RETURNING 1) SELECT count(*) FROM i; ROLLBACK;"

# === AT07 — SET ROLE / membership pivots ===================================
expect_sql_failure AT07a poc02_a1 "SET ROLE poc02_a2; SELECT 1;" "permission denied to set role"
expect_sql_failure AT07b poc02_a1 "SET ROLE poc02_b1; SELECT 1;" "permission denied to set role"
expect_sql_failure AT07c poc02_a1 "SET ROLE poc02_owner; SELECT 1;" "permission denied to set role"
expect_value AT07d poc02_a1 "SELECT pg_has_role('poc02_a1','poc02_a2','USAGE')::text||','||pg_has_role('poc02_a1','poc02_owner','USAGE')::text||','||pg_has_role('poc02_a1','poc02_b1','USAGE')::text;" "false,false,false"
expect_value AT07e postgres "SELECT count(*) FROM pg_auth_members m JOIN pg_roles mem ON mem.oid=m.member JOIN pg_roles grp ON grp.oid=m.roleid WHERE mem.rolname LIKE 'poc02%' AND grp.rolname LIKE 'poc02%';" "0"

# === AT08 — suspended actor authenticates but gets nothing =================
expect_value AT08a poc02_a3 "SELECT 1;" "1"
expect_value AT08b poc02_a3 "SELECT count(*) FROM leads_actor;" "0"
expect_value AT08c poc02_a3 "SET app.user_id='${A2}'; SET app.tenant_id='${TA}'; SELECT count(*) FROM admin_grants;" "0"
expect_value AT08d poc02_a3 "SELECT coalesce(public.app_actor_tenant()::text,'NULL');" "NULL"

# === AT09 — empty / malformed GUCs: no leak, no escalation, no error =======
expect_value AT09a poc02_a1 "SET app.user_id=''; SET app.tenant_id=''; SELECT count(*) FROM leads_actor;" "2"
expect_value AT09b poc02_a1 "SET app.user_id='not-a-uuid'; SELECT count(*) FROM leads_actor;" "2"
expect_value AT09c poc02_a1 "SET app.user_id='not-a-uuid'; SELECT count(*) FROM admin_grants;" "0"

# === AT10 — search_path / pg_temp shadowing cannot redirect the anchor =====
expect_value AT10a poc02_a1 "CREATE FUNCTION pg_temp.app_actor_tenant() RETURNS uuid LANGUAGE sql AS \$f\$ SELECT '${TB}'::uuid \$f\$; SET search_path = pg_temp, public; SELECT count(*) FROM leads_actor;" "2"
expect_value AT10b poc02_a1 "CREATE FUNCTION pg_temp.app_actor_is_admin() RETURNS boolean LANGUAGE sql AS \$f\$ SELECT true \$f\$; SET search_path = pg_temp, public; SELECT count(*) FROM admin_grants;" "0"

# === AT11 — prove CURRENT_USER vs SESSION_USER semantics ===================
expect_value AT11a poc02_a1 "SELECT current_u||','||session_u FROM public.poc02_identity_probe_invoker();" "poc02_a1,poc02_a1"
expect_value AT11b poc02_a1 "SELECT current_u||','||session_u FROM public.poc02_identity_probe_definer();" "poc02_owner,poc02_a1"
expect_value AT11c poc02_a1 "SELECT coalesce(public.poc02_wrong_actor_tenant_via_current_user()::text,'NULL');" "NULL"

# === AT12 — equal-privilege peer isolation =================================
expect_value AT12a poc02_a1 "SELECT count(*) FROM leads_actor WHERE id='${LEAD_A4}';" "0"
expect_value AT12b poc02_a4 "SELECT count(*) FROM leads_actor;" "1"
expect_value AT12c poc02_a4 "SET app.user_id='${A1}'; SELECT count(*) FROM leads_actor WHERE id='${LEAD_A1}';" "0"

# === AT13 — differential vs the two weaker models ==========================
expect_value AT13a poc02_tenant_a_shared "SET app.context_mode='TENANT'; SET app.tenant_id='${TB}'; SELECT count(*) FROM leads_baseline_guc WHERE tenant_id='${TB}';" "1"
expect_value AT13b poc02_tenant_a_shared "SET app.context_mode='TENANT'; SET app.tenant_id='${TA}'; SET app.user_id='${A1}'; SELECT count(*) FROM leads_baseline_guc WHERE owner_actor_id='${A2}';" "1"
expect_value AT13c poc02_tenant_a_shared "SET app.user_id='${A1}'; SELECT count(*) FROM leads_tenant_only WHERE owner_actor_id='${A2}';" "1"
expect_value AT13d poc02_tenant_a_shared "SELECT count(*) FROM leads_tenant_only WHERE tenant_id='${TB}';" "0"
expect_value AT13e poc02_a1 "SELECT count(*) FROM leads_actor WHERE owner_actor_id='${A2}';" "0"

# === AT14 — role attributes, FORCE RLS, anchor ACL, ownership ==============
expect_value AT14a postgres "SELECT count(*) FROM pg_roles WHERE rolname LIKE 'poc02%' AND rolname <> 'poc02_owner' AND (rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolinherit OR rolreplication);" "0"
expect_value AT14b poc02_a1 "SELECT bool_and(relforcerowsecurity)::text FROM pg_class WHERE relname IN ('leads_actor','admin_grants');" "true"
expect_value AT14c poc02_a1 "SELECT has_table_privilege('poc02_a1','actor_identity_map','SELECT')::text||','||has_table_privilege('poc02_a1','actor_identity_map','UPDATE')::text||','||has_table_privilege('poc02_a1','actor_identity_map','INSERT')::text;" "false,false,false"
expect_value AT14d postgres "SELECT relowner::regrole::text FROM pg_class WHERE relname='actor_identity_map';" "poc02_owner"

# === AT17 — session reuse + GUC resets never leak ==========================
expect_value AT17a poc02_a1 "SET app.user_id='${A2}'; SELECT count(*) FROM leads_actor;" "2"
expect_value AT17b poc02_a1 "SET app.user_id='${A2}'; RESET app.user_id; SELECT count(*) FROM leads_actor;" "2"
expect_value2 AT17c poc02_a1 "DISCARD ALL;" "SELECT count(*) FROM leads_actor;" "2"

# === AT18 — the anchor is out of reach of A1's free SQL ====================
expect_sql_failure AT18a poc02_a1 "SELECT count(*) FROM actor_identity_map;" "permission denied"
expect_sql_failure AT18b poc02_a1 "UPDATE actor_identity_map SET is_admin=true WHERE role_name='poc02_a1';" "permission denied"
expect_sql_failure AT18c poc02_a1 "CREATE ROLE poc02_escalated LOGIN;" "permission denied"
expect_sql_failure AT18d poc02_a1 "GRANT poc02_a2 TO poc02_a1;" ""
expect_sql_failure AT18e poc02_a1 "ALTER ROLE poc02_a1 SUPERUSER;" ""
expect_sql_failure AT18f poc02_a1 "ALTER TABLE leads_actor DISABLE ROW LEVEL SECURITY;" "must be owner"
expect_sql_failure AT18g poc02_a1 "CREATE POLICY wideopen ON leads_actor FOR SELECT USING (true);" "must be owner"

# === AT15 — no fixture drift across the whole run ==========================
FP_AFTER=$(fingerprint)
if [[ "$FP_BEFORE" == "$FP_AFTER" ]]; then
  record AT15 PASS "$FP_BEFORE" "$FP_AFTER" 0 "no fixture drift"
else
  record AT15 FAIL "$FP_BEFORE" "$FP_AFTER" 0 "FIXTURE DRIFT"
fi

# === AT16 — deliberate harness self-failure checks =========================
if [[ "$POC2_CHILD" == "0" ]]; then
  BADPORT_RC=0
  ( PGPASSWORD="${PGPOC2_SUPERUSER_PW:-}" psql -X -tA -v ON_ERROR_STOP=1 -h "$HOST" -p 1 -U postgres -d "$DB" -c "SELECT 1;" ) >/dev/null 2>&1 || BADPORT_RC=$?
  if [[ $BADPORT_RC -ne 0 ]]; then record AT16a PASS "rc!=0" "rc=$BADPORT_RC" "$BADPORT_RC" "bad port rejected"
  else record AT16a FAIL "rc!=0" "rc=0" 0 "bad port accepted"; fi

  BADDB_RC=0
  ( PGPASSWORD="${PGPOC2_SUPERUSER_PW:-}" psql -X -tA -v ON_ERROR_STOP=1 -h "$HOST" -p "$PORT" -U postgres -d "does_not_exist_poc02" -c "SELECT 1;" ) >/dev/null 2>&1 || BADDB_RC=$?
  if [[ $BADDB_RC -ne 0 ]]; then record AT16b PASS "rc!=0" "rc=$BADDB_RC" "$BADDB_RC" "bad db rejected"
  else record AT16b FAIL "rc!=0" "rc=0" 0 "bad db accepted"; fi

  GUARD_RC=0
  ( POC2_CHILD=1 EXPECT_SYSID=999 HOST="$HOST" PORT="$PORT" DB="$DB" bash "$0" ) >/dev/null 2>&1 || GUARD_RC=$?
  if [[ $GUARD_RC -eq 98 ]]; then record AT16c PASS "rc=98" "rc=$GUARD_RC" "$GUARD_RC" "identity guard aborts"
  else record AT16c FAIL "rc=98" "rc=$GUARD_RC" "$GUARD_RC" "identity guard did not abort"; fi
fi

# ===========================================================================
echo "==================== RESULTS ===================="
for l in "${LINES[@]}"; do echo "$l"; done
echo "================================================="
echo "PASS=$PASS_N FAIL=$FAIL_N HARNESS_ERRORS=$HARNESS_N"
echo "FIXTURE_FINGERPRINT_BEFORE=$FP_BEFORE"
echo "FIXTURE_FINGERPRINT_AFTER=$FP_AFTER"
echo "PGBOUNCER_POOLING=NOT_VERIFIED (no pooler in this sandbox)"
if [[ $FAIL_N -eq 0 && $HARNESS_N -eq 0 ]]; then
  echo "OVERALL=PASS_SCOPED"; exit 0
else
  echo "OVERALL=FAIL"; exit 1
fi
