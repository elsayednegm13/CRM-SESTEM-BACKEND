#!/usr/bin/env bash
# ============================================================================
# F06 ACTOR POC — HARDENED (POC03) harness
# ----------------------------------------------------------------------------
# Fixes the independent review's harness findings:
#  H1  a denial counts only when the SQLSTATE is the expected privilege/RLS
#      code (and, where given, the message matches). Syntax (42601), undefined
#      column (42703), integrity (23xxx), connection (08xxx), auth (28xxx) and
#      unclassified errors are never a security PASS.
#  H2  authentication is re-proved every run: correct password works, missing
#      password fails, wrong password fails with 28P01, identity matches, and
#      pg_hba has zero trust rules.
#  H3  every potentially mutating case runs inside BEGIN .. ROLLBACK.
#  H4  the fingerprint covers rows, owners, role attributes, memberships,
#      table AND column ACLs, policies, constraints, triggers and function
#      security — not counts; both sides check rc before comparing.
#  H5  an explicit MANIFEST of scenario IDs is enforced: no scenario may be
#      skipped, duplicated, or added silently, and the expected count is
#      asserted against the manifest, not a hard-coded number.
#  H6  ASSERTION_FAIL / HARNESS_ERROR / SECURITY_CONTROL_PASS are distinct;
#      any of the first two makes the whole script exit non-zero.
#
# Secrets come from the environment only and are never echoed:
#   H01_SU_PW H01_A1_PW H01_A2_PW H01_A3_PW H01_A4_PW H01_B1_PW H01_SHARED_PW
#
# Usage: HOST=127.0.0.1 PORT=5432 bash run_tests.sh
# ============================================================================
set -uo pipefail

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-5432}"
DB="${DB:-daleel_f06_harden01_h3k9q7_synthetic}"
EXPECT_SYSID="${EXPECT_SYSID:-7700516237007110183}"

# ---------------------------------------------------------------------------
# MANIFEST — the authoritative list. Every id must be recorded exactly once.
# ---------------------------------------------------------------------------
MANIFEST="
AUTH01 AUTH02 AUTH03 AUTH04 AUTH05
A01 A02 A03 A04 A05 A06 A07 A08 A09 A10
B01 B02 B03 B04 B05 B06 B07 B08 B09 B10 B11
C01 C02 C03 C04 C05
D01 D02 D03 D04 D05 D06 D07 D08 D09 D10 D11 D12 D13 D14 D15 D16 D17 D18
F01 F02 F03 F04 F05 F06 F07
G01
H01 H02 H03 H04 H05 H06
"
EXPECTED_IDS=$(echo $MANIFEST)
EXPECTED_COUNT=$(echo $MANIFEST | wc -w)

PASS_N=0; FAIL_N=0; HARNESS_N=0
RECORDED_IDS=""
declare -a LINES

TA='11111111-1111-1111-1111-111111111111'
TB='22222222-2222-2222-2222-222222222222'
A1='aaaaaaaa-0000-0000-0000-00000000a001'
A2='aaaaaaaa-0000-0000-0000-00000000a002'
A4='aaaaaaaa-0000-0000-0000-00000000a004'
B1='bbbbbbbb-0000-0000-0000-00000000b001'
HID_A2='20000000-0000-0000-0000-0000000000a2'   # A2's row, invisible to A1
ROW_A1='10000000-0000-0000-0000-0000000000a1'
ROW_B1='b0000000-0000-0000-0000-0000000000b1'

# SQLSTATEs that must never be accepted as a security denial.
FORBIDDEN_STATES='42601 42703 42P01 42883 23505 23503 23502 23514 08006 08001 08P01 28000 28P01 3D000 57P03 53300 53400 55000 22P02 22012'

pw_for () {
  case "$1" in
    postgres)      printf '%s' "${H01_SU_PW:-}";;
    h01_a1)        printf '%s' "${H01_A1_PW:-}";;
    h01_a2)        printf '%s' "${H01_A2_PW:-}";;
    h01_a3)        printf '%s' "${H01_A3_PW:-}";;
    h01_a4)        printf '%s' "${H01_A4_PW:-}";;
    h01_b1)        printf '%s' "${H01_B1_PW:-}";;
    h01_shared_a)  printf '%s' "${H01_SHARED_PW:-}";;
    *) printf '';;
  esac
}

OUT=''; ERR=''; RC=0; STATE=''
# One psql call. stdout, stderr, rc and SQLSTATE are captured separately.
# VERBOSITY=verbose makes psql print "ERROR:  <SQLSTATE>: message" (verified
# empirically on this exact image before this harness relied on it).
q () { # role sql [pw_override] [host_override] [port_override] [db_override]
  local role="$1" sql="$2" pw host port db errf
  pw="${3-__USE_DEFAULT__}"; host="${4:-$HOST}"; port="${5:-$PORT}"; db="${6:-$DB}"
  [[ "$pw" == "__USE_DEFAULT__" ]] && pw="$(pw_for "$role")"
  errf=$(mktemp)
  OUT=$(PGPASSWORD="$pw" psql -X -q -tA -v ON_ERROR_STOP=1 -v VERBOSITY=verbose \
        -h "$host" -p "$port" -U "$role" -d "$db" -c "$sql" 2>"$errf")
  RC=$?
  ERR=$(tr '\n' ' ' <"$errf" | cut -c1-220)
  STATE=$(sed -n 's/^ERROR:  \([0-9A-Za-z]\{5\}\): .*/\1/p' "$errf" | head -1)
  rm -f "$errf"
}

is_conn_or_auth_problem () {
  case "$ERR" in
    *"connection to server"*|*"no password supplied"*|*"password authentication failed"*|\
    *"could not connect"*|*"server closed the connection"*|*"Connection refused"*|\
    *"does not exist"*"database"*) return 0;;
  esac
  case " $STATE " in *" 08006 "*|*" 08001 "*|*" 08P01 "*|*" 28000 "*|*" 28P01 "*|*" 3D000 "*) return 0;; esac
  return 1
}

state_is_forbidden () { case " $FORBIDDEN_STATES " in *" $1 "*) return 0;; esac; return 1; }

record () { # id verdict expected actual evidence
  RECORDED_IDS="$RECORDED_IDS $1"
  LINES+=("$(printf '%-7s %-20s exp=%-26s act=%-26s %s' "$1" "$2" "$3" "$4" "$5")")
  case "$2" in
    SECURITY_CONTROL_PASS|PASS) PASS_N=$((PASS_N+1));;
    HARNESS_ERROR)              HARNESS_N=$((HARNESS_N+1));;
    *)                          FAIL_N=$((FAIL_N+1));;
  esac
}

# --- assertion on an exact scalar value -----------------------------------
expect_value () { # id role sql expected
  q "$2" "$3"
  if [[ $RC -ne 0 ]]; then
    if is_conn_or_auth_problem; then record "$1" HARNESS_ERROR "$4" "<conn/auth>" "$ERR"
    else record "$1" ASSERTION_FAIL "$4" "<err $STATE>" "$ERR"; fi
    return
  fi
  if [[ "$OUT" == "$4" ]]; then record "$1" PASS "$4" "$OUT" "as $2"
  else record "$1" ASSERTION_FAIL "$4" "$OUT" "as $2"; fi
}

# --- denial that must come from a specific SQLSTATE ------------------------
# Emits "VERDICT|SQLSTATE|message" on stdout. It is called via command
# substitution (so negative controls can assert on the verdict), which means
# the globals it sets are NOT visible to the caller — the state and message
# therefore travel in the returned string instead of being read from globals.
# An earlier revision of this harness read $STATE/$ERR in the caller and
# printed stale evidence from the previous query; see README_REVIEW.md.
deny_verdict () { # role sql want_state want_msg
  local role="$1" sql="$2" want="$3" msg="$4" v
  q "$role" "$sql"
  if   [[ $RC -eq 0 ]];            then v='NO_ERROR'
  elif is_conn_or_auth_problem;    then v='HARNESS_ERROR'
  elif [[ -z "$STATE" ]];          then v='UNCLASSIFIED'
  elif [[ "$STATE" != "$want" ]];  then
    if state_is_forbidden "$STATE"; then v="FORBIDDEN_STATE_${STATE}"
    else v="WRONG_STATE_${STATE}"; fi
  elif [[ -n "$msg" && "$ERR" != *"$msg"* ]]; then v='WRONG_MESSAGE'
  else v='SECURITY_CONTROL_PASS'
  fi
  printf '%s|%s|%s' "$v" "${STATE:-none}" "$(printf '%s' "$ERR" | tr '|' '/' | cut -c1-110)"
}

expect_deny () { # id role sql want_state want_msg
  local raw v st ev
  raw=$(deny_verdict "$2" "$3" "$4" "${5:-}")
  v="${raw%%|*}"; raw="${raw#*|}"; st="${raw%%|*}"; ev="${raw#*|}"
  case "$v" in
    SECURITY_CONTROL_PASS) record "$1" SECURITY_CONTROL_PASS "deny/$4" "sqlstate=$st" "$ev";;
    HARNESS_ERROR)         record "$1" HARNESS_ERROR "deny/$4" "<conn/auth>" "$ev";;
    *)                     record "$1" ASSERTION_FAIL "deny/$4" "$v" "$ev";;
  esac
}

# --- denial expressed as "statement succeeds but touches no row" -----------
expect_zero_rows () { # id role sql_returning_count
  q "$2" "$3"
  if [[ $RC -ne 0 ]]; then
    if is_conn_or_auth_problem; then record "$1" HARNESS_ERROR "0 rows" "<conn/auth>" "$ERR"
    else record "$1" ASSERTION_FAIL "0 rows" "<err $STATE>" "$ERR"; fi
    return
  fi
  if [[ "$OUT" == "0" ]]; then record "$1" SECURITY_CONTROL_PASS "0 rows" "0" "USING hid the row, as $2"
  else record "$1" ASSERTION_FAIL "0 rows" "$OUT" "as $2"; fi
}

fingerprint () { # -> echoes fp or empty; sets RC
  q postgres "SELECT public.h01_fingerprint();"
  printf '%s' "$OUT"
}

# ===========================================================================
# Identity guard: prove the target before anything runs.
# ===========================================================================
q postgres "SELECT current_database()||'|'||(SELECT system_identifier::text FROM pg_control_system())||'|'||session_user;"
if [[ $RC -ne 0 ]]; then
  echo "DB_IDENTITY_BLOCKED: no verified connection rc=$RC err=$ERR" >&2; exit 97
fi
if [[ "$OUT" != "${DB}|${EXPECT_SYSID}|postgres" ]]; then
  echo "DB_IDENTITY_BLOCKED: got [$OUT] expected [${DB}|${EXPECT_SYSID}|postgres]" >&2; exit 98
fi
echo "PREFLIGHT_OK target=$OUT host=$HOST port=$PORT"

FP_BEFORE=$(fingerprint)
if [[ $RC -ne 0 || -z "$FP_BEFORE" ]]; then
  echo "DB_IDENTITY_BLOCKED: baseline fingerprint unavailable rc=$RC err=$ERR" >&2; exit 96
fi
echo "FINGERPRINT_BEFORE=$FP_BEFORE"
echo

# ===========================================================================
# E) AUTHENTICATION — re-proved every run (H2)
# ===========================================================================
expect_value AUTH01 h01_a1 "SELECT 'auth_ok';" "auth_ok"

q h01_a1 "SELECT 1;" ""   # empty password
if [[ $RC -ne 0 && "$ERR" == *"no password supplied"* ]]; then
  record AUTH02 PASS "refused(no password)" "refused" "$ERR"
else
  record AUTH02 ASSERTION_FAIL "refused(no password)" "rc=$RC" "$ERR"
fi

q h01_a1 "SELECT 1;" "definitely-not-the-password"
if [[ $RC -ne 0 && ( "$STATE" == "28P01" || "$ERR" == *"password authentication failed"* ) ]]; then
  record AUTH03 PASS "refused(28P01)" "${STATE:-28P01}" "$ERR"
elif [[ $RC -ne 0 ]]; then
  record AUTH03 ASSERTION_FAIL "refused(28P01)" "state=$STATE" "$ERR"
else
  record AUTH03 ASSERTION_FAIL "refused(28P01)" "accepted" "wrong password accepted"
fi

expect_value AUTH04 h01_a1 "SELECT current_database()||'|'||session_user||'|'||current_user;" "${DB}|h01_a1|h01_a1"
expect_value AUTH05 postgres "SELECT (SELECT count(*) FROM pg_hba_file_rules WHERE auth_method='trust')||'|'||current_setting('password_encryption');" "0|scram-sha-256"

# ===========================================================================
# A) LEGITIMATE WORK — proved by data, not by absence of error
# ===========================================================================
expect_value A01 h01_a1 "SELECT count(*) FROM leads_actor;" "2"
expect_value A02 h01_a1 "SELECT name FROM leads_actor WHERE code='A1-C1';" "Lead A1-one"
expect_value A03 h01_a1 "BEGIN; UPDATE leads_actor SET name='legit-new-a1' WHERE code='A1-C1'; SELECT name FROM leads_actor WHERE code='A1-C1'; ROLLBACK;" "legit-new-a1"
expect_value A04 h01_a1 "BEGIN; INSERT INTO leads_actor (tenant_id, owner_actor_id, code, name) VALUES ('${TA}','${A1}','A1-NEW','made by a1'); SELECT owner_actor_id||'|'||name FROM leads_actor WHERE code='A1-NEW'; ROLLBACK;" "${A1}|made by a1"
expect_value A05 h01_a1 "BEGIN; WITH d AS (DELETE FROM leads_actor WHERE code='A1-C2' RETURNING 1) SELECT count(*) FROM d; ROLLBACK;" "1"
expect_value A06 h01_a2 "SELECT count(*) FROM leads_actor;" "4"
expect_value A07 h01_a2 "BEGIN; UPDATE leads_actor SET name='admin-edited' WHERE code='A1-C1'; SELECT name FROM leads_actor WHERE code='A1-C1'; ROLLBACK;" "admin-edited"
expect_value A08 h01_a2 "BEGIN; INSERT INTO leads_actor (tenant_id, owner_actor_id, code, name) VALUES ('${TA}','${A2}','A2-NEW','made by admin'); SELECT count(*) FROM leads_actor WHERE code='A2-NEW'; ROLLBACK;" "1"
expect_value A09 h01_a2 "SELECT count(*) FROM admin_grants;" "1"
expect_value A10 h01_b1 "SELECT count(*) FROM leads_actor;" "1"

# ===========================================================================
# B) ACTOR ISOLATION INSIDE ONE TENANT
# ===========================================================================
expect_value B01 h01_a1 "SET app.context_mode='TENANT'; SET app.tenant_id='${TA}'; SET app.user_id='${A2}'; SELECT count(*) FROM admin_grants;" "0"
expect_value B02 h01_a1 "SET app.user_id='${A2}'; SELECT count(*) FROM leads_actor WHERE code='A2-SECRET';" "0"
expect_value B03 h01_a1 "SET app.user_id='${A2}'; SELECT count(*) FROM leads_actor;" "2"
# mass UPDATE with no WHERE touches only the actor's own rows
expect_value B04 h01_a1 "BEGIN; SET app.user_id='${A2}'; WITH u AS (UPDATE leads_actor SET name='mass' RETURNING 1) SELECT count(*) FROM u; ROLLBACK;" "2"
expect_deny  B05 h01_a1 "BEGIN; UPDATE leads_actor SET owner_actor_id='${A2}' WHERE code='A1-C1'; ROLLBACK;" "42501" "owner_actor_id is immutable"
expect_deny  B06 h01_a1 "BEGIN; UPDATE leads_actor SET tenant_id='${TB}' WHERE code='A1-C1'; ROLLBACK;" "42501" "permission denied"
expect_deny  B07 h01_a1 "BEGIN; INSERT INTO leads_actor (tenant_id, owner_actor_id, code, name) VALUES ('${TA}','${A2}','A1-FORGED','claims a2'); ROLLBACK;" "42501" "row-level security"
expect_zero_rows B08 h01_a1 "BEGIN; WITH u AS (UPDATE leads_actor SET name='pwned' WHERE code='A2-SECRET' RETURNING 1) SELECT count(*) FROM u; ROLLBACK;"
expect_zero_rows B09 h01_a1 "BEGIN; WITH d AS (DELETE FROM leads_actor WHERE code='A2-SECRET' RETURNING 1) SELECT count(*) FROM d; ROLLBACK;"
expect_value B10 h01_a4 "SET app.user_id='${A1}'; SELECT count(*) FROM leads_actor WHERE code='A1-C1';" "0"
expect_deny  B11 h01_a2 "BEGIN; UPDATE leads_actor SET owner_actor_id='${A1}' WHERE code='A2-SECRET'; ROLLBACK;" "42501" "owner_actor_id is immutable"

# ===========================================================================
# C) TENANT ISOLATION UNDER FULL GUC FORGERY
# ===========================================================================
expect_value C01 h01_a1 "SET app.context_mode='TENANT'; SET app.tenant_id='${TB}'; SET app.user_id='${B1}'; SELECT count(*) FROM leads_actor WHERE tenant_id='${TB}';" "0"
expect_zero_rows C02 h01_a1 "BEGIN; SET app.tenant_id='${TB}'; SET app.user_id='${B1}'; WITH u AS (UPDATE leads_actor SET name='pwned' WHERE code='B1-C1' RETURNING 1) SELECT count(*) FROM u; ROLLBACK;"
expect_deny  C03 h01_a1 "BEGIN; SET app.tenant_id='${TB}'; INSERT INTO leads_actor (tenant_id, owner_actor_id, code, name) VALUES ('${TB}','${B1}','X-INJ','injected'); ROLLBACK;" "42501" "row-level security"
expect_value C04 h01_b1 "SET app.tenant_id='${TA}'; SET app.user_id='${A1}'; SELECT count(*) FROM leads_actor WHERE tenant_id='${TA}';" "0"
expect_value C05 h01_a2 "SET app.tenant_id='${TB}'; SELECT count(*) FROM leads_actor WHERE tenant_id='${TB}';" "0"

# ===========================================================================
# D) ROLE / ACL / POLICY / ANCHOR INTEGRITY
# ===========================================================================
expect_deny  D01 h01_a1 "SET ROLE h01_a2; SELECT 1;" "42501" "permission denied to set role"
expect_deny  D02 h01_a1 "SET ROLE h01_owner; SELECT 1;" "42501" "permission denied to set role"
expect_value D03 h01_a1 "SELECT pg_has_role('h01_a1','h01_a2','USAGE')::text||','||pg_has_role('h01_a1','h01_owner','USAGE')::text||','||pg_has_role('h01_a1','h01_b1','USAGE')::text;" "false,false,false"
expect_value D04 postgres "SELECT count(*) FROM pg_auth_members m WHERE m.roleid::regrole::text LIKE 'h01%' OR m.member::regrole::text LIKE 'h01%';" "0"
expect_deny  D05 h01_a1 "SELECT count(*) FROM actor_identity_map;" "42501" "permission denied for table actor_identity_map"
expect_deny  D06 h01_a1 "BEGIN; UPDATE actor_identity_map SET is_admin=true WHERE role_name='h01_a1'; ROLLBACK;" "42501" "permission denied for table actor_identity_map"
expect_deny  D07 h01_a1 "BEGIN; CREATE ROLE h01_escalated LOGIN; ROLLBACK;" "42501" "permission denied to create role"
expect_deny  D08 h01_a1 "BEGIN; GRANT h01_a2 TO h01_a1; ROLLBACK;" "42501" "permission denied to grant role"
expect_deny  D09 h01_a1 "BEGIN; ALTER ROLE h01_a1 SUPERUSER; ROLLBACK;" "42501" "permission denied to alter role"
expect_deny  D10 h01_a1 "BEGIN; ALTER TABLE leads_actor DISABLE ROW LEVEL SECURITY; ROLLBACK;" "42501" "must be owner of table leads_actor"
expect_deny  D11 h01_a1 "BEGIN; CREATE POLICY wideopen ON leads_actor FOR SELECT USING (true); ROLLBACK;" "42501" "must be owner of table leads_actor"
expect_value D12 postgres "SELECT count(*) FROM pg_roles WHERE rolname LIKE 'h01%' AND (rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolinherit OR rolreplication);" "0"
expect_value D13 h01_a1 "SELECT bool_and(relforcerowsecurity)::text FROM pg_class WHERE relname IN ('leads_actor','admin_grants');" "true"
expect_value D14 postgres "SELECT relowner::regrole::text FROM pg_class WHERE relname='actor_identity_map';" "h01_owner"
expect_value D15 postgres "SELECT count(*) FROM pg_proc p, aclexplode(p.proacl) a WHERE p.proname IN ('app_actor_tenant','app_actor_id','app_actor_is_admin','h01_fingerprint') AND a.grantee=0;" "0"
expect_deny  D16 h01_a1 "BEGIN; CREATE FUNCTION public.h01_hijack() RETURNS uuid LANGUAGE sql AS 'SELECT NULL::uuid'; ROLLBACK;" "42501" "permission denied for schema public"
# CURRENT_USER vs SESSION_USER, measured not assumed
expect_value D17 h01_a1 "SELECT (SELECT current_u||','||session_u FROM public.h01_probe_invoker())||' / '||(SELECT current_u||','||session_u FROM public.h01_probe_definer())||' / '||coalesce(public.h01_wrong_tenant_via_current_user()::text,'NULL');" "h01_a1,h01_a1 / h01_owner,h01_a1 / NULL"
# pg_temp shadowing cannot redirect the anchor
expect_value D18 h01_a1 "CREATE FUNCTION pg_temp.app_actor_tenant() RETURNS uuid LANGUAGE sql AS \$f\$ SELECT '${TB}'::uuid \$f\$; CREATE FUNCTION pg_temp.app_actor_is_admin() RETURNS boolean LANGUAGE sql AS \$f\$ SELECT true \$f\$; SET search_path = pg_temp, public; SELECT (SELECT count(*) FROM leads_actor)||'|'||(SELECT count(*) FROM admin_grants);" "2|0"

# ===========================================================================
# F) HARNESS NEGATIVE CONTROLS — intentional faults must never read as PASS
# ===========================================================================
V=$(deny_verdict h01_a1 "SELEC 1;" "42501" "")
if [[ "${V%%|*}" == "FORBIDDEN_STATE_42601" ]]; then record F01 PASS "reject syntax error" "${V%%|*}" "classifier refused 42601"
else record F01 ASSERTION_FAIL "reject syntax error" "${V%%|*}" "classifier mis-handled a syntax error"; fi

V=$(deny_verdict h01_a1 "SELECT nope FROM leads_actor;" "42501" "")
if [[ "${V%%|*}" == "FORBIDDEN_STATE_42703" ]]; then record F02 PASS "reject undefined column" "${V%%|*}" "classifier refused 42703"
else record F02 ASSERTION_FAIL "reject undefined column" "${V%%|*}" "classifier mis-handled 42703"; fi

V=$(deny_verdict h01_a1 "BEGIN; INSERT INTO leads_actor (tenant_id, owner_actor_id, code, name) VALUES ('${TA}','${A1}','A1-C1','dup'); ROLLBACK;" "42501" "")
if [[ "${V%%|*}" == "FORBIDDEN_STATE_23505" ]]; then record F03 PASS "reject unique violation" "${V%%|*}" "classifier refused 23505"
else record F03 ASSERTION_FAIL "reject unique violation" "${V%%|*}" "classifier mis-handled 23505"; fi

q h01_a1 "SELECT 1;" "__USE_DEFAULT__" "$HOST" 1 "$DB"
if [[ $RC -ne 0 ]] && is_conn_or_auth_problem; then record F04 PASS "harness error on bad port" "rc=$RC" "$ERR"
else record F04 ASSERTION_FAIL "harness error on bad port" "rc=$RC" "$ERR"; fi

q h01_a1 "SELECT 1;" "__USE_DEFAULT__" "$HOST" "$PORT" "no_such_db_h01"
if [[ $RC -ne 0 ]] && is_conn_or_auth_problem; then record F05 PASS "harness error on bad db" "rc=$RC" "$ERR"
else record F05 ASSERTION_FAIL "harness error on bad db" "rc=$RC" "$ERR"; fi

GUARD_RC=0
( EXPECT_SYSID=999999 HOST="$HOST" PORT="$PORT" DB="$DB" bash "$0" --child ) >/dev/null 2>&1 || GUARD_RC=$?
if [[ $GUARD_RC -eq 98 ]]; then record F06 PASS "identity guard exits 98" "rc=$GUARD_RC" "wrong system_identifier aborts the run"
else record F06 ASSERTION_FAIL "identity guard exits 98" "rc=$GUARD_RC" "guard did not abort"; fi

# a denial test run with a wrong password must classify as HARNESS, not PASS
OUT=''; ERR=''; RC=0; STATE=''
q h01_a1 "BEGIN; UPDATE leads_actor SET owner_actor_id='${A2}' WHERE code='A1-C1'; ROLLBACK;" "wrong-password-on-purpose"
if [[ $RC -ne 0 ]] && is_conn_or_auth_problem; then record F07 PASS "auth failure != security deny" "conn/auth" "$ERR"
else record F07 ASSERTION_FAIL "auth failure != security deny" "rc=$RC state=$STATE" "$ERR"; fi

# ===========================================================================
# H) EXISTENCE CHANNELS, SESSION REUSE, LIVE STATUS CHANGE
# ===========================================================================
# PK is DB-generated and the id column is not insertable -> no key probing.
expect_deny H01 h01_a1 "BEGIN; INSERT INTO leads_actor (id, tenant_id, owner_actor_id, code, name) VALUES ('${HID_A2}','${TA}','${A1}','probe','probe'); ROLLBACK;" "42501" "permission denied for table leads_actor"
# Touching a hidden row by its id reveals nothing: no error, no rows.
expect_zero_rows H02 h01_a1 "BEGIN; WITH u AS (UPDATE leads_actor SET name='probe' WHERE id='${HID_A2}' RETURNING 1) SELECT count(*) FROM u; ROLLBACK;"
# A tenant-wide UNIQUE on a client-supplied business key REMAINS an in-tenant
# existence oracle. Measured, not hidden: 23505 proves A2-SECRET exists.
V=$(deny_verdict h01_a1 "BEGIN; INSERT INTO leads_actor (tenant_id, owner_actor_id, code, name) VALUES ('${TA}','${A1}','A2-SECRET','probe'); ROLLBACK;" "42501" "")
if [[ "${V%%|*}" == "FORBIDDEN_STATE_23505" ]]; then
  record H03 PASS "oracle OPEN in-tenant (23505 observed)" "${V%%|*}" "unique(tenant_id,code) leaks existence of a hidden row inside the tenant"
else
  record H03 ASSERTION_FAIL "oracle OPEN in-tenant (23505 observed)" "${V%%|*}" "unexpected classification"
fi
# Cross-tenant the same probe is stopped by RLS before uniqueness is reached.
expect_deny H04 h01_a1 "BEGIN; INSERT INTO leads_actor (tenant_id, owner_actor_id, code, name) VALUES ('${TB}','${A1}','B1-C1','probe'); ROLLBACK;" "42501" "row-level security"
# Single session: repeated GUC forgery, RESET, then DISCARD ALL.
q2_out=''
errf=$(mktemp)
q2_out=$(PGPASSWORD="$(pw_for h01_a1)" psql -X -q -tA -v ON_ERROR_STOP=1 -v VERBOSITY=verbose \
  -h "$HOST" -p "$PORT" -U h01_a1 -d "$DB" \
  -c "SET app.user_id='${A2}'; SET app.tenant_id='${TB}'; SELECT count(*) FROM leads_actor;" \
  -c "RESET app.user_id; RESET app.tenant_id; SELECT count(*) FROM leads_actor;" \
  -c "DISCARD ALL;" \
  -c "SELECT count(*) FROM leads_actor;" 2>"$errf"); RC=$?
ERR=$(tr '\n' ' ' <"$errf" | cut -c1-220); rm -f "$errf"
if [[ $RC -eq 0 && "$q2_out" == "2
2
2" ]]; then record H05 PASS "2/2/2 in one session" "$(echo $q2_out)" "GUC forgery, RESET and DISCARD ALL all irrelevant"
else record H05 ASSERTION_FAIL "2/2/2 in one session" "$(echo $q2_out) rc=$RC" "$ERR"; fi

# Live status change: suspend A4 (committed), observe, then restore.
q postgres "UPDATE actor_identity_map SET actor_status='SUSPENDED' WHERE role_name='h01_a4';"
SUSPEND_RC=$RC
if [[ $SUSPEND_RC -ne 0 ]]; then
  record H06 HARNESS_ERROR "suspend->0 then restore->1" "setup failed" "$ERR"
else
  q h01_a4 "SELECT count(*) FROM leads_actor;"
  H06_MID="$OUT"; H06_MID_RC=$RC
  q postgres "UPDATE actor_identity_map SET actor_status='ACTIVE' WHERE role_name='h01_a4';"
  RESTORE_RC=$RC
  q h01_a4 "SELECT count(*) FROM leads_actor;"
  H06_END="$OUT"; H06_END_RC=$RC
  if [[ $H06_MID_RC -eq 0 && $RESTORE_RC -eq 0 && $H06_END_RC -eq 0 && "$H06_MID" == "0" && "$H06_END" == "1" ]]; then
    record H06 PASS "suspend->0 then restore->1" "0 then 1" "revocation visible to the next statement; restored"
  else
    record H06 ASSERTION_FAIL "suspend->0 then restore->1" "mid=$H06_MID end=$H06_END" "restore_rc=$RESTORE_RC"
  fi
fi

# ===========================================================================
# G) INTEGRITY — full fingerprint, fail-closed on either side
# ===========================================================================
FP_AFTER=$(fingerprint)
if [[ $RC -ne 0 || -z "$FP_AFTER" ]]; then
  record G01 HARNESS_ERROR "fp(before)==fp(after)" "fp query failed" "$ERR"
elif [[ "$FP_BEFORE" == "$FP_AFTER" ]]; then
  record G01 PASS "fp(before)==fp(after)" "identical" "data+roles+ACL+policies+constraints+triggers+functions"
else
  record G01 ASSERTION_FAIL "fp(before)==fp(after)" "DRIFT" "before=$FP_BEFORE after=$FP_AFTER"
fi

# ===========================================================================
# MANIFEST enforcement (H5)
# ===========================================================================
ACTUAL_COUNT=$(echo $RECORDED_IDS | wc -w)
MISSING=''; EXTRA=''; DUPES=''
for id in $EXPECTED_IDS; do
  n=$(echo $RECORDED_IDS | tr ' ' '\n' | grep -cx "$id")
  [[ "$n" -eq 0 ]] && MISSING="$MISSING $id"
  [[ "$n" -gt 1 ]] && DUPES="$DUPES $id(x$n)"
done
for id in $RECORDED_IDS; do
  echo " $EXPECTED_IDS " | grep -q " $id " || EXTRA="$EXTRA $id"
done

echo "==================== RESULTS ===================="
for l in "${LINES[@]}"; do echo "$l"; done
echo "================================================="
echo "EXPECTED_SCENARIOS=$EXPECTED_COUNT RECORDED=$ACTUAL_COUNT"
echo "MISSING=[${MISSING# }] DUPLICATED=[${DUPES# }] UNDECLARED=[${EXTRA# }]"
echo "PASS=$PASS_N ASSERTION_FAIL=$FAIL_N HARNESS_ERRORS=$HARNESS_N"
echo "FINGERPRINT_BEFORE=$FP_BEFORE"
echo "FINGERPRINT_AFTER=$FP_AFTER"
echo "PGBOUNCER_POOLING=NOT_VERIFIED (no pooler in this sandbox)"

MANIFEST_OK=1
[[ -n "$MISSING" || -n "$DUPES" || -n "$EXTRA" || "$ACTUAL_COUNT" -ne "$EXPECTED_COUNT" ]] && MANIFEST_OK=0
echo "MANIFEST_COMPLETE=$([[ $MANIFEST_OK -eq 1 ]] && echo PASS || echo FAIL)"

if [[ $FAIL_N -eq 0 && $HARNESS_N -eq 0 && $MANIFEST_OK -eq 1 ]]; then
  echo "OVERALL=PASS_SCOPED"; exit 0
else
  echo "OVERALL=FAIL"; exit 1
fi
