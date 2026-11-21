#!/usr/bin/env bash
# ============================================================================
# F06 ACTOR POC — FINAL HARDEN (POC04) harness
# ----------------------------------------------------------------------------
# Closes the independent review's findings on POC03:
#
# F1 SQLSTATE classification — a fixed NON_SECURITY set (syntax / undefined
#    column / constraint / connection / auth / data errors) is rejected FIRST,
#    before the expected code is even looked at, so a test that wrongly expects
#    e.g. 23505 can never pass. A denial must also match a declared DENY KIND
#    (DENY_ACL / DENY_RLS / DENY_TRIGGER / DENY_OWNER) derived from the server
#    message, so 42501 alone is not accepted as proof.
#    The existence-oracle case is recorded as EXPECTED_FINDING in its own
#    counter and can never become a control pass.
#
# F2 fingerprint RC capture — fp_read() is called directly (never in a command
#    substitution), writes stdout/stderr/rc to files and sets FP_VALUE/FP_RC/
#    FP_ERR. Contract: rc must be 0 AND value non-empty AND 64 hex chars.
#    Non-empty stdout with rc!=0 is rejected. Two empty/failed reads are never
#    treated as "equal".
#
# F3 fingerprint coverage — fh_fingerprint() (003) declares components 01..17
#    and lists what is NOT covered; sensitivity is proved by mutants.
#
# F4 effective PUBLIC EXECUTE — fh_effective_public_execute() resolves
#    acldefault() when proacl IS NULL; a negative control creates a function
#    with the default ACL inside a transaction and the detector must see it.
#
# F5 AUTH gate — a standalone gate runs before any mutating scenario and exits
#    non-zero immediately (code 70) if, for ANY matrix login: the correct
#    password fails, a missing password succeeds, a wrong password succeeds, or
#    any effective HBA rule that could match the test path is `trust`.
#
# F6 revocation safety — the suspend/observe/restore cycle uses a dedicated
#    actor (fh_a5), an idempotent recovery marker, a restore verified by a
#    separate read, and a final mapping assertion. The in-transaction variant
#    (rollback-guaranteed) is reported separately from the cross-connection
#    variant, and the committed window is declared, not hidden.
#
# Secrets come from the environment only and are never echoed. xtrace is off.
#   FH_SU_PW FH_A1_PW FH_A2_PW FH_A3_PW FH_A4_PW FH_A5_PW FH_B1_PW FH_SHARED_PW
#
# Usage: HOST=127.0.0.1 PORT=5432 bash run_tests.sh
# ============================================================================
set -uo pipefail
set +x

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-5432}"
DB="${DB:-daleel_f06_final_harden_q8w2_synthetic}"
EXPECT_SYSID="${EXPECT_SYSID:-7700553360591278118}"
WORKDIR="${WORKDIR:-/tmp/fh_work}"
mkdir -p "$WORKDIR"; chmod 700 "$WORKDIR"
RECOVERY_MARKER="$WORKDIR/h06_recovery_pending"

# ---------------------------------------------------------------------------
# MANIFEST (expands beyond POC03's 63; the count is derived, never hard-coded)
# ---------------------------------------------------------------------------
MANIFEST="
AUTH01 AUTH02 AUTH03 AUTH04 AUTH05 AUTH06
A01 A02 A03 A04 A05 A06 A07 A08 A09 A10
B01 B02 B03 B04 B05 B06 B07 B08 B09 B10 B11
C01 C02 C03 C04 C05
D01 D02 D03 D04 D05 D06 D07 D08 D09 D10 D11 D12 D13 D14 D15 D16 D17 D18 D19 D20
F1a F1b F1c F1d F2a F2b F2c F4a F4b F5a
G01 G02
H01 H02 H03 H04 H05 H06a H06b H06c
"
EXPECTED_IDS=$(echo $MANIFEST)
EXPECTED_COUNT=$(echo $MANIFEST | wc -w)

PASS_N=0; FAIL_N=0; HARNESS_N=0; FINDING_N=0
RECORDED_IDS=""
declare -a LINES

TA='11111111-1111-1111-1111-111111111111'
TB='22222222-2222-2222-2222-222222222222'
A1='aaaaaaaa-0000-0000-0000-00000000a001'
A2='aaaaaaaa-0000-0000-0000-00000000a002'
A4='aaaaaaaa-0000-0000-0000-00000000a004'
A5='aaaaaaaa-0000-0000-0000-00000000a005'
B1='bbbbbbbb-0000-0000-0000-00000000b001'
HID_A2='20000000-0000-0000-0000-0000000000a2'
ROW_A1='10000000-0000-0000-0000-0000000000a1'

# F1: these are NEVER a security denial, whatever a test claims to expect.
NON_SECURITY_STATES='42601 42703 42P01 42883 42P07 42704 23505 23503 23502 23514 23P01 22P02 22012 22003 22001 08000 08003 08006 08001 08P01 28000 28P01 3D000 3F000 53300 53400 57P01 57P02 57P03 25P02 40001 40P01 XX000'
# F1: the only SQLSTATE accepted as a security control refusal here.
SECURITY_STATES='42501'

MATRIX_LOGINS='fh_a1 fh_a2 fh_a3 fh_a4 fh_a5 fh_b1 fh_shared_a'

pw_for () {
  case "$1" in
    postgres)     printf '%s' "${FH_SU_PW:-}";;
    fh_a1)        printf '%s' "${FH_A1_PW:-}";;
    fh_a2)        printf '%s' "${FH_A2_PW:-}";;
    fh_a3)        printf '%s' "${FH_A3_PW:-}";;
    fh_a4)        printf '%s' "${FH_A4_PW:-}";;
    fh_a5)        printf '%s' "${FH_A5_PW:-}";;
    fh_b1)        printf '%s' "${FH_B1_PW:-}";;
    fh_shared_a)  printf '%s' "${FH_SHARED_PW:-}";;
    *) printf '';;
  esac
}

OUT=''; ERR=''; RC=0; STATE=''
q () { # role sql [pw_override] [host] [port] [db]
  local role="$1" sql="$2" pw host port db
  pw="${3-__DEFAULT__}"; host="${4:-$HOST}"; port="${5:-$PORT}"; db="${6:-$DB}"
  [[ "$pw" == "__DEFAULT__" ]] && pw="$(pw_for "$role")"
  : > "$WORKDIR/q.out"; : > "$WORKDIR/q.err"
  PGPASSWORD="$pw" psql -X -q -tA -v ON_ERROR_STOP=1 -v VERBOSITY=verbose \
      -h "$host" -p "$port" -U "$role" -d "$db" -c "$sql" \
      > "$WORKDIR/q.out" 2> "$WORKDIR/q.err"
  RC=$?
  OUT=$(cat "$WORKDIR/q.out")
  ERR=$(tr '\n' ' ' < "$WORKDIR/q.err" | cut -c1-240)
  STATE=$(sed -n 's/^ERROR:  \([0-9A-Za-z]\{5\}\): .*/\1/p' "$WORKDIR/q.err" | head -1)
}

in_set () { case " $2 " in *" $1 "*) return 0;; esac; return 1; }

is_conn_or_auth () {
  case "$ERR" in
    *"connection to server"*|*"no password supplied"*|*"password authentication failed"*|\
    *"could not connect"*|*"server closed the connection"*|*"Connection refused"*) return 0;;
  esac
  [[ -n "$STATE" ]] && in_set "$STATE" '08000 08003 08006 08001 08P01 28000 28P01 3D000' && return 0
  return 1
}

# F1: derive WHICH control refused, from the server message.
deny_kind () {
  case "$ERR" in
    *"is immutable on"*)                      printf 'DENY_TRIGGER';;
    *"row-level security policy"*)            printf 'DENY_RLS';;
    *"must be owner of"*)                     printf 'DENY_OWNER';;
    *"permission denied for table"*|*"permission denied for schema"*|\
    *"permission denied for relation"*|*"permission denied to"*|\
    *"permission denied for function"*)       printf 'DENY_ACL';;
    *)                                        printf 'DENY_UNKNOWN';;
  esac
}

record () { # id verdict expected actual evidence
  RECORDED_IDS="$RECORDED_IDS $1"
  LINES+=("$(printf '%-6s %-21s exp=%-30s act=%-28s %s' "$1" "$2" "$3" "$4" "$5")")
  case "$2" in
    PASS|SECURITY_CONTROL_PASS) PASS_N=$((PASS_N+1));;
    EXPECTED_FINDING)           FINDING_N=$((FINDING_N+1));;
    HARNESS_ERROR)              HARNESS_N=$((HARNESS_N+1));;
    *)                          FAIL_N=$((FAIL_N+1));;
  esac
}

expect_value () { # id role sql expected
  q "$2" "$3"
  if [[ $RC -ne 0 ]]; then
    if is_conn_or_auth; then record "$1" HARNESS_ERROR "$4" "<conn/auth>" "$ERR"
    else record "$1" ASSERTION_FAIL "$4" "<err ${STATE:-none}>" "$ERR"; fi
    return
  fi
  if [[ "$OUT" == "$4" ]]; then record "$1" PASS "$4" "$OUT" "as $2"
  else record "$1" ASSERTION_FAIL "$4" "$OUT" "as $2"; fi
}

# F1 classifier. Emits VERDICT|STATE|KIND|message
deny_verdict () { # role sql want_state want_kind want_msg
  local role="$1" sql="$2" want="$3" kind_want="$4" msg="$5" v k
  q "$role" "$sql"
  k=$(deny_kind)
  if   [[ $RC -eq 0 ]];                              then v='NO_ERROR'
  elif is_conn_or_auth;                              then v='HARNESS_ERROR'
  elif [[ -z "$STATE" ]];                            then v='UNCLASSIFIED'
  elif in_set "$STATE" "$NON_SECURITY_STATES";       then v="NON_SECURITY_FAILURE_${STATE}"
  elif ! in_set "$STATE" "$SECURITY_STATES";         then v="NOT_A_SECURITY_STATE_${STATE}"
  elif [[ "$STATE" != "$want" ]];                    then v="WRONG_STATE_${STATE}"
  elif [[ "$k" == 'DENY_UNKNOWN' ]];                 then v='DENY_KIND_UNKNOWN'
  elif [[ -n "$kind_want" && "$k" != "$kind_want" ]];then v="WRONG_KIND_${k}"
  elif [[ -n "$msg" && "$ERR" != *"$msg"* ]];        then v='WRONG_MESSAGE'
  else v='SECURITY_CONTROL_PASS'
  fi
  printf '%s|%s|%s|%s' "$v" "${STATE:-none}" "$k" "$(printf '%s' "$ERR" | tr '|' '/' | cut -c1-96)"
}

expect_deny () { # id role sql want_state want_kind want_msg
  local raw v st k ev
  raw=$(deny_verdict "$2" "$3" "$4" "$5" "${6:-}")
  v="${raw%%|*}"; raw="${raw#*|}"; st="${raw%%|*}"; raw="${raw#*|}"; k="${raw%%|*}"; ev="${raw#*|}"
  case "$v" in
    SECURITY_CONTROL_PASS) record "$1" SECURITY_CONTROL_PASS "deny/$4/$5" "$st/$k" "$ev";;
    HARNESS_ERROR)         record "$1" HARNESS_ERROR "deny/$4/$5" "<conn/auth>" "$ev";;
    *)                     record "$1" ASSERTION_FAIL "deny/$4/$5" "$v" "$ev";;
  esac
}

expect_zero_rows () { # id role sql_returning_count
  q "$2" "$3"
  if [[ $RC -ne 0 ]]; then
    if is_conn_or_auth; then record "$1" HARNESS_ERROR "0 rows" "<conn/auth>" "$ERR"
    else record "$1" ASSERTION_FAIL "0 rows" "<err ${STATE:-none}>" "$ERR"; fi
    return
  fi
  if [[ "$OUT" == "0" ]]; then record "$1" SECURITY_CONTROL_PASS "0 rows (USING)" "0" "as $2"
  else record "$1" ASSERTION_FAIL "0 rows (USING)" "$OUT" "as $2"; fi
}

# ---------------------------------------------------------------------------
# F2: fingerprint read with an explicit (value, rc, stderr) contract.
# Never called inside a command substitution.
# ---------------------------------------------------------------------------
FP_VALUE=''; FP_RC=0; FP_ERR=''; FP_OK=0
fp_read () { # [sql_override]
  local sql="${1:-SELECT public.fh_fingerprint();}"
  : > "$WORKDIR/fp.out"; : > "$WORKDIR/fp.err"
  PGPASSWORD="$(pw_for postgres)" psql -X -q -tA -v ON_ERROR_STOP=1 -v VERBOSITY=verbose \
      -h "$HOST" -p "$PORT" -U postgres -d "$DB" -c "$sql" \
      > "$WORKDIR/fp.out" 2> "$WORKDIR/fp.err"
  FP_RC=$?
  FP_VALUE=$(cat "$WORKDIR/fp.out")
  FP_ERR=$(tr '\n' ' ' < "$WORKDIR/fp.err" | cut -c1-200)
  FP_OK=0
  if [[ $FP_RC -eq 0 && ${#FP_VALUE} -eq 64 ]] && [[ "$FP_VALUE" =~ ^[0-9a-f]{64}$ ]]; then FP_OK=1; fi
}

# ===========================================================================
# Target guard
# ===========================================================================
q postgres "SELECT current_database()||'|'||(SELECT system_identifier::text FROM pg_control_system())||'|'||session_user;"
if [[ $RC -ne 0 ]]; then echo "DB_IDENTITY_BLOCKED rc=$RC err=$ERR" >&2; exit 97; fi
if [[ "$OUT" != "${DB}|${EXPECT_SYSID}|postgres" ]]; then
  echo "DB_IDENTITY_BLOCKED got=[$OUT] want=[${DB}|${EXPECT_SYSID}|postgres]" >&2; exit 98; fi
echo "PREFLIGHT_OK target=$OUT host=$HOST port=$PORT"

# ===========================================================================
# F6 idempotent recovery: if a previous run died inside the committed window,
# restore fh_a5 before anything else and say so.
# ===========================================================================
if [[ -f "$RECOVERY_MARKER" ]]; then
  echo "H06_RECOVERY: marker found, restoring fh_a5 to ACTIVE before testing"
  q postgres "UPDATE actor_identity_map SET actor_status='ACTIVE' WHERE role_name='fh_a5';"
  [[ $RC -eq 0 ]] && rm -f "$RECOVERY_MARKER"
fi
q postgres "SELECT actor_status FROM actor_identity_map WHERE role_name='fh_a5';"
if [[ $RC -ne 0 || "$OUT" != "ACTIVE" ]]; then
  echo "BLOCKED_CLEANUP_REQUIRED: fh_a5 is '$OUT' (rc=$RC) before the run; refusing to continue" >&2; exit 95; fi

fp_read
if [[ $FP_OK -ne 1 ]]; then
  echo "DB_IDENTITY_BLOCKED: baseline fingerprint invalid rc=$FP_RC len=${#FP_VALUE} err=$FP_ERR" >&2; exit 96; fi
FP_BEFORE="$FP_VALUE"
echo "FINGERPRINT_BEFORE=$FP_BEFORE"

# ===========================================================================
# F5 — AUTH GATE. Fails fast with exit 70 before any mutation runs.
# ===========================================================================
auth_gate () {
  local role bad=0
  # (1) effective HBA: reject any rule that could match our test path and is trust
  q postgres "SELECT count(*) FROM pg_hba_file_rules
              WHERE error IS NULL AND auth_method='trust'
                AND (type IN ('local','host','hostssl','hostnossl'))
                AND ( '${DB}' = ANY(database) OR 'all' = ANY(database) OR 'replication' = ANY(database) );"
  if [[ $RC -ne 0 ]]; then echo "AUTH_GATE_FAIL: cannot read pg_hba_file_rules: $ERR" >&2; return 1; fi
  if [[ "$OUT" != "0" ]]; then echo "AUTH_GATE_FAIL: $OUT effective trust rule(s) could match the test path" >&2; return 1; fi
  record AUTH01 PASS "0 effective trust rules" "0" "pg_hba_file_rules, matched on type+database"
  # (2) encryption in force
  q postgres "SELECT current_setting('password_encryption');"
  [[ $RC -eq 0 && "$OUT" == "scram-sha-256" ]] || { echo "AUTH_GATE_FAIL: password_encryption=$OUT" >&2; return 1; }
  record AUTH02 PASS "scram-sha-256" "$OUT" "password_encryption"
  # (3) every matrix login: correct password works
  for role in $MATRIX_LOGINS; do
    q "$role" "SELECT session_user;"
    if [[ $RC -ne 0 || "$OUT" != "$role" ]]; then
      echo "AUTH_GATE_FAIL: correct-password login failed for $role rc=$RC err=$ERR" >&2; bad=1; fi
  done
  [[ $bad -eq 0 ]] || return 1
  record AUTH03 PASS "all 7 logins authenticate" "7/7" "$MATRIX_LOGINS"
  # (4) every matrix login: missing password refused
  for role in $MATRIX_LOGINS; do
    q "$role" "SELECT 1;" ""
    if [[ $RC -eq 0 || "$ERR" != *"no password supplied"* ]]; then
      echo "AUTH_GATE_FAIL: missing-password was not refused for $role (rc=$RC)" >&2; bad=1; fi
  done
  [[ $bad -eq 0 ]] || return 1
  record AUTH04 PASS "missing password refused x7" "7/7" "fe_sendauth"
  # (5) every matrix login: wrong password refused with 28P01
  for role in $MATRIX_LOGINS; do
    q "$role" "SELECT 1;" "wrong-password-$role-$$"
    if [[ $RC -eq 0 ]] || { [[ "$STATE" != "28P01" ]] && [[ "$ERR" != *"password authentication failed"* ]]; }; then
      echo "AUTH_GATE_FAIL: wrong-password was not refused for $role (rc=$RC state=$STATE)" >&2; bad=1; fi
  done
  [[ $bad -eq 0 ]] || return 1
  record AUTH05 PASS "wrong password refused x7" "7/7" "28P01"
  # (6) the transport actually used by the tests is TCP to the in-container endpoint
  q postgres "SELECT CASE WHEN inet_server_addr() IS NULL THEN 'socket' ELSE host(inet_server_addr())||':'||inet_server_port() END;"
  if [[ $RC -ne 0 || "$OUT" != "127.0.0.1:${PORT}" ]]; then
    echo "AUTH_GATE_FAIL: unexpected transport [$OUT]" >&2; return 1; fi
  record AUTH06 PASS "tcp 127.0.0.1:${PORT}" "$OUT" "inet_server_addr/port"
  return 0
}

if ! auth_gate; then
  echo "AUTH_GATE=FAIL — refusing to run any security or mutation scenario" >&2
  echo "OVERALL=FAIL"; exit 70
fi
echo "AUTH_GATE=PASS"
echo

# ===========================================================================
# A) legitimate work, proved by data
# ===========================================================================
expect_value A01 fh_a1 "SELECT count(*) FROM leads_actor;" "2"
expect_value A02 fh_a1 "SELECT name FROM leads_actor WHERE code='A1-C1';" "Lead A1-one"
expect_value A03 fh_a1 "BEGIN; UPDATE leads_actor SET name='legit-new-a1' WHERE code='A1-C1'; SELECT name FROM leads_actor WHERE code='A1-C1'; ROLLBACK;" "legit-new-a1"
expect_value A04 fh_a1 "BEGIN; INSERT INTO leads_actor (tenant_id, owner_actor_id, code, name) VALUES ('${TA}','${A1}','A1-NEW','made by a1'); SELECT owner_actor_id||'|'||name FROM leads_actor WHERE code='A1-NEW'; ROLLBACK;" "${A1}|made by a1"
expect_value A05 fh_a1 "BEGIN; WITH d AS (DELETE FROM leads_actor WHERE code='A1-C2' RETURNING 1) SELECT count(*) FROM d; ROLLBACK;" "1"
expect_value A06 fh_a2 "SELECT count(*) FROM leads_actor;" "5"
expect_value A07 fh_a2 "BEGIN; UPDATE leads_actor SET name='admin-edited' WHERE code='A1-C1'; SELECT name FROM leads_actor WHERE code='A1-C1'; ROLLBACK;" "admin-edited"
expect_value A08 fh_a2 "BEGIN; INSERT INTO leads_actor (tenant_id, owner_actor_id, code, name) VALUES ('${TA}','${A2}','A2-NEW','made by admin'); SELECT count(*) FROM leads_actor WHERE code='A2-NEW'; ROLLBACK;" "1"
expect_value A09 fh_a2 "SELECT count(*) FROM admin_grants;" "1"
expect_value A10 fh_b1 "SELECT count(*) FROM leads_actor;" "1"

# ===========================================================================
# B) actor isolation inside a tenant
# ===========================================================================
expect_value B01 fh_a1 "SET app.context_mode='TENANT'; SET app.tenant_id='${TA}'; SET app.user_id='${A2}'; SELECT count(*) FROM admin_grants;" "0"
expect_value B02 fh_a1 "SET app.user_id='${A2}'; SELECT count(*) FROM leads_actor WHERE code='A2-SECRET';" "0"
expect_value B03 fh_a1 "SET app.user_id='${A2}'; SELECT count(*) FROM leads_actor;" "2"
expect_value B04 fh_a1 "BEGIN; SET app.user_id='${A2}'; WITH u AS (UPDATE leads_actor SET name='mass' RETURNING 1) SELECT count(*) FROM u; ROLLBACK;" "2"
expect_deny  B05 fh_a1 "BEGIN; UPDATE leads_actor SET owner_actor_id='${A2}' WHERE code='A1-C1'; ROLLBACK;" "42501" "DENY_TRIGGER" "owner_actor_id is immutable"
expect_deny  B06 fh_a1 "BEGIN; UPDATE leads_actor SET tenant_id='${TB}' WHERE code='A1-C1'; ROLLBACK;" "42501" "DENY_ACL" "permission denied for table"
expect_deny  B07 fh_a1 "BEGIN; INSERT INTO leads_actor (tenant_id, owner_actor_id, code, name) VALUES ('${TA}','${A2}','A1-FORGED','claims a2'); ROLLBACK;" "42501" "DENY_RLS" "row-level security"
expect_zero_rows B08 fh_a1 "BEGIN; WITH u AS (UPDATE leads_actor SET name='pwned' WHERE code='A2-SECRET' RETURNING 1) SELECT count(*) FROM u; ROLLBACK;"
expect_zero_rows B09 fh_a1 "BEGIN; WITH d AS (DELETE FROM leads_actor WHERE code='A2-SECRET' RETURNING 1) SELECT count(*) FROM d; ROLLBACK;"
expect_value B10 fh_a4 "SET app.user_id='${A1}'; SELECT count(*) FROM leads_actor WHERE code='A1-C1';" "0"
expect_deny  B11 fh_a2 "BEGIN; UPDATE leads_actor SET owner_actor_id='${A1}' WHERE code='A2-SECRET'; ROLLBACK;" "42501" "DENY_TRIGGER" "owner_actor_id is immutable"

# ===========================================================================
# C) tenant isolation under full GUC forgery
# ===========================================================================
expect_value C01 fh_a1 "SET app.context_mode='TENANT'; SET app.tenant_id='${TB}'; SET app.user_id='${B1}'; SELECT count(*) FROM leads_actor WHERE tenant_id='${TB}';" "0"
expect_zero_rows C02 fh_a1 "BEGIN; SET app.tenant_id='${TB}'; WITH u AS (UPDATE leads_actor SET name='pwned' WHERE code='B1-C1' RETURNING 1) SELECT count(*) FROM u; ROLLBACK;"
expect_deny  C03 fh_a1 "BEGIN; SET app.tenant_id='${TB}'; INSERT INTO leads_actor (tenant_id, owner_actor_id, code, name) VALUES ('${TB}','${B1}','X-INJ','injected'); ROLLBACK;" "42501" "DENY_RLS" "row-level security"
expect_value C04 fh_b1 "SET app.tenant_id='${TA}'; SET app.user_id='${A1}'; SELECT count(*) FROM leads_actor WHERE tenant_id='${TA}';" "0"
expect_value C05 fh_a2 "SET app.tenant_id='${TB}'; SELECT count(*) FROM leads_actor WHERE tenant_id='${TB}';" "0"

# ===========================================================================
# D) role / ACL / policy / anchor integrity
# ===========================================================================
expect_deny  D01 fh_a1 "SET ROLE fh_a2; SELECT 1;" "42501" "DENY_ACL" "permission denied to set role"
expect_deny  D02 fh_a1 "SET ROLE fh_owner; SELECT 1;" "42501" "DENY_ACL" "permission denied to set role"
expect_value D03 fh_a1 "SELECT pg_has_role('fh_a1','fh_a2','USAGE')::text||','||pg_has_role('fh_a1','fh_owner','USAGE')::text||','||pg_has_role('fh_a1','fh_b1','USAGE')::text;" "false,false,false"
expect_value D04 postgres "SELECT count(*) FROM pg_auth_members m WHERE m.roleid::regrole::text LIKE 'fh%' OR m.member::regrole::text LIKE 'fh%';" "0"
expect_deny  D05 fh_a1 "SELECT count(*) FROM actor_identity_map;" "42501" "DENY_ACL" "permission denied for table actor_identity_map"
expect_deny  D06 fh_a1 "BEGIN; UPDATE actor_identity_map SET is_admin=true WHERE role_name='fh_a1'; ROLLBACK;" "42501" "DENY_ACL" "permission denied for table actor_identity_map"
expect_deny  D07 fh_a1 "BEGIN; CREATE ROLE fh_escalated LOGIN; ROLLBACK;" "42501" "DENY_ACL" "permission denied to create role"
expect_deny  D08 fh_a1 "BEGIN; GRANT fh_a2 TO fh_a1; ROLLBACK;" "42501" "DENY_ACL" "permission denied to grant role"
expect_deny  D09 fh_a1 "BEGIN; ALTER ROLE fh_a1 SUPERUSER; ROLLBACK;" "42501" "DENY_ACL" "permission denied to alter role"
expect_deny  D10 fh_a1 "BEGIN; ALTER TABLE leads_actor DISABLE ROW LEVEL SECURITY; ROLLBACK;" "42501" "DENY_OWNER" "must be owner of table leads_actor"
expect_deny  D11 fh_a1 "BEGIN; CREATE POLICY wideopen ON leads_actor FOR SELECT USING (true); ROLLBACK;" "42501" "DENY_OWNER" "must be owner of table leads_actor"
expect_value D12 postgres "SELECT count(*) FROM pg_roles WHERE rolname LIKE 'fh%' AND (rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolinherit OR rolreplication);" "0"
expect_value D13 fh_a1 "SELECT bool_and(relrowsecurity AND relforcerowsecurity)::text FROM pg_class WHERE relname IN ('leads_actor','admin_grants');" "true"
expect_value D14 postgres "SELECT relowner::regrole::text FROM pg_class WHERE relname='actor_identity_map';" "fh_owner"
# F4: effective PUBLIC EXECUTE must be zero for the anchor functions
expect_value D15 postgres "SELECT count(*) FROM public.fh_effective_public_execute() WHERE func LIKE 'app_actor%' OR func LIKE 'fh_%';" "0"
expect_deny  D16 fh_a1 "BEGIN; CREATE FUNCTION public.fh_hijack() RETURNS uuid LANGUAGE sql AS 'SELECT NULL::uuid'; ROLLBACK;" "42501" "DENY_ACL" "permission denied for schema public"
expect_value D17 fh_a1 "SELECT (SELECT current_u||','||session_u FROM public.fh_probe_invoker())||' / '||(SELECT current_u||','||session_u FROM public.fh_probe_definer())||' / '||coalesce(public.fh_wrong_tenant_via_current_user()::text,'NULL');" "fh_a1,fh_a1 / fh_owner,fh_a1 / NULL"
expect_value D18 fh_a1 "CREATE FUNCTION pg_temp.app_actor_tenant() RETURNS uuid LANGUAGE sql AS \$f\$ SELECT '${TB}'::uuid \$f\$; CREATE FUNCTION pg_temp.app_actor_is_admin() RETURNS boolean LANGUAGE sql AS \$f\$ SELECT true \$f\$; SET search_path = pg_temp, public; SELECT (SELECT count(*) FROM leads_actor)||'|'||(SELECT count(*) FROM admin_grants);" "2|0"
# schema privileges for login roles: USAGE yes, CREATE no
expect_value D19 postgres "SELECT string_agg(r||':'||has_schema_privilege(r,'public','USAGE')::text||'/'||has_schema_privilege(r,'public','CREATE')::text, ',' ORDER BY r) FROM (VALUES ('fh_a1'),('fh_a2'),('fh_b1')) v(r);" "fh_a1:true/false,fh_a2:true/false,fh_b1:true/false"
# resolvers are SECURITY DEFINER, owned by fh_owner, with pinned search_path
expect_value D20 postgres "SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname IN ('app_actor_tenant','app_actor_id','app_actor_is_admin') AND p.prosecdef AND p.proowner::regrole::text='fh_owner' AND array_to_string(p.proconfig,',') LIKE 'search_path=%';" "3"

# ===========================================================================
# F1 negative controls — non-security SQLSTATEs can never pass, even when a
# test wrongly declares them as expected.
# ===========================================================================
V=$(deny_verdict fh_a1 "SELEC 1;" "42601" "DENY_ACL" "")
[[ "${V%%|*}" == "NON_SECURITY_FAILURE_42601" ]] && record F1a PASS "reject 42601 even if expected" "${V%%|*}" "syntax error cannot be a denial" \
  || record F1a ASSERTION_FAIL "reject 42601 even if expected" "${V%%|*}" "classifier accepted a syntax error"
V=$(deny_verdict fh_a1 "SELECT nope FROM leads_actor;" "42703" "DENY_ACL" "")
[[ "${V%%|*}" == "NON_SECURITY_FAILURE_42703" ]] && record F1b PASS "reject 42703 even if expected" "${V%%|*}" "undefined column cannot be a denial" \
  || record F1b ASSERTION_FAIL "reject 42703 even if expected" "${V%%|*}" "classifier accepted 42703"
V=$(deny_verdict fh_a1 "BEGIN; INSERT INTO leads_actor (tenant_id, owner_actor_id, code, name) VALUES ('${TA}','${A1}','A1-C1','dup'); ROLLBACK;" "23505" "DENY_RLS" "")
[[ "${V%%|*}" == "NON_SECURITY_FAILURE_23505" ]] && record F1c PASS "reject 23505 even if expected" "${V%%|*}" "unique violation cannot be a denial" \
  || record F1c ASSERTION_FAIL "reject 23505 even if expected" "${V%%|*}" "classifier accepted 23505"
# wrong KIND must fail even with the right SQLSTATE
V=$(deny_verdict fh_a1 "BEGIN; UPDATE leads_actor SET owner_actor_id='${A2}' WHERE code='A1-C1'; ROLLBACK;" "42501" "DENY_RLS" "")
[[ "${V%%|*}" == "WRONG_KIND_DENY_TRIGGER" ]] && record F1d PASS "42501 with wrong kind fails" "${V%%|*}" "kind must match the control" \
  || record F1d ASSERTION_FAIL "42501 with wrong kind fails" "${V%%|*}" "kind check did not fire"

# ===========================================================================
# F2 negative controls — fingerprint read contract
# ===========================================================================
fp_read "SELECT public.fh_no_such_function();"
[[ $FP_OK -eq 0 && $FP_RC -ne 0 ]] && record F2a PASS "rc!=0 => not usable" "rc=$FP_RC ok=$FP_OK" "missing function" \
  || record F2a ASSERTION_FAIL "rc!=0 => not usable" "rc=$FP_RC ok=$FP_OK" "contract did not reject"
fp_read "SELECT 'not-a-hash'; SELECT 1/0;"
[[ $FP_OK -eq 0 ]] && record F2b PASS "non-empty stdout + rc!=0 rejected" "rc=$FP_RC len=${#FP_VALUE}" "stdout present but query failed" \
  || record F2b ASSERTION_FAIL "non-empty stdout + rc!=0 rejected" "rc=$FP_RC len=${#FP_VALUE}" "contract accepted a failed read"
fp_read "SELECT 'deadbeef';"
[[ $FP_OK -eq 0 ]] && record F2c PASS "wrong-shape value rejected" "len=${#FP_VALUE}" "not 64 hex chars" \
  || record F2c ASSERTION_FAIL "wrong-shape value rejected" "len=${#FP_VALUE}" "contract accepted a bad value"

# ===========================================================================
# F4 negative control — a function left with the DEFAULT ACL must be detected
# ===========================================================================
q postgres "BEGIN; CREATE FUNCTION public.fh_default_acl_probe() RETURNS int LANGUAGE sql AS 'SELECT 1'; SELECT count(*) FROM public.fh_effective_public_execute() WHERE func LIKE 'fh_default_acl_probe%'; ROLLBACK;"
if [[ $RC -eq 0 && "$OUT" == "1" ]]; then record F4a PASS "default-ACL function detected" "1" "proacl IS NULL resolved via acldefault"
else record F4a ASSERTION_FAIL "default-ACL function detected" "$OUT rc=$RC" "$ERR"; fi
q postgres "BEGIN; CREATE FUNCTION public.fh_revoked_probe() RETURNS int LANGUAGE sql AS 'SELECT 1'; REVOKE ALL ON FUNCTION public.fh_revoked_probe() FROM PUBLIC; SELECT count(*) FROM public.fh_effective_public_execute() WHERE func LIKE 'fh_revoked_probe%'; ROLLBACK;"
if [[ $RC -eq 0 && "$OUT" == "0" ]]; then record F4b PASS "revoked function not flagged" "0" "explicit REVOKE respected"
else record F4b ASSERTION_FAIL "revoked function not flagged" "$OUT rc=$RC" "$ERR"; fi

# ===========================================================================
# F5 negative control — the HBA trust detector itself
# ===========================================================================
q postgres "SELECT count(*) FROM pg_hba_file_rules WHERE error IS NULL AND auth_method='trust';"
if [[ $RC -eq 0 && "$OUT" == "0" ]]; then record F5a PASS "no trust rule anywhere" "0" "pg_hba_file_rules"
else record F5a ASSERTION_FAIL "no trust rule anywhere" "$OUT rc=$RC" "$ERR"; fi

# ===========================================================================
# H) existence channels, session reuse, revocation
# ===========================================================================
expect_deny H01 fh_a1 "BEGIN; INSERT INTO leads_actor (id, tenant_id, owner_actor_id, code, name) VALUES ('${HID_A2}','${TA}','${A1}','probe','probe'); ROLLBACK;" "42501" "DENY_ACL" "permission denied for table leads_actor"
expect_zero_rows H02 fh_a1 "BEGIN; WITH u AS (UPDATE leads_actor SET name='probe' WHERE id='${HID_A2}' RETURNING 1) SELECT count(*) FROM u; ROLLBACK;"
# EXPECTED_FINDING, never a control pass (F1 exception, own counter)
V=$(deny_verdict fh_a1 "BEGIN; INSERT INTO leads_actor (tenant_id, owner_actor_id, code, name) VALUES ('${TA}','${A1}','A2-SECRET','probe'); ROLLBACK;" "42501" "DENY_RLS" "")
if [[ "${V%%|*}" == "NON_SECURITY_FAILURE_23505" ]]; then
  record H03 EXPECTED_FINDING "oracle OPEN intra-tenant" "23505" "UNIQUE(tenant_id,code) reveals a hidden row inside the tenant"
else
  record H03 ASSERTION_FAIL "oracle OPEN intra-tenant" "${V%%|*}" "unexpected classification"
fi
expect_deny H04 fh_a1 "BEGIN; INSERT INTO leads_actor (tenant_id, owner_actor_id, code, name) VALUES ('${TB}','${A1}','B1-C1','probe'); ROLLBACK;" "42501" "DENY_RLS" "row-level security"

# single polluted session
: > "$WORKDIR/h05.out"; : > "$WORKDIR/h05.err"
PGPASSWORD="$(pw_for fh_a1)" psql -X -q -tA -v ON_ERROR_STOP=1 -v VERBOSITY=verbose \
  -h "$HOST" -p "$PORT" -U fh_a1 -d "$DB" \
  -c "SET app.user_id='${A2}'; SET app.tenant_id='${TB}'; SELECT count(*) FROM leads_actor;" \
  -c "RESET app.user_id; RESET app.tenant_id; SELECT count(*) FROM leads_actor;" \
  -c "DISCARD ALL;" \
  -c "SELECT count(*) FROM leads_actor;" > "$WORKDIR/h05.out" 2> "$WORKDIR/h05.err"
H05_RC=$?
H05_OUT=$(tr '\n' ' ' < "$WORKDIR/h05.out" | sed 's/ *$//')
if [[ $H05_RC -eq 0 && "$H05_OUT" == "2 2 2" ]]; then record H05 PASS "2 2 2 in one session" "$H05_OUT" "forge, RESET, DISCARD ALL all irrelevant"
else record H05 ASSERTION_FAIL "2 2 2 in one session" "$H05_OUT rc=$H05_RC" "$(tr '\n' ' ' < "$WORKDIR/h05.err" | cut -c1-120)"; fi

# F6a — mechanism inside ONE rollback-guaranteed transaction (no committed window)
q postgres "BEGIN; UPDATE actor_identity_map SET actor_status='SUSPENDED' WHERE role_name='fh_a5'; SELECT count(*) FROM leads_actor WHERE tenant_id = (SELECT tenant_id FROM actor_identity_map WHERE role_name='fh_a5' AND actor_status='ACTIVE'); ROLLBACK;"
if [[ $RC -eq 0 && "$OUT" == "0" ]]; then record H06a PASS "in-tx: resolver yields nothing" "0" "rollback-guaranteed; does NOT prove cross-connection revocation"
else record H06a ASSERTION_FAIL "in-tx: resolver yields nothing" "$OUT rc=$RC" "$ERR"; fi

# F6b — cross-connection visibility, dedicated actor, marker + verified restore
H06B_VERDICT='ASSERTION_FAIL'; H06B_ACT=''; H06B_EV=''
touch "$RECOVERY_MARKER"
q postgres "UPDATE actor_identity_map SET actor_status='SUSPENDED' WHERE role_name='fh_a5';"
if [[ $RC -ne 0 ]]; then
  H06B_VERDICT='HARNESS_ERROR'; H06B_ACT='suspend failed'; H06B_EV="$ERR"
else
  q fh_a5 "SELECT count(*) FROM leads_actor;"
  MID="$OUT"; MID_RC=$RC
  q postgres "UPDATE actor_identity_map SET actor_status='ACTIVE' WHERE role_name='fh_a5';"
  RESTORE_RC=$RC
  q postgres "SELECT actor_status FROM actor_identity_map WHERE role_name='fh_a5';"
  VERIFY="$OUT"; VERIFY_RC=$RC
  q fh_a5 "SELECT count(*) FROM leads_actor;"
  END="$OUT"; END_RC=$RC
  if [[ $RESTORE_RC -eq 0 && $VERIFY_RC -eq 0 && "$VERIFY" == "ACTIVE" ]]; then rm -f "$RECOVERY_MARKER"; fi
  if [[ $MID_RC -eq 0 && $END_RC -eq 0 && "$MID" == "0" && "$END" == "1" && "$VERIFY" == "ACTIVE" ]]; then
    H06B_VERDICT='PASS'; H06B_ACT='0 then 1, restored'
    H06B_EV='committed window exists between suspend and restore; marker-based idempotent recovery covers it'
  else
    H06B_ACT="mid=$MID end=$END verify=$VERIFY"; H06B_EV="restore_rc=$RESTORE_RC"
  fi
fi
record H06b "$H06B_VERDICT" "cross-conn: 0 then 1" "$H06B_ACT" "$H06B_EV"

# F6c — interruption safety of the in-transaction variant: kill psql mid-tx
printf "BEGIN;\nUPDATE actor_identity_map SET actor_status='SUSPENDED' WHERE role_name='fh_a5';\nSELECT pg_sleep(30);\nROLLBACK;\n" > "$WORKDIR/h06c.sql"
PGPASSWORD="$(pw_for postgres)" psql -X -q -tA -h "$HOST" -p "$PORT" -U postgres -d "$DB" -f "$WORKDIR/h06c.sql" >/dev/null 2>&1 &
H06C_PID=$!
sleep 3
kill -9 "$H06C_PID" >/dev/null 2>&1
wait "$H06C_PID" 2>/dev/null
sleep 2
q postgres "SELECT actor_status FROM actor_identity_map WHERE role_name='fh_a5';"
if [[ $RC -eq 0 && "$OUT" == "ACTIVE" ]]; then
  record H06c PASS "SIGKILL mid-tx leaves ACTIVE" "ACTIVE" "PostgreSQL rolled the aborted transaction back"
else
  record H06c ASSERTION_FAIL "SIGKILL mid-tx leaves ACTIVE" "$OUT rc=$RC" "BLOCKED_CLEANUP_REQUIRED if not ACTIVE"
fi
rm -f "$WORKDIR/h06c.sql"

# ===========================================================================
# G) integrity — fingerprint, fail-closed on both sides (F2 contract)
# ===========================================================================
fp_read
if [[ $FP_OK -ne 1 ]]; then
  record G01 HARNESS_ERROR "fp(after) readable" "rc=$FP_RC len=${#FP_VALUE}" "$FP_ERR"
  record G02 HARNESS_ERROR "fp(before)==fp(after)" "unavailable" "after-read failed"
else
  FP_AFTER="$FP_VALUE"
  record G01 PASS "fp(after) readable" "64 hex, rc=0" "contract satisfied"
  if [[ "$FP_BEFORE" == "$FP_AFTER" ]]; then
    record G02 PASS "fp(before)==fp(after)" "identical" "components 01..17"
  else
    record G02 ASSERTION_FAIL "fp(before)==fp(after)" "DRIFT" "before=$FP_BEFORE after=$FP_AFTER"
  fi
fi

# ===========================================================================
# MANIFEST enforcement
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
echo "PASS=$PASS_N ASSERTION_FAIL=$FAIL_N HARNESS_ERRORS=$HARNESS_N EXPECTED_FINDINGS=$FINDING_N"
echo "FINGERPRINT_BEFORE=$FP_BEFORE"
echo "FINGERPRINT_AFTER=${FP_AFTER:-<unavailable>}"
echo "PGBOUNCER_POOLING=NOT_VERIFIED (no pooler in this sandbox)"
MANIFEST_OK=1
[[ -n "$MISSING" || -n "$DUPES" || -n "$EXTRA" || "$ACTUAL_COUNT" -ne "$EXPECTED_COUNT" ]] && MANIFEST_OK=0
echo "MANIFEST_COMPLETE=$([[ $MANIFEST_OK -eq 1 ]] && echo PASS || echo FAIL)"
if [[ -f "$RECOVERY_MARKER" ]]; then
  echo "RECOVERY_MARKER_PRESENT=YES (fh_a5 may be suspended — BLOCKED_CLEANUP_REQUIRED)"
  MANIFEST_OK=0
fi

if [[ $FAIL_N -eq 0 && $HARNESS_N -eq 0 && $MANIFEST_OK -eq 1 ]]; then
  echo "OVERALL=PASS_SCOPED"; exit 0
else
  echo "OVERALL=FAIL"; exit 1
fi
