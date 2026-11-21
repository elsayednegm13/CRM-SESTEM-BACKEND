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

# F5 FIX3 (poc04-last-proof-correction): refuse to inherit any ambient libpq
# connection parameter from the calling shell/environment — every connection
# this harness makes states its own host/port/db/sslmode/gssencmode
# explicitly (see q()/fp_read() below), so an inherited PGSSLMODE, PGHOST,
# PGGSSENCMODE, etc. in the invoking shell can never silently change which
# HBA rule our "plain, non-SSL, non-GSS, TCP" test connection actually hits.
unset PGHOST PGHOSTADDR PGPORT PGDATABASE PGUSER PGSERVICE PGSSLMODE \
      PGGSSENCMODE PGSSLCERT PGSSLKEY PGSSLROOTCERT PGCHANNELBINDING 2>/dev/null || true

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
AUTH01 AUTH02 AUTH03 AUTH04 AUTH05 AUTH06 AUTH07 AUTH08 AUTH09 AUTH10 AUTH11
A01 A02 A03 A04 A05 A06 A07 A08 A09 A10
B01 B02 B03 B04 B05 B06 B07 B08 B09 B10 B11
C01 C02 C03 C04 C05
D01 D02 D03 D04 D05 D06 D07 D08 D09 D10 D11 D12 D13 D14 D15 D16 D17 D18 D19 D20
F1a F1b F1c F1d F2a F2b F2c F3a F3b F4a F4b F5a F5b
G01 G02
H01 H02 H03 H04 H05 H06a H06b H06c
"
EXPECTED_IDS=$(echo $MANIFEST)
EXPECTED_COUNT=$(echo $MANIFEST | wc -w)

PASS_N=0; FAIL_N=0; HARNESS_N=0; FINDING_N=0
RECORDED_IDS=""
EXPECTED_FINDING_IDS=""
H03_VERDICT=''
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
      -h "$host" -p "$port" -U "$role" -d "dbname=$db sslmode=disable gssencmode=disable" -c "$sql" \
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
    EXPECTED_FINDING)           FINDING_N=$((FINDING_N+1)); EXPECTED_FINDING_IDS="$EXPECTED_FINDING_IDS $1";;
    HARNESS_ERROR)              HARNESS_N=$((HARNESS_N+1));;
    *)                          FAIL_N=$((FAIL_N+1));;
  esac
  [[ "$1" == "H03" ]] && H03_VERDICT="$2"
  return 0
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
      -h "$HOST" -p "$PORT" -U postgres -d "dbname=$DB sslmode=disable gssencmode=disable" -c "$sql" \
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
# F5 FIX (poc04-closeout): the prior AUTH gate only proved "no rule that
# matches our test path is 'trust'". That is necessary but not sufficient:
# a matching rule of 'md5' (or 'password', 'ident', 'peer', 'cert', ...)
# would ALSO let every correct/missing/wrong-password probe behave exactly
# as a scram rule would (correct succeeds, missing/wrong are refused), so
# AUTH03-AUTH05 could all PASS under md5 and the gate would never notice
# the weaker method. It also read pg_hba_file_rules (the FILE on disk)
# without ever proving a reload had actually loaded that file into the
# running postmaster's effective configuration.
#
# FIX: (a) explicitly reload before judging anything and confirm success;
# (b) for POSTGRES and every one of the 7 matrix logins, resolve the ACTUAL
# first-matching HBA rule for our real connection path (type=host,
# address containing 127.0.0.1, by ascending line_number = real priority
# order) and require its auth_method to be EXACTLY 'scram-sha-256' — not
# merely "not trust". hba_effective_method() is also exposed standalone so
# the F5 negative control (section below) can probe it after an
# intentional md5 mutation without re-running the whole gate.
# ===========================================================================
# ---------------------------------------------------------------------------
# F5 FIX2 (poc04-targeted-gate): Codex (VERIFIED_SOURCE) found that the
# earlier matcher treated address='0.0.0.0' as "matches everything",
# ignoring the SEPARATE netmask column entirely. A rule
#   host all all 0.0.0.0/32 scram-sha-256     (address=0.0.0.0, netmask=255.255.255.255 — matches ONLY 0.0.0.0, never 127.0.0.1)
# followed by
#   host all all 127.0.0.1/32 md5             (the rule that actually matches our loopback test connection)
# would have the OLD matcher pick the first row by naive address-literal
# matching and wrongly report scram-sha-256, even though the REAL
# first-matching rule for 127.0.0.1 is the md5 one.
#
# FIX: walk every type/db/user-matching row in true line_number order and,
# for EACH row in turn, evaluate REAL network membership of 127.0.0.1 using
# address AND netmask together (network bitwise AND, not string/CIDR-text
# comparison): a host H matches network (address,netmask) iff
#   (H & netmask) = (address & netmask)
# This is the same containment test PostgreSQL itself uses internally.
# address='all' always matches. address IN ('samehost','samenet'), or any
# row we cannot parse as inet, is NOT skipped silently — it FAILS CLOSED
# immediately (we cannot prove what matches without evaluating server-local
# interface state, so we refuse to claim a verdict past that point).
# ---------------------------------------------------------------------------
hba_addr_matches_127 () { # address netmask -> sets OUT to 't'/'f', or FAIL_CLOSED via RC marker
  local addr="$1" mask="$2"
  q postgres "SELECT (family('${addr}'::inet) = family(inet '127.0.0.1'))
                     AND ( (inet '127.0.0.1' & '${mask}'::inet) = ('${addr}'::inet & '${mask}'::inet) );"
}

# ---------------------------------------------------------------------------
# F5 FIX3 (poc04-last-proof-correction): Codex (VERIFIED_SOURCE) found two
# further matcher bugs, both in the row-selection WHERE clause above:
#   (1) 'replication' = ANY(database) was OR'd into the match condition, so
#       a rule scoped ONLY to physical replication connections (database =
#       {replication}) was treated as if it also covered our ordinary
#       `-d <synthetic_db>` connection. It does not: a replication-only rule
#       NEVER matches a normal database connection. Removed outright — only
#       'all' or the literal db name now counts as a match.
#   (2) type IN ('host','hostssl','hostnossl') included 'hostssl', which
#       matches ONLY SSL-encrypted connections; our test connection is now
#       explicitly proven non-SSL/non-GSS (sslmode=disable, gssencmode=
#       disable — see q()/fp_read() and AUTH10/AUTH11 below), so a
#       'hostssl'-only rule could never legitimately be the one governing
#       us and must be excluded, not merely left unordered. 'hostnogssenc'
#       is added (it DOES apply to our proven non-GSS connection); plain
#       'host' still matches regardless of SSL/GSS state. 'hostgssenc' is
#       correctly excluded by omission (same reasoning as hostssl).
# ---------------------------------------------------------------------------
hba_effective_method () { # role -> sets OUT to the method of the TRUE first-matching rule,
                           # or '<no_matching_rule>' / '<FAIL_CLOSED:reason>' / '<query_failed>'
  local role="$1" rows line addr mask method
  q postgres "SELECT string_agg(line_number||'~'||coalesce(address,'<null>')||'~'||coalesce(netmask,'<null>')||'~'||auth_method, E'\n' ORDER BY line_number)
              FROM pg_hba_file_rules
              WHERE error IS NULL
                AND type IN ('host','hostnossl','hostnogssenc')
                AND ('${role}' = ANY(user_name) OR 'all' = ANY(user_name))
                AND ('${DB}' = ANY(database) OR 'all' = ANY(database));"
  if [[ $RC -ne 0 ]]; then OUT='<query_failed>'; return; fi
  rows="$OUT"
  OUT='<no_matching_rule>'
  if [[ -z "$rows" ]]; then return; fi
  while IFS='~' read -r line addr mask method; do
    [[ -z "$line" ]] && continue
    if [[ "$addr" == "all" ]]; then OUT="$method"; return; fi
    if [[ "$addr" == "samehost" || "$addr" == "samenet" || "$addr" == "<null>" || "$mask" == "<null>" ]]; then
      OUT="<FAIL_CLOSED:unresolvable_address_at_line_${line}:${addr}>"; return
    fi
    hba_addr_matches_127 "$addr" "$mask"
    if [[ $RC -ne 0 ]]; then OUT="<FAIL_CLOSED:unparseable_address_at_line_${line}:${addr}/${mask}>"; return; fi
    if [[ "$OUT" == "t" ]]; then OUT="$method"; return; fi
  done <<< "$rows"
  OUT='<no_matching_rule>'
}

auth_gate () {
  local role bad=0
  # (0) force a reload and prove it actually ran before trusting the file view
  q postgres "SELECT pg_conf_load_time();"; local load_before="$OUT"
  q postgres "SELECT pg_reload_conf();"
  if [[ $RC -ne 0 || "$OUT" != "t" ]]; then echo "AUTH_GATE_FAIL: pg_reload_conf did not report success" >&2; return 1; fi
  sleep 0.3
  q postgres "SELECT pg_conf_load_time();"; local load_after="$OUT"
  if [[ $RC -ne 0 || -z "$load_after" ]]; then echo "AUTH_GATE_FAIL: cannot confirm pg_conf_load_time after reload" >&2; return 1; fi
  record AUTH07 PASS "reload acknowledged, load_time readable" "before=$load_before after=$load_after" "pg_reload_conf+pg_conf_load_time"
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
  # (2b) the ACTUAL first-matching rule for every login (incl. postgres) must be scram-sha-256,
  # not merely "not trust" — this is what a weaker-than-trust mutant (md5) would otherwise hide.
  for role in postgres $MATRIX_LOGINS; do
    hba_effective_method "$role"
    if [[ "$OUT" != "scram-sha-256" ]]; then
      echo "AUTH_GATE_FAIL: effective HBA method for $role is '$OUT', not scram-sha-256" >&2; bad=1; fi
  done
  [[ $bad -eq 0 ]] || return 1
  record AUTH08 PASS "effective matching rule is scram-sha-256 x8" "8/8" "hba_effective_method, line_number-ordered"
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
  # (7) F5 FIX2: §3-ب — the transport check above only covered the postgres
  # superuser connection the gate happens to use for its own queries; prove
  # every one of the 7 matrix logins ALSO authenticates over the same real
  # TCP endpoint (never a unix socket or an inherited PGHOST), since it is
  # THAT connection path whose HBA match AUTH08 is reasoning about.
  for role in $MATRIX_LOGINS; do
    q "$role" "SELECT CASE WHEN inet_server_addr() IS NULL THEN 'socket' ELSE host(inet_server_addr())||':'||inet_server_port() END;"
    if [[ $RC -ne 0 || "$OUT" != "127.0.0.1:${PORT}" ]]; then
      echo "AUTH_GATE_FAIL: unexpected transport for $role [$OUT]" >&2; bad=1; fi
  done
  [[ $bad -eq 0 ]] || return 1
  record AUTH09 PASS "tcp 127.0.0.1:${PORT} x7 matrix logins" "7/7" "inet_server_addr/port per matrix login"
  # ---------------------------------------------------------------------
  # F5 FIX3 — §3-A: prove, from a FRESH connection explicitly configured
  # sslmode=disable/gssencmode=disable (see q(), unchanged for this call),
  # that our own test connection really is what hba_effective_method()'s
  # type filter (host/hostnossl/hostnogssenc, excluding hostssl/hostgssenc)
  # assumes it is: plain TCP from 127.0.0.1, with TLS NOT in use for this
  # session. This is evidence about OUR OWN test connection's contract
  # only — it is not a claim about the on-wire SASL/MD5 auth exchange,
  # which remains ON_WIRE_AUTH_METHOD=NOT_VERIFIED (see F5b/final report).
  # ---------------------------------------------------------------------
  q postgres "SELECT host(inet_client_addr());"
  if [[ $RC -ne 0 || "$OUT" != "127.0.0.1" ]]; then
    echo "AUTH_GATE_FAIL: inet_client_addr()='$OUT', not 127.0.0.1" >&2; return 1; fi
  record AUTH10 PASS "inet_client_addr=127.0.0.1" "$OUT" "proves our own test connection's client address"
  q postgres "SELECT coalesce((SELECT ssl::text FROM pg_stat_ssl WHERE pid = pg_backend_pid()), 'false');"
  if [[ $RC -ne 0 || "$OUT" != "false" ]]; then
    echo "AUTH_GATE_FAIL: pg_stat_ssl.ssl for our own session is '$OUT', expected false (sslmode=disable)" >&2; return 1; fi
  record AUTH11 PASS "pg_stat_ssl.ssl=false for our own session" "$OUT" "sslmode=disable honored; hostssl-only rules correctly excluded from our match set"
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
# F3 negative controls — unambiguous serialization (see 003_comparison.sql,
# fh_fingerprint): leads_actor.code/name are two adjacent free-text columns;
# the OLD bare '||','||' concatenation mapped
#   A: code='x,y', name='z'   and   B: code='x', name='y,z'
# to the SAME text. Both probes run inside their own BEGIN;...;ROLLBACK so
# neither ever commits and the baseline fingerprint is restored (F3b).
# ===========================================================================
F3_PROBE_ID='99999999-0000-0000-0000-000000000f01'
F3_PROBE_TS='2026-01-01 00:00:00+00'
q postgres "BEGIN;
INSERT INTO leads_actor (id, tenant_id, owner_actor_id, code, name, created_at)
  VALUES ('${F3_PROBE_ID}','${TA}','${A1}','x,y','z','${F3_PROBE_TS}');
SELECT public.fh_fingerprint()||'|'||('01:'||id||','||tenant_id||','||owner_actor_id||','||code||','||name||','
       ||to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US'))
  FROM leads_actor WHERE id='${F3_PROBE_ID}';
ROLLBACK;"
F3_RC_A=$RC; F3_FP_A="${OUT%%|*}"; F3_OLD_A="${OUT#*|}"
q postgres "BEGIN;
INSERT INTO leads_actor (id, tenant_id, owner_actor_id, code, name, created_at)
  VALUES ('${F3_PROBE_ID}','${TA}','${A1}','x','y,z','${F3_PROBE_TS}');
SELECT public.fh_fingerprint()||'|'||('01:'||id||','||tenant_id||','||owner_actor_id||','||code||','||name||','
       ||to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US'))
  FROM leads_actor WHERE id='${F3_PROBE_ID}';
ROLLBACK;"
F3_RC_B=$RC; F3_FP_B="${OUT%%|*}"; F3_OLD_B="${OUT#*|}"
if [[ $F3_RC_A -eq 0 && $F3_RC_B -eq 0 && ${#F3_FP_A} -eq 64 && ${#F3_FP_B} -eq 64 \
      && "$F3_OLD_A" == "$F3_OLD_B" && "$F3_FP_A" != "$F3_FP_B" ]]; then
  record F3a PASS "old concat equal, new fingerprint differs" "old_text_eq=1 fp_A!=fp_B" \
    "A:code=x,y/name=z vs B:code=x/name=y,z (old text identical: $F3_OLD_A)"
else
  record F3a ASSERTION_FAIL "old concat equal, new fingerprint differs" \
    "old_eq=$([[ "$F3_OLD_A" == "$F3_OLD_B" ]] && echo 1 || echo 0) fp_A=$F3_FP_A fp_B=$F3_FP_B" \
    "expected old-style text equal AND new fingerprint distinct"
fi
fp_read
if [[ $FP_OK -eq 1 && "$FP_VALUE" == "$FP_BEFORE" ]]; then
  record F3b PASS "fp unchanged after rollback-guaranteed F3 probes" "fp==baseline" "both inserts rolled back, no residue"
else
  record F3b ASSERTION_FAIL "fp unchanged after rollback-guaranteed F3 probes" "fp=$FP_VALUE baseline=$FP_BEFORE" "rollback did not fully restore state"
fi

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
# F5b — synthetic unit check of the membership predicate itself, independent
# of the live pg_hba.conf file (no mutation/reload needed). This is exactly
# the Codex scenario: address='0.0.0.0' with netmask=255.255.255.255 (i.e.
# a /32 rule that matches ONLY the literal address 0.0.0.0) must NOT be
# treated as matching 127.0.0.1, while address='0.0.0.0'/netmask='0.0.0.0'
# (the real 0.0.0.0/0 catch-all) correctly DOES match.
# ===========================================================================
hba_addr_matches_127 '0.0.0.0' '255.255.255.255'
F5B_NARROW="$OUT"; F5B_NARROW_RC=$RC
hba_addr_matches_127 '0.0.0.0' '0.0.0.0'
F5B_WIDE="$OUT"; F5B_WIDE_RC=$RC
if [[ $F5B_NARROW_RC -eq 0 && "$F5B_NARROW" == "f" && $F5B_WIDE_RC -eq 0 && "$F5B_WIDE" == "t" ]]; then
  record F5b PASS "0.0.0.0/32 no-match, 0.0.0.0/0 match" "narrow=f wide=t" "netmask-aware membership, not address-literal"
else
  record F5b ASSERTION_FAIL "0.0.0.0/32 no-match, 0.0.0.0/0 match" "narrow=$F5B_NARROW wide=$F5B_WIDE" "membership predicate did not distinguish netmask"
fi

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
  -h "$HOST" -p "$PORT" -U fh_a1 -d "dbname=$DB sslmode=disable gssencmode=disable" \
  -c "SET app.user_id='${A2}'; SET app.tenant_id='${TB}'; SELECT count(*) FROM leads_actor;" \
  -c "RESET app.user_id; RESET app.tenant_id; SELECT count(*) FROM leads_actor;" \
  -c "DISCARD ALL;" \
  -c "SELECT count(*) FROM leads_actor;" > "$WORKDIR/h05.out" 2> "$WORKDIR/h05.err"
H05_RC=$?
H05_OUT=$(tr '\n' ' ' < "$WORKDIR/h05.out" | sed 's/ *$//')
if [[ $H05_RC -eq 0 && "$H05_OUT" == "2 2 2" ]]; then record H05 PASS "2 2 2 in one session" "$H05_OUT" "forge, RESET, DISCARD ALL all irrelevant"
else record H05 ASSERTION_FAIL "2 2 2 in one session" "$H05_OUT rc=$H05_RC" "$(tr '\n' ' ' < "$WORKDIR/h05.err" | cut -c1-120)"; fi

# ---------------------------------------------------------------------------
# F6a FIX (poc04-closeout): the old H06a claim was "resolver yields nothing" —
# but this scenario never calls a resolver (app_actor_tenant/app_actor_id/
# app_actor_is_admin); it queries actor_identity_map directly as postgres.
# That claim was simply inaccurate. The least-change fix: H06a now proves
# ONLY what it actually can — that a BEGIN/ROLLBACK leaves actor_status and
# the whole-DB fingerprint exactly as they were (the mutation is visible
# mid-transaction, then fully undone) — and makes NO claim about resolvers
# or about revocation across a connection boundary (that is H06b/H06c).
# ---------------------------------------------------------------------------
fp_read; FP_H06A_BEFORE="$FP_VALUE"; FP_H06A_BEFORE_OK=$FP_OK
q postgres "BEGIN; UPDATE actor_identity_map SET actor_status='SUSPENDED' WHERE role_name='fh_a5';
SELECT actor_status FROM actor_identity_map WHERE role_name='fh_a5'; ROLLBACK;"
H06A_MID_RC=$RC; H06A_MID_STATUS="$OUT"
q postgres "SELECT actor_status FROM actor_identity_map WHERE role_name='fh_a5';"
H06A_AFTER_RC=$RC; H06A_AFTER_STATUS="$OUT"
fp_read; FP_H06A_AFTER="$FP_VALUE"; FP_H06A_AFTER_OK=$FP_OK
if [[ $H06A_MID_RC -eq 0 && "$H06A_MID_STATUS" == "SUSPENDED" && $H06A_AFTER_RC -eq 0 \
      && "$H06A_AFTER_STATUS" == "ACTIVE" && $FP_H06A_BEFORE_OK -eq 1 && $FP_H06A_AFTER_OK -eq 1 \
      && "$FP_H06A_BEFORE" == "$FP_H06A_AFTER" ]]; then
  record H06a PASS "in-tx mutation visible, then fully rolled back, fp unchanged" \
    "mid=SUSPENDED after=ACTIVE fp_eq=1" "BEGIN/ROLLBACK guarantee only; no resolver or cross-connection claim"
else
  record H06a ASSERTION_FAIL "in-tx mutation visible, then fully rolled back, fp unchanged" \
    "mid=$H06A_MID_STATUS after=$H06A_AFTER_STATUS fp_before=$FP_H06A_BEFORE fp_after=$FP_H06A_AFTER" "rollback guarantee violated"
fi

# ---------------------------------------------------------------------------
# F6b FIX (poc04-closeout): the old code did `touch "$RECOVERY_MARKER"` with
# its exit status discarded, then suspended fh_a5 unconditionally. If the
# marker write had silently failed (full disk, permissions, read-only tmp),
# fh_a5 would have been suspended with NO durable record to recover it.
# FIX: write identifying content (not just touch), verify it is actually
# on disk with the expected content, and refuse to run the UPDATE at all
# if that verification fails — BLOCK happens strictly before any mutation.
# ---------------------------------------------------------------------------
H06B_VERDICT='ASSERTION_FAIL'; H06B_ACT=''; H06B_EV=''
: > "$WORKDIR/marker.err"
printf 'role_name=fh_a5\nreason=H06b_cross_connection_test\npid=%s\nts=%s\n' "$$" "$(date -u +%FT%TZ 2>/dev/null || date -u)" \
  > "$RECOVERY_MARKER" 2>"$WORKDIR/marker.err"
MARKER_WRITE_RC=$?
MARKER_CONTENT=$(cat "$RECOVERY_MARKER" 2>/dev/null)
if [[ $MARKER_WRITE_RC -ne 0 || ! -s "$RECOVERY_MARKER" || "$MARKER_CONTENT" != *"role_name=fh_a5"* ]]; then
  H06B_VERDICT='HARNESS_ERROR'
  H06B_ACT='<marker precondition failed, fh_a5 left ACTIVE, UPDATE never issued>'
  H06B_EV="write_rc=$MARKER_WRITE_RC content_ok=$([[ "$MARKER_CONTENT" == *"role_name=fh_a5"* ]] && echo 1 || echo 0)"
  rm -f "$RECOVERY_MARKER" 2>/dev/null
else
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
fi
record H06b "$H06B_VERDICT" "cross-conn: 0 then 1" "$H06B_ACT" "$H06B_EV"

# ---------------------------------------------------------------------------
# F6c FIX (poc04-closeout): the old code only did `sleep 3` then `kill -9`,
# assuming (never verifying) that the UPDATE had executed and that the
# killed PID was genuinely still sitting inside an open transaction. FIX:
# the child itself emits a self-identifying ACK line (its own
# pg_backend_pid() plus the post-UPDATE status) which this script polls
# for on the child's own stdout — never a blind sleep — and then
# independently confirms via pg_stat_activity that exactly that backend is
# alive and mid pg_sleep() (i.e. inside the open, uncommitted transaction)
# BEFORE any signal is sent. Only the psql CLIENT pid ($H06C_PID) that this
# script itself spawned is ever signalled — never a server backend pid and
# never any other container's process.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# F6c FIX3 (poc04-last-proof-correction): Codex (VERIFIED_SOURCE) found that
# kill_rc==0/wait_rc==137 were genuinely proven (good), but backend
# DISAPPEARANCE from pg_stat_activity was only polled informationally and
# never required for PASS — so H06c could record a clean PASS while the
# original server backend was, in fact, still sitting inside its
# not-yet-aborted transaction. Client killed != server transaction finished.
#
# FIX: identity is now the COMPOSITE (pid, backend_start) captured from the
# ACK itself, not pid alone (a bare pid can be reused by an unrelated later
# process during a long poll). The pre-kill liveness/activity check, and the
# post-kill disappearance check, both match on this exact composite. Backend
# disappearance (by that composite) is now a HARD, REQUIRED gate — bounded
# by H06C_DISAPPEAR_TIMEOUT_SECONDS (default 40s, comfortably above the
# measured ~30-31s natural pg_sleep(30) completion) — before any
# actor_status/fingerprint readback is even attempted. Timing out with the
# composite identity still present is ASSERTION_FAIL /
# SERVER_ROLLBACK=NOT_VERIFIED, regardless of how clean a readback might
# otherwise look. Every stage is traced explicitly in the evidence string:
# ACK_RECEIVED, BACKEND_IDENTIFIED, PREKILL_ACTIVE, KILL_RC, WAIT_RC,
# BACKEND_DISAPPEARED, POST_ABORT_READBACK, FP_EQUAL.
# ---------------------------------------------------------------------------
fp_read; FP_H06C_BEFORE="$FP_VALUE"; FP_H06C_BEFORE_OK=$FP_OK
printf "BEGIN;\nUPDATE actor_identity_map SET actor_status='SUSPENDED' WHERE role_name='fh_a5';\nSELECT 'H06C_ACK:'||pg_backend_pid()||':'||(SELECT backend_start::text FROM pg_stat_activity WHERE pid=pg_backend_pid())||':'||actor_status FROM actor_identity_map WHERE role_name='fh_a5';\nSELECT pg_sleep(${H06C_SLEEP_SECONDS:-30});\nROLLBACK;\n" > "$WORKDIR/h06c.sql"
: > "$WORKDIR/h06c.out"; : > "$WORKDIR/h06c.err"
PGPASSWORD="$(pw_for postgres)" psql -X -q -tA -h "$HOST" -p "$PORT" -U postgres -d "dbname=$DB sslmode=disable gssencmode=disable" -f "$WORKDIR/h06c.sql" \
  > "$WORKDIR/h06c.out" 2> "$WORKDIR/h06c.err" &
H06C_PID=$!
H06C_ACK=''; H06C_WAITED=0
while [[ $H06C_WAITED -lt 10 ]]; do
  H06C_ACK=$(grep '^H06C_ACK:' "$WORKDIR/h06c.out" 2>/dev/null | head -1)
  [[ -n "$H06C_ACK" ]] && break
  sleep 0.3; H06C_WAITED=$((H06C_WAITED+1))
done
H06C_REST="${H06C_ACK#H06C_ACK:}"
H06C_BACKEND_PID="${H06C_REST%%:*}"
H06C_REST2="${H06C_REST#*:}"
H06C_BACKEND_START="${H06C_REST2%:*}"
H06C_ACK_STATUS="${H06C_REST2##*:}"
H06C_TRACE="ACK_RECEIVED=0"
if [[ -z "$H06C_ACK" || "$H06C_ACK_STATUS" != "SUSPENDED" || -z "$H06C_BACKEND_PID" || -z "$H06C_BACKEND_START" ]]; then
  kill -9 "$H06C_PID" >/dev/null 2>&1; wait "$H06C_PID" 2>/dev/null
  record H06c ASSERTION_FAIL "trace:$H06C_TRACE" "<no ACK within 3s>" \
    "UPDATE never confirmed before any kill was sent; refusing to call this a pass"
else
  H06C_TRACE="ACK_RECEIVED=1,BACKEND_IDENTIFIED=0"
  q postgres "SELECT count(*) FROM pg_stat_activity WHERE pid=${H06C_BACKEND_PID} AND backend_start::text='${H06C_BACKEND_START}' AND state = 'active' AND query ILIKE '%pg_sleep%';"
  H06C_ALIVE="$OUT"; H06C_ALIVE_RC=$RC
  if [[ $H06C_ALIVE_RC -ne 0 || "$H06C_ALIVE" != "1" ]]; then
    kill -9 "$H06C_PID" >/dev/null 2>&1; wait "$H06C_PID" 2>/dev/null
    record H06c ASSERTION_FAIL "trace:$H06C_TRACE" "<backend(pid,backend_start) not confirmed active in pg_sleep>" \
      "pg_stat_activity did not show backend pid=$H06C_BACKEND_PID,backend_start=$H06C_BACKEND_START state=active running pg_sleep (alive=$H06C_ALIVE)"
  else
    H06C_TRACE="ACK_RECEIVED=1,BACKEND_IDENTIFIED=1,PREKILL_ACTIVE=1"
    # Test-only knob (default 0, inert in every normal run): an explicit,
    # documented pause here — AFTER the active+pg_sleep prekill check and
    # BEFORE the kill -0 liveness precheck — is how the F6C-NEG-EARLY-EXIT
    # regression reliably reproduces "child exits naturally in the gap
    # between check and kill" without depending on a sub-10ms OS-scheduling
    # race that would be flaky across machines. It never touches Laravel or
    # product code; it only widens the window this script's OWN guard must
    # already handle (kill -0 before signalling).
    [[ -n "${H06C_TEST_DELAY_BEFORE_KILL_SECONDS:-}" ]] && sleep "$H06C_TEST_DELAY_BEFORE_KILL_SECONDS"
    kill -0 "$H06C_PID" 2>/dev/null
    H06C_PRECHECK_ALIVE_RC=$?
    continue_h06c=0
    if [[ $H06C_PRECHECK_ALIVE_RC -ne 0 ]]; then
      record H06c ASSERTION_FAIL "trace:$H06C_TRACE,KILL_RC=<not_attempted>" \
        "<child pid $H06C_PID already gone before signal>" "kill -0 precheck failed rc=$H06C_PRECHECK_ALIVE_RC; refusing to claim a kill that could not have happened"
    else
      kill -9 "$H06C_PID" 2>/dev/null
      H06C_KILL_RC=$?
      wait "$H06C_PID" 2>/dev/null
      H06C_WAIT_RC=$?
      H06C_TRACE="$H06C_TRACE,KILL_RC=$H06C_KILL_RC,WAIT_RC=$H06C_WAIT_RC"
      if [[ $H06C_KILL_RC -ne 0 || $H06C_WAIT_RC -ne 137 ]]; then
        record H06c ASSERTION_FAIL "trace:$H06C_TRACE" \
          "kill_rc=$H06C_KILL_RC wait_rc=$H06C_WAIT_RC" "kill and/or wait did not report a genuine SIGKILL termination of the owned child pid $H06C_PID"
      else
        continue_h06c=1
      fi
    fi
    if [[ $continue_h06c -eq 1 ]]; then
      # HARD GATE (not informational): backend disappearance by the exact
      # (pid, backend_start) composite is REQUIRED before any readback.
      H06C_GONE='1'; H06C_REAPED_SEC=''
      H06C_DISAPPEAR_TIMEOUT="${H06C_DISAPPEAR_TIMEOUT_SECONDS:-40}"
      H06C_POLL_START=$(date +%s 2>/dev/null || echo 0)
      for ((H06C_I=1; H06C_I<=H06C_DISAPPEAR_TIMEOUT; H06C_I++)); do
        sleep 1
        q postgres "SELECT count(*) FROM pg_stat_activity WHERE pid=${H06C_BACKEND_PID} AND backend_start::text='${H06C_BACKEND_START}';"
        H06C_GONE="$OUT"
        if [[ "$H06C_GONE" == "0" ]]; then
          H06C_REAPED_SEC=$(( $(date +%s 2>/dev/null || echo 0) - H06C_POLL_START )); break
        fi
      done
      if [[ "$H06C_GONE" != "0" ]]; then
        H06C_TRACE="$H06C_TRACE,BACKEND_DISAPPEARED=0(timeout=${H06C_DISAPPEAR_TIMEOUT}s)"
        record H06c ASSERTION_FAIL "trace:$H06C_TRACE,SERVER_ROLLBACK=NOT_VERIFIED" \
          "backend pid=$H06C_BACKEND_PID,backend_start=$H06C_BACKEND_START STILL PRESENT in pg_stat_activity after ${H06C_DISAPPEAR_TIMEOUT}s" \
          "client was killed but the original server backend never disappeared within the bound — SIGKILL of the client is NOT proof the server-side transaction finished"
      else
        H06C_TRACE="$H06C_TRACE,BACKEND_DISAPPEARED=1(${H06C_REAPED_SEC}s),POST_ABORT_READBACK=0"
        q postgres "SELECT actor_status FROM actor_identity_map WHERE role_name='fh_a5';"
        H06C_FINAL_RC=$RC; H06C_FINAL_STATUS="$OUT"
        fp_read; FP_H06C_AFTER="$FP_VALUE"; FP_H06C_AFTER_OK=$FP_OK
        if [[ $H06C_FINAL_RC -ne 0 || $FP_H06C_BEFORE_OK -ne 1 || $FP_H06C_AFTER_OK -ne 1 ]]; then
          record H06c ASSERTION_FAIL "trace:$H06C_TRACE" \
            "<readback failed: status_rc=$H06C_FINAL_RC fp_before_ok=$FP_H06C_BEFORE_OK fp_after_ok=$FP_H06C_AFTER_OK>" \
            "fail-closed: a failed or stale fingerprint/status read is never treated as evidence of anything"
        else
          H06C_TRACE="$H06C_TRACE(ok),FP_EQUAL=$([[ "$FP_H06C_BEFORE" == "$FP_H06C_AFTER" ]] && echo 1 || echo 0)"
          if [[ "$H06C_FINAL_STATUS" == "ACTIVE" && "$FP_H06C_BEFORE" == "$FP_H06C_AFTER" ]]; then
            record H06c PASS "trace:$H06C_TRACE" \
              "backend(pid=$H06C_BACKEND_PID,start=$H06C_BACKEND_START) kill_rc=$H06C_KILL_RC wait_rc=$H06C_WAIT_RC disappeared_after=${H06C_REAPED_SEC}s status=$H06C_FINAL_STATUS" \
              "full chain verified: ACK -> identity(pid+backend_start) -> active+pg_sleep prekill -> kill_rc=0/wait_rc=137 -> backend disappeared (hard gate, not informational) -> independent readback ACTIVE+fp unchanged"
          else
            record H06c ASSERTION_FAIL "trace:$H06C_TRACE" \
              "status=$H06C_FINAL_STATUS fp_before=$FP_H06C_BEFORE fp_after=$FP_H06C_AFTER" \
              "backend disappeared but post-abort readback did not match expectations; BLOCKED_CLEANUP_REQUIRED if actor_status != ACTIVE"
          fi
        fi
      fi
    fi
  fi
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

# ===========================================================================
# H03 FIX (poc04-closeout): OVERALL=PASS_SCOPED must never be reachable if
# H03's verdict silently changed, vanished, duplicated, or if some OTHER id
# also produced EXPECTED_FINDING. This is a hard invariant, independent of
# PASS_N/FAIL_N/HARNESS_N, so a mutation that turns H03 into a plain PASS
# (while every other scenario still PASSes and the manifest stays complete)
# is caught here, not by accident elsewhere.
# ===========================================================================
FINDING_CONTRACT_OK=1; FINDING_CONTRACT_REASON=''
if [[ "$H03_VERDICT" != "EXPECTED_FINDING" ]]; then
  FINDING_CONTRACT_OK=0; FINDING_CONTRACT_REASON="H03 verdict is '$H03_VERDICT', not EXPECTED_FINDING"
elif [[ "$FINDING_N" -ne 1 ]]; then
  FINDING_CONTRACT_OK=0; FINDING_CONTRACT_REASON="FINDING_N=$FINDING_N (expected exactly 1)"
elif [[ "$(echo $EXPECTED_FINDING_IDS)" != "H03" ]]; then
  FINDING_CONTRACT_OK=0; FINDING_CONTRACT_REASON="EXPECTED_FINDING ids=[$(echo $EXPECTED_FINDING_IDS)] (expected exactly H03 and no other id)"
fi
if [[ $FINDING_CONTRACT_OK -eq 1 ]]; then
  echo "FINDING_CONTRACT=PASS (H03=EXPECTED_FINDING exactly once, no other EXPECTED_FINDING id)"
else
  echo "FINDING_CONTRACT=FAIL ($FINDING_CONTRACT_REASON)"
  MANIFEST_OK=0
fi

if [[ $FAIL_N -eq 0 && $HARNESS_N -eq 0 && $MANIFEST_OK -eq 1 ]]; then
  echo "OVERALL=PASS_SCOPED"; exit 0
else
  echo "OVERALL=FAIL"; exit 1
fi
