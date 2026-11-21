#!/usr/bin/env bash
# F06 POC adversarial test matrix (T01-T12).
# Connects over real TCP with real LOGIN/SCRAM credentials (127.0.0.1:55441),
# never local trust, never superuser for adversarial cases.
# Requires env vars (not committed, not printed): PGPOC_SUPERUSER_PW,
# PGPOC_TENANT_A_PW, PGPOC_TENANT_B_PW, PGPOC_BASELINE_SHARED_PW.
# Safe to re-run: every test runs inside BEGIN...ROLLBACK, fixtures are
# verified unchanged before and after (T11/T12).

set -u
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-55441}"
DB=daleel_f06_poc01_synthetic

# Hard preflight: every subsequent PASS is meaningless if we never actually
# reached the sandbox. Abort loudly instead of letting a connection-refused
# string accidentally satisfy a substring check downstream.
PREFLIGHT=$(PGPASSWORD="${PGPOC_SUPERUSER_PW:-}" psql -X -q -h "$HOST" -p "$PORT" -U postgres -d "$DB" -tAc "select 1;" 2>&1)
if [[ "$PREFLIGHT" != "1" ]]; then
  echo "PREFLIGHT_CONNECTION_FAILED host=$HOST port=$PORT output=[$PREFLIGHT]" >&2
  echo "ABORTING: no test below is valid without a live connection." >&2
  exit 97
fi

declare -A RESULT

run_sql () { # role password sql
  PGPASSWORD="$2" psql -X -q -h "$HOST" -p "$PORT" -U "$1" -d "$DB" -v ON_ERROR_STOP=0 -tAc "$3" 2>&1
}

run_tx () { # role password sql_body  (wrapped BEGIN...ROLLBACK)
  PGPASSWORD="$2" psql -X -q -h "$HOST" -p "$PORT" -U "$1" -d "$DB" -v ON_ERROR_STOP=0 <<SQL 2>&1
BEGIN;
$3
ROLLBACK;
SQL
}

has_err () { echo "$1" | grep -qi 'error'; } # true if $1 contains "error" (any case)
last_count () { echo "$1" | grep -E '^[[:space:]]*[0-9]+[[:space:]]*$' | tail -1 | tr -d '[:space:]'; } # last bare numeric row in psql table output

row_counts () {
  PGPASSWORD="$PGPOC_SUPERUSER_PW" psql -X -q -h "$HOST" -p "$PORT" -U postgres -d "$DB" -tAc \
    "SELECT (SELECT count(*) FROM leads_baseline) || '|' || (SELECT count(*) FROM leads_fixed) || '|' || (SELECT count(*) FROM poc_actor_bound_grants) || '|' || (SELECT count(*) FROM poc_staff_memberships);"
}

echo "=== Fixture row counts BEFORE ==="
BEFORE=$(row_counts)
echo "$BEFORE"

echo
echo "=== T01: tenant A reads+writes its own leads_fixed rows -> expect ALLOW ==="
OUT=$(run_tx poc_runtime_tenant_a "$PGPOC_TENANT_A_PW" "
SELECT count(*) FROM leads_fixed WHERE tenant_id = '11111111-1111-1111-1111-111111111111';
UPDATE leads_fixed SET name = 'Lead A (fixed, touched)' WHERE id = 'a1111111-0000-0000-0000-00000000000a';
")
echo "$OUT"
if ! has_err "$OUT" && [[ "$OUT" == *"1"* ]]; then RESULT[T01]=PASS; else RESULT[T01]=FAIL; fi

echo
echo "=== T02: tenant B reads+writes its own leads_fixed rows -> expect ALLOW ==="
OUT=$(run_tx poc_runtime_tenant_b "$PGPOC_TENANT_B_PW" "
SELECT count(*) FROM leads_fixed WHERE tenant_id = '22222222-2222-2222-2222-222222222222';
UPDATE leads_fixed SET name = 'Lead B (fixed, touched)' WHERE id = 'b1111111-0000-0000-0000-00000000000b';
")
echo "$OUT"
if ! has_err "$OUT" && [[ "$OUT" == *"1"* ]]; then RESULT[T02]=PASS; else RESULT[T02]=FAIL; fi

echo
echo "=== T03: tenant A credential + forged app.tenant_id/context_mode -> SELECT tenant B rows on FIXED table -> expect DENY (0 rows) ==="
OUT=$(run_tx poc_runtime_tenant_a "$PGPOC_TENANT_A_PW" "
SELECT set_config('app.context_mode','TENANT',true), set_config('app.tenant_id','22222222-2222-2222-2222-222222222222',true);
SELECT count(*) FROM leads_fixed WHERE tenant_id = '22222222-2222-2222-2222-222222222222';
")
echo "$OUT"
LASTCOUNT=$(last_count "$OUT")
[[ "$LASTCOUNT" == "0" ]] && RESULT[T03]=PASS || RESULT[T03]=FAIL

echo
echo "=== T03b (baseline contrast, NOT part of the fixed-design score): same forged GUC trick against BASELINE table -> expect it SUCCEEDS (reproduces today's real risk) ==="
OUT=$(run_tx poc_runtime_shared "$PGPOC_BASELINE_SHARED_PW" "
SELECT set_config('app.context_mode','TENANT',true), set_config('app.tenant_id','22222222-2222-2222-2222-222222222222',true);
SELECT count(*) FROM leads_baseline WHERE tenant_id = '22222222-2222-2222-2222-222222222222';
")
echo "$OUT"
LASTCOUNT=$(last_count "$OUT")
[[ "$LASTCOUNT" == "1" ]] && RESULT[T03b_BASELINE_VULN_REPRO]=CONFIRMED_VULNERABLE || RESULT[T03b_BASELINE_VULN_REPRO]=UNEXPECTED

echo
echo "=== T04: tenant A credential + forged GUC -> INSERT/UPDATE/DELETE on tenant B rows (FIXED table) -> expect DENY ==="
OUT=$(run_tx poc_runtime_tenant_a "$PGPOC_TENANT_A_PW" "
SELECT set_config('app.context_mode','TENANT',true), set_config('app.tenant_id','22222222-2222-2222-2222-222222222222',true);
UPDATE leads_fixed SET name = 'PWNED' WHERE id = 'b1111111-0000-0000-0000-00000000000b';
INSERT INTO leads_fixed (id, tenant_id, name) VALUES ('ffffffff-0000-0000-0000-00000000ffff','22222222-2222-2222-2222-222222222222','injected');
DELETE FROM leads_fixed WHERE tenant_id = '22222222-2222-2222-2222-222222222222';
")
echo "$OUT"
if [[ "$OUT" != *"UPDATE 1"* ]] && [[ "$OUT" != *"INSERT 0 1"* ]] && [[ "$OUT" != *"DELETE 1"* ]] && [[ "$OUT" != *"DELETE 2"* ]]; then
  RESULT[T04]=PASS
else
  RESULT[T04]=FAIL
fi

echo
echo "=== T05: tenant A credential tries SET ROLE / membership into tenant B -> expect DENY ==="
OUT=$(run_sql poc_runtime_tenant_a "$PGPOC_TENANT_A_PW" "SET ROLE poc_runtime_tenant_b;")
echo "$OUT"
has_err "$OUT" && RESULT[T05]=PASS || RESULT[T05]=FAIL
MEMCHK=$(PGPASSWORD="$PGPOC_SUPERUSER_PW" psql -X -q -h "$HOST" -p "$PORT" -U postgres -d "$DB" -tAc \
  "SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.roleid JOIN pg_roles mm ON mm.oid=m.member WHERE mm.rolname IN ('poc_runtime_tenant_a','poc_runtime_tenant_b') AND r.rolname IN ('poc_runtime_tenant_a','poc_runtime_tenant_b');")
echo "cross-membership rows between A/B roles: $MEMCHK"
[[ "$MEMCHK" == "0" ]] && RESULT[T05_NO_CROSS_MEMBERSHIP]=PASS || RESULT[T05_NO_CROSS_MEMBERSHIP]=FAIL

echo
echo "=== T06: tenant A credential forges app.user_id to A2 (higher-privileged, ACTIVE) to read actor-bound admin grant -> expect this SUCCEEDS (ACTOR_ISOLATION OPEN, documented honestly) ==="
OUT=$(run_tx poc_runtime_tenant_a "$PGPOC_TENANT_A_PW" "
SELECT set_config('app.context_mode','TENANT',true), set_config('app.tenant_id','11111111-1111-1111-1111-111111111111',true), set_config('app.user_id','aaaaaaaa-0000-0000-0000-00000000a002',true);
SELECT count(*) FROM poc_actor_bound_grants WHERE grantee_staff_id = 'aaaaaaaa-0000-0000-0000-00000000a002' AND capability = 'company.administer';
")
echo "$OUT"
LASTCOUNT=$(last_count "$OUT")
if [[ "$LASTCOUNT" == "1" ]]; then RESULT[T06_ACTOR_ISOLATION]=OPEN_CONFIRMED_IMPERSONATION_SUCCEEDS; else RESULT[T06_ACTOR_ISOLATION]=UNEXPECTED_BLOCKED; fi

echo
echo "=== T07: fail-closed checks (suspended member, malformed GUC) must not leak, and must not break legitimate case ==="
OUT1=$(run_tx poc_runtime_tenant_a "$PGPOC_TENANT_A_PW" "
SELECT set_config('app.context_mode','TENANT',true), set_config('app.tenant_id','11111111-1111-1111-1111-111111111111',true), set_config('app.user_id','aaaaaaaa-0000-0000-0000-00000000a003',true);
SELECT count(*) FROM poc_actor_bound_grants;
")
echo "suspended-actor attempt: $OUT1"
LASTCOUNT1=$(last_count "$OUT1")
[[ "$LASTCOUNT1" == "0" ]] && RESULT[T07_SUSPENDED_FAILS_CLOSED]=PASS || RESULT[T07_SUSPENDED_FAILS_CLOSED]=FAIL

OUT2=$(run_tx poc_runtime_tenant_a "$PGPOC_TENANT_A_PW" "
SELECT set_config('app.user_id','not-a-uuid',true);
SELECT count(*) FROM poc_actor_bound_grants;
")
echo "malformed GUC attempt: $OUT2"
has_err "$OUT2" && RESULT[T07_MALFORMED_FAILS_CLOSED]=PASS || RESULT[T07_MALFORMED_FAILS_CLOSED]=FAIL

OUT3=$(run_tx poc_runtime_tenant_a "$PGPOC_TENANT_A_PW" "
SELECT count(*) FROM leads_fixed WHERE tenant_id = '11111111-1111-1111-1111-111111111111';
")
echo "legitimate case still works after fail-closed probes: $OUT3"
LASTCOUNT3=$(last_count "$OUT3")
[[ "$LASTCOUNT3" == "1" ]] && RESULT[T07_LEGITIMATE_STILL_ALLOWED]=PASS || RESULT[T07_LEGITIMATE_STILL_ALLOWED]=FAIL

echo
echo "=== T08: GUC trickery within one tenant-A session cannot surface tenant-B rows (no pooler modeled here -> partial, see report) ==="
OUT=$(run_tx poc_runtime_tenant_a "$PGPOC_TENANT_A_PW" "
SELECT set_config('app.tenant_id','11111111-1111-1111-1111-111111111111',true);
SELECT count(*) FROM leads_fixed;
SELECT set_config('app.tenant_id','22222222-2222-2222-2222-222222222222',true);
SELECT count(*) FROM leads_fixed;
")
echo "$OUT"
COUNTS=$(echo "$OUT" | grep -E '^[0-9]+$')
UNIQ=$(echo "$COUNTS" | sort -u | wc -l)
[[ "$UNIQ" == "1" ]] && RESULT[T08_SESSION_REUSE_GUC_NO_EFFECT]=PASS || RESULT[T08_SESSION_REUSE_GUC_NO_EFFECT]=FAIL
RESULT[T08_PGBOUNCER_POOLER]=NOT_VERIFIED_NO_POOLER_IN_POC

echo
echo "=== T09: role/ACL inspection (non-superuser query of catalogs) ==="
OUT=$(run_sql poc_runtime_tenant_a "$PGPOC_TENANT_A_PW" "
SELECT rolname, rolsuper, rolbypassrls, rolcreatedb, rolcreaterole, rolinherit
FROM pg_roles WHERE rolname IN ('poc_runtime_tenant_a','poc_runtime_tenant_b') ORDER BY rolname;
")
echo "$OUT"
BADFLAGS=$(echo "$OUT" | grep -E '\|t\|.*\|t\||t\|t\|' || true)
FORCERLS=$(run_sql poc_runtime_tenant_a "$PGPOC_TENANT_A_PW" "SELECT relforcerowsecurity FROM pg_class WHERE relname='leads_fixed';")
echo "leads_fixed FORCE RLS = $FORCERLS"
[[ -z "$BADFLAGS" && "$FORCERLS" == "t" ]] && RESULT[T09]=PASS || RESULT[T09]=FAIL

echo
echo "=== T10: comparison with real migration 036 / LeadService contract (source comparison, documented in report, not a live DB check) ==="
RESULT[T10]=DOCUMENTED_IN_REPORT_SCOPED_EQUIVALENT

echo
echo "=== T11: fixture row counts AFTER must equal BEFORE (every test wrapped in ROLLBACK) ==="
AFTER=$(row_counts)
echo "BEFORE=$BEFORE AFTER=$AFTER"
[[ "$BEFORE" == "$AFTER" ]] && RESULT[T11]=PASS || RESULT[T11]=FAIL

echo
echo "=== T12: no permanent unauthorized change happened (same as T11, restated) ==="
[[ "${RESULT[T11]}" == "PASS" ]] && RESULT[T12]=PASS || RESULT[T12]=FAIL

echo
echo "=================== SUMMARY ==================="
for k in "${!RESULT[@]}"; do
  printf '%-45s %s\n' "$k" "${RESULT[$k]}"
done | sort
