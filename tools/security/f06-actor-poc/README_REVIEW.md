# Internal adversarial review — POC01 harness, and what POC02 changed

**Label this honestly: this is an _internal_ review. The same tool that wrote
POC01 wrote POC02 and this file. It is not an independent audit.** An
independent Codex review is recommended once these artifacts are in the
owner's hands; its absence did not block writing POC02.

## Part 1 — POC01 (`../f06-poc/run_tests.sh`), static review

POC01's security conclusions held up, but its harness had defects that could
have produced false PASS verdicts. Both of the following are documented
failures that actually occurred during POC01 before correction:

1. **Wrong port from inside the container.** The script hard-coded
   `PORT=55441`, which is the *host* publish port. Executed inside the
   container, every connection was refused. All queries failed and no test
   actually ran.
2. **`tail -1 | tr -dc '0-9'` parsing.** Row counts were scraped from psql's
   aligned table output by taking the last line and stripping non-digits. The
   last line was not the value, so the comparison fell through to FAIL for
   correct results (T03, T07) — and, worse, the *success* checks in T01/T02
   asserted only `[[ "$OUT" == *"1"* ]]`, i.e. "contains the digit 1
   anywhere", which the string `127.0.0.1` inside a connection-error message
   satisfies. That is exactly how the first POC01 run printed `T01 PASS`
   while nothing had executed.

Further weaknesses found by reading POC01 now (not previously corrected
there, and left untouched because POC01 is out of scope for writing):

3. `ON_ERROR_STOP=0` — statements after a failure kept running, so a later
   statement's output could be read as the result of an earlier failed one.
4. **Exit codes discarded.** `run_sql`/`run_tx` returned text only; `$?` was
   never inspected. A connection failure and a legitimate empty result were
   distinguishable only by string matching.
5. **`2>&1` merged stderr into the asserted value**, so error prose competed
   with data in the same string.
6. `has_err()` matched the substring `error` case-insensitively — it would
   also fire on a data value containing "error", and it treats a *connection*
   error identically to a *permission* denial, which is precisely the
   false-positive the task warns about.
7. **T04 asserted only the absence of success tags.** An aborted transaction
   (`current transaction is aborted…`) also yields that absence, so the test
   could pass for the wrong reason.
8. **T05 accepted any error** as proof that `SET ROLE` was denied.
9. **T09 regex-matched a formatted catalog row** (`grep -E '\|t\|…'`) instead
   of asserting each boolean column.
10. **No deliberate harness-failure test** existed, so a silently broken
    harness would have reported green.

## Part 2 — what POC02's harness does instead

| POC01 weakness | POC02 measure |
|---|---|
| table-output parsing | `psql -X -q -tA` only; every assertion compares a **bare value** by exact string equality. `-q` was verified empirically to suppress command tags (`SET`/`BEGIN`/`ROLLBACK`/`CREATE FUNCTION`/`RESET`) before being relied on |
| GUC forging printed rows and polluted the asserted value | GUC forging uses `SET …` (no result rows) rather than `SELECT set_config(…)` |
| exit code ignored | `RC` captured for every call; stdout and stderr captured **separately** |
| connection failure could read as DENY | `is_connection_problem()` classifies conn/auth failures as `HARNESS`, never `PASS`; a non-zero `HARNESS_ERRORS` count forces `OVERALL=FAIL` |
| any error accepted as denial | `expect_sql_failure` requires the error text to contain a specific phrase (e.g. `permission denied to set role`, `must be owner`) |
| negative mutation proved only by absence | `expect_deny_mutation` runs `WITH u AS (UPDATE … RETURNING 1) SELECT count(*)` inside `BEGIN … ROLLBACK` and requires **either** a real RLS/ACL error **or** an exact `0` rows-affected, and records which of the two happened |
| no target guard | the script asserts `current_database()` **and** `system_identifier` before any test and exits `98` on mismatch |
| no self-failure test | AT16a bad port, AT16b nonexistent database, AT16c the identity guard itself — each must produce a non-zero exit, asserted |
| only negative catalog claims | AT07d/AT07e/AT14a–d make **positive** catalog assertions: `pg_has_role(...)=false`, zero `pg_auth_members` rows among `poc02%`, zero unsafe role attributes, `relforcerowsecurity=true`, `has_table_privilege` false on the anchor table, anchor owned by `poc02_owner` |

## Part 3 — POC02's own pre-fix failure, recorded

The first POC02 run (`run1.log`) reported **PASS=38 FAIL=22**. Cause: `psql
-tA` *without* `-q` echoes command tags, so `OUT` for e.g. AT04a was
`SET\nSET\nSET\n0` instead of `0`, and `AT17c` additionally failed because
`DISCARD ALL` cannot run inside the implicit transaction that a multi-statement
`-c` creates.

Two fixes, both in the harness only (no SQL/policy change):
- add `-q`, after empirically confirming it removes tags;
- add `q2()`/`expect_value2()` to send two statements as separate implicit
  transactions on one session, used by AT17c.

Note the failure mode: the strict assertions made a harness bug look like 22
test failures rather than silently passing. That is the intended direction of
error. Every security value in that first run was already correct — it was the
comparison, not the database behaviour, that was wrong.

A third, smaller observation worth recording: in the W0 shell checks, an
`echo "exit_no_password=$?"` after a pipeline reported the exit status of
`head`, not of `psql`. It had no effect on any test verdict (the harness never
uses pipelines for exit codes), but it is the same class of mistake as POC01's
defect 4 and is why `q()` assigns `RC=$?` immediately after a bare command
substitution.
