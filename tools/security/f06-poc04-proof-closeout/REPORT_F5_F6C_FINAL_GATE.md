# REPORT_F5_F6C_FINAL_GATE.md — SECURITY-POC04-LAST-PROOF-CORRECTION-01

Scope: F5 and F6c ONLY, in `run_tests.sh` only. Incoming baseline: Codex =
PARTIAL_BLOCKED on this same directory; F3/F6a/F6b/H03 untouched and not
re-reviewed here (their code paths were not modified).

## 1. Sandbox identity (brand new — prior gate/closeout sandboxes untouched)

| Field | Value |
|---|---|
| Container name | `daleel-f06-poc04-lastfix-ug4u3s-pg` |
| Container ID (full) | `19c1f1255a50c1c3aa891126c46ae6f37d5e7b4ee89c2a44fc229ca659249d2e` |
| Network | `daleel-f06-poc04-lastfix-ug4u3s-net` (`30fc7fcb90e13e5219735cd1dd925cca890a6255b412b0930403426737a841ae`), `Internal=true` |
| Volume | `daleel_f06_poc04_lastfix_ug4u3s_pg_data` |
| Database / OID | `daleel_f06_poc04_lastfix_ug4u3s_synthetic` / `16384` |
| `system_identifier` | `7700627911063912486` (distinct from every registered prior sandbox) |
| Image | `postgres:16` (local, no pull) |
| Published port | **NONE** |
| Resources | `--memory=384m`, `--cpus=1` |
| Server `ssl` | `off` (no cert configured — our connection's `sslmode=disable` is both requested AND the only possibility here; confirmed independently via `pg_stat_ssl.ssl=false` for our own session — AUTH11) |
| HBA | all effective rules `scram-sha-256`; `0` trust at rest and after every restore |

`daleel-f06-poc04-gate-39jjf5-pg` and `daleel-f06-poc04-closeout-znnlfh-pg`
were never connected to, exec'd into, or modified this task.

## 2. W0 — Git before/after

5 HEADs identical before/after (ROOT `c2ee5a3a3e…`, API `e8cee07c2c…`, WEB
`6fb01b8838…`, ADMIN `9fa43befad…`, SUPER `a802e44b8a…`). `git status
--porcelain` identical before/after in all 5: ROOT = the same 3 unstaged doc
edits + `.codex-remote-attachments/` untracked; API = `?? tools/` only
(these untracked POC directories, including this one, remain a preservation
decision for the owner — no `git add`/`commit` performed); WEB/ADMIN/SUPER
clean; staged=0 everywhere.

## 3. Delta — files and SHA-256

```
579259a851c8763b2da0038434bfc3805f8d8017e2badff47ff302bf0d7cf20b  003_comparison.sql  (UNCHANGED — not opened for write)
befd0b8066569479351ad38c88272ba2b8af26fcd3a61055e6029f3954d7a2ba  run_tests.sh        (PATCHED — F5, F6c only, this task)
```
No other file in `f06-poc04-proof-closeout/` was modified. No POC01-04
original file, no migration, no Laravel/Next.js file, no
`config/database.php`, no `LeadService.php` was opened for write.

## 4. F5 — replication exclusion + hostssl/hostnossl + connection evidence

**Bug (Codex, VERIFIED_SOURCE):** `hba_effective_method()`'s row-selection
WHERE clause OR'd in `'replication' = ANY(database)`, so a rule scoped only
to physical replication connections was wrongly treated as covering our
ordinary `-d <synthetic_db>` connection. The `type` filter also included
`hostssl`, which matches only SSL-encrypted connections — never legitimately
the rule governing a connection we had not yet proven was non-SSL.

**Fix:**
- Removed the `'replication' = ANY(database)` disjunct outright — only
  `'all'` or the literal db name now counts as a database match.
- `type IN ('host','hostnossl','hostnogssenc')` — `hostssl`/`hostgssenc`
  excluded by construction (not merely unordered).
- `q()`/`fp_read()`/the H05 and H06c ad hoc connections all now pass
  `-d "dbname=$DB sslmode=disable gssencmode=disable"` (libpq conninfo-style
  dbname argument), and the script `unset`s `PGHOST`/`PGSSLMODE`/
  `PGGSSENCMODE`/etc. at startup so no inherited shell/env value can
  silently change which rule our connection actually hits.
- New **AUTH10**: `host(inet_client_addr())='127.0.0.1'` for our own test
  connection. New **AUTH11**: `pg_stat_ssl.ssl=false` for our own session's
  `pg_backend_pid()`. Both are evidence about OUR OWN connection's contract,
  never a claim about the on-wire protocol in general.

**F5-NEG-REPLICATION (mandatory, reproduced):**
```
2 host replication all 127.0.0.1/32 scram-sha-256   (replication-scoped — must NOT be treated as matching us)
3 host all         all 127.0.0.1/32 md5             (the REAL match for our plain DB connection)
```
`pg_reload_conf()=t`, no parse errors. Full harness run: `exit 70`,
`AUTH_GATE_FAIL: effective HBA method for <role> is 'md5', not scram-sha-256`
for all 8 identities, zero `A`/`B`/`C`/`D`/`H` scenarios. The OLD matcher
would have accepted row 2 (via the `replication` disjunct) and reported
`scram-sha-256`. HBA restored and reverified at `0` non-scram rows
immediately after.

**F5-NEG-SSL (mandatory, reproduced):**
```
2 hostssl   all all 127.0.0.1/32 scram-sha-256   (SSL-only — excluded)
3 hostnossl all all 127.0.0.1/32 md5             (the REAL match, non-SSL)
```
`pg_hba_file_rules` itself flagged row 2 with
`error = "hostssl record cannot match because SSL is disabled"` (this
server has no SSL cert configured) — our `WHERE error IS NULL` filter
already excludes it on that basis alone, and the `type` exclusion is
independent defense-in-depth for a server where SSL *is* configured. Full
harness run: `exit 70`, `md5` correctly identified for all 8 identities,
zero scenarios. Restored and reverified.

**Positive regression (every normal run, §7):** all 8 identities resolve to
`scram-sha-256` via the true first-matching rule; `AUTH03/04/05` (correct/
missing/wrong password) pass for all 7 matrix logins; `0` trust rules.

**Claim-layer separation, unchanged from the prior delta, re-confirmed:**
`HBA_FILE_PARSED` (pg_hba_file_rules, error IS NULL), `RELOAD_REQUESTED`
(pg_reload_conf()=t, AUTH07), `FRESH_CONNECTION_BEHAVIOR` (AUTH03/04/05/08/
09/10/11, all post-reload), `HBA_LOADED_STATE` = inferred from that
behavior only, never a direct read of postmaster memory,
`ON_WIRE_AUTH_METHOD = NOT_VERIFIED` — no packet capture exists in this
harness, and an `md5`-labelled HBA rule can still negotiate SCRAM if the
stored verifier is SCRAM-shaped; this report never conflates the two.

## 5. F6c — backend disappearance as a hard, required gate

**Bug (Codex, VERIFIED_SOURCE):** `kill_rc==0`/`wait_rc==137` were genuinely
proven, but backend *disappearance* from `pg_stat_activity` was polled only
informationally — PASS never depended on it. A backend that was still
sitting inside its not-yet-aborted transaction when the poll window closed
could still produce a clean `actor_status`/fingerprint readback (because
the UPDATE was never committed either way) and a false PASS.

**Fix:**
- Identity is now the composite `(pid, backend_start)`, captured from the
  ACK itself (`pg_backend_pid()` + a self-referential `backend_start` read),
  not pid alone — immune to PID reuse across the poll window.
- Pre-kill check requires `state='active' AND query ILIKE '%pg_sleep%'` for
  that exact composite.
- Post-kill backend disappearance, by the same composite, is now a **hard,
  required gate** (`H06C_DISAPPEAR_TIMEOUT_SECONDS`, default 40s) — timing
  out with the backend still present is `H06c ASSERTION_FAIL`,
  `SERVER_ROLLBACK=NOT_VERIFIED`, `OVERALL=FAIL`, regardless of any
  actor_status/fingerprint reading (which is not even attempted until
  disappearance is confirmed).
- Every stage is traced explicitly in the evidence string: `ACK_RECEIVED`,
  `BACKEND_IDENTIFIED`, `PREKILL_ACTIVE`, `KILL_RC`, `WAIT_RC`,
  `BACKEND_DISAPPEARED`, `POST_ABORT_READBACK`, `FP_EQUAL`.
- A new test-only knob, `H06C_TEST_DELAY_BEFORE_KILL_SECONDS` (default
  unset/inert), inserts a documented pause between the pre-kill check and
  the `kill -0` liveness precheck, purely to make the F6C-NEG-EARLY-EXIT
  regression deterministically reproducible rather than dependent on a
  sub-10ms OS-scheduling race.

**F6C-NEG-BACKEND-STILL-ALIVE (mandatory, reproduced):**
`H06C_SLEEP_SECONDS=60`, `H06C_DISAPPEAR_TIMEOUT_SECONDS=5`. Result:
```
H06c ASSERTION_FAIL trace:...,KILL_RC=0,WAIT_RC=137,BACKEND_DISAPPEARED=0(timeout=5s),SERVER_ROLLBACK=NOT_VERIFIED
act=backend pid=5173,backend_start=2026-10-25 15:33:04.760101+00 STILL PRESENT in pg_stat_activity after 5s
OVERALL=FAIL
```
`kill_rc=0`/`wait_rc=137` (the client WAS genuinely SIGKILLed), yet the
verdict is `ASSERTION_FAIL` because the real server backend — independently
confirmed present via `pg_stat_activity` by its exact `(pid,backend_start)`
— was still there when the bound expired. This is NOT a fabricated/mutated
guard failure: the backend was genuinely alive, confirmed by direct query,
not assumed. Cleanup: identity re-verified (`SELECT count(*) ... WHERE
pid=5173 AND backend_start='...'` → `1`) immediately before a deliberate,
separately-issued `pg_terminate_backend(5173)` (conditioned on that same
WHERE clause), confirmed gone (`count=0`) and `fh_a5`/fingerprint confirmed
unaffected (`ACTIVE`, baseline hash) — this cleanup action is NOT counted
as part of the (already-recorded) test verdict.

**F6C-NEG-EARLY-EXIT (mandatory regression, reproduced deterministically):**
`H06C_SLEEP_SECONDS=0.5`, `H06C_TEST_DELAY_BEFORE_KILL_SECONDS=1`. Result:
```
H06c ASSERTION_FAIL trace:ACK_RECEIVED=1,BACKEND_IDENTIFIED=1,PREKILL_ACTIVE=1,KILL_RC=<not_attempted>
act=<child pid 38182 already gone before signal> kill -0 precheck failed rc=1
OVERALL=FAIL
```
The pre-kill active/pg_sleep check passed (`PREKILL_ACTIVE=1`), the child
then exited naturally during the deliberate 1s pause, and `kill -0`
correctly caught its absence before any `kill -9` was attempted. `fh_a5`
confirmed `ACTIVE` throughout.

**Positive proof (every normal run, §7):** `kill_rc=0, wait_rc=137,
BACKEND_DISAPPEARED=1(~30-31s), POST_ABORT_READBACK` succeeds,
`FP_EQUAL=1`.

## 6. Regression — F1/F2/F3/F4/F6a/F6b/H03 unaffected

All of F1a-d, F2a-c, F3a/F3b, F4a/F4b, F5a, F5b, H03, H06a, H06b recorded
identical verdicts/evidence to the prior delta's closing runs in every run
this task. Manifest grew from 78 to 80 (`+AUTH10,+AUTH11`; no new F5/F6c
scenario IDs were added beyond the prior delta's F5a/F5b — the four new
negative controls this task are execution-phase, like F5-NEG-MASK before
them, not permanent manifest entries), derived from the manifest string,
never hard-coded. `MISSING=[] DUPLICATED=[] UNDECLARED=[]` every run.

## 7. Three final runs after the last script edit

The last edit to `run_tests.sh` was adding
`H06C_TEST_DELAY_BEFORE_KILL_SECONDS` (needed to make F6C-NEG-EARLY-EXIT
reproducible). No edit was made after that. The three runs below used the
unmodified, redeployed script with no env knobs (defaults only):

| Run | Exit | EXPECTED/RECORDED | PASS | ASSERTION_FAIL | HARNESS_ERRORS | EXPECTED_FINDINGS | FP before | FP after | `H06c` disappeared_after | OVERALL |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 0 | 80/80 | 79 | 0 | 0 | 1 | `8e69579551fcb199739f597de30e718e74400850ee06237494dbc2d9be0acaa4` | same | 31s | PASS_SCOPED |
| 2 | 0 | 80/80 | 79 | 0 | 0 | 1 | same | same | 31s | PASS_SCOPED |
| 3 | 0 | 80/80 | 79 | 0 | 0 | 1 | same | same | 30s | PASS_SCOPED |

All three: `H06c`'s full trace identical in shape
(`ACK_RECEIVED=1,BACKEND_IDENTIFIED=1,PREKILL_ACTIVE=1,KILL_RC=0,WAIT_RC=137,
BACKEND_DISAPPEARED=1(~30s),POST_ABORT_READBACK=0(ok),FP_EQUAL=1`), with
distinct per-run `pid`/`backend_start` values (as expected — new
connections each run).

## 8. Intermediate failure disclosed, not hidden

The first execution attempt after this task's edits failed:
```
AUTH_GATE_FAIL: inet_client_addr()='127.0.0.1/32', not 127.0.0.1
```
Root cause: `inet_client_addr()::text` renders as CIDR (`127.0.0.1/32`) for
this PostgreSQL version, not a bare address. Fixed by using
`host(inet_client_addr())`, which returns the bare address; verified
directly before re-running. The F6C-NEG-EARLY-EXIT regression also required
two rounds of timing exploration (a sub-10ms race window, then the explicit
`H06C_TEST_DELAY_BEFORE_KILL_SECONDS` knob) before it reproduced reliably —
documented in full in §5, not elided.

## 9. Delta/Impact (VERIFIED_LIVE vs VERIFIED_SOURCE vs DOCUMENTED_PRIOR vs STATIC_INFERENCE)

- **VERIFIED_LIVE** (run in this sandbox, this task): §4's F5-NEG-REPLICATION/
  F5-NEG-SSL and all positive AUTH checks; §5's F6C-NEG-BACKEND-STILL-ALIVE/
  F6C-NEG-EARLY-EXIT and all three positive final runs; §1's sandbox
  identity and egress/SSL facts; §2's Git state.
- **VERIFIED_SOURCE**: Codex's F5/F6c findings as quoted in the task prompt
  (this report does not re-derive them independently beyond reproducing the
  fix and the negative proofs).
- **DOCUMENTED_PRIOR**: everything attributed to the first and second deltas'
  own reports (`REPORT_EVIDENCE_CLOSEOUT.md`, `REPORT_EVIDENCE_TARGETED_GATE.md`)
  — F3/F6a/F6b/H03 behavior, H03's POC-only existence oracle, H06b's
  committed window, schema/ACL/RLS/Leads-contract facts.
- **STATIC_INFERENCE**: none relied upon for this report's verdict.

No product, RLS/ACL, migration, or Laravel change; impact = zero on
schema/ACL/RLS/contracts. `H03` stays `OPEN` (POC-only); `H06b`'s committed
window is unchanged and undefended by this task;
`LARAVEL_WIRE_INTEGRATION`/credential provisioning/pooling/revocation remain
not executed.

## 10. Resource state at end of task

`daleel-f06-poc04-lastfix-ug4u3s-pg` left RUNNING (no stop/rm/prune),
internal network and volume intact, `/tmp/fh_work` evidence intact, no
published port. `daleel-f06-poc04-gate-39jjf5-pg` and
`daleel-f06-poc04-closeout-znnlfh-pg` (and all protected resources: POC01-04,
G2, acceptance, scratch) were not started, stopped, connected to, or
otherwise touched. No `docker prune`/`rm`/`volume rm`/`network rm` executed.
8 one-time test passwords (24-char random alphanumeric, `umask 077`)
overwritten and deleted from host and container `/tmp` after the final run;
no plaintext copy survives. `grep -rl PASSWORD` over `/tmp/fh_work` inside
the container returned nothing. The one orphaned test backend from
F6C-NEG-BACKEND-STILL-ALIVE was deliberately, identity-verified, terminated
(§5) — no other backend/process outside this sandbox was touched.
