# REPORT_EVIDENCE_TARGETED_GATE.md — SECURITY-POC04-TARGETED-GATE-01

Scope: F5 and F6c ONLY. `REPORT_EVIDENCE_CLOSEOUT.md` (first delta) is
historical and predates the fixes below. Codex's incoming baseline for this
task: F3=PASS_SOURCE, F6a=PASS_SOURCE, F6b=PASS_SCOPED, H03=PASS_SOURCE,
F5=PARTIAL, F6c=PARTIAL — none of the first four were touched this task.

## 1. Sandbox identity (brand new — the prior closeout sandbox is sealed/read-only)

| Field | Value |
|---|---|
| Container name | `daleel-f06-poc04-gate-39jjf5-pg` |
| Container ID (full) | `dfa23755271f0e2ae60ad0c31d0052a7250769fd89cffb28d015cfbfbdca2a05` |
| Network | `daleel-f06-poc04-gate-39jjf5-net` (`b49965a9c8ebcb6611cf81b5f0964428209895ddb4c90657d4b9cc1f09f0a2ba`), `Internal=true` |
| Volume | `daleel_f06_poc04_gate_39jjf5_pg_data` |
| Database / OID | `daleel_f06_poc04_gate_39jjf5_synthetic` / `16384` |
| `system_identifier` | `7700588471912390695` (distinct from every prior sandbox: closeout `7700574292682092582`, POC04 `7700553360591278118`, POC03 `7700516237007110183`, POC02 `7700478534754992166`, POC01 `7700445040430698534`, G2 `7700288866362540071`) |
| Image | `postgres:16` (16.15), local, no pull |
| Published port | **NONE** |
| Resource limits | `--memory=384m` (402653184 B), `--cpus=1` (1000000000 nanocpus) |
| Label | `com.daleel.purpose=f06-poc04-targeted-gate` |
| Egress | measured BLOCKED: `bash -c 'exec 3<>/dev/tcp/1.1.1.1/443'` → "Network is unreachable"; `getent hosts google.com` → `rc=2` |
| HBA | all 7 effective rules `scram-sha-256` at rest; `0` trust rules before and after every mutation test |

The OLD closeout sandbox (`daleel-f06-poc04-closeout-znnlfh-pg`) was **not
connected to or used** — its credentials were deliberately wiped at the end
of the first delta (confirmed sealed: a no-password connection attempt
during this task's W0 returned `fe_sendauth: no password supplied`, as
expected, and nothing further was attempted against it).

## 2. W0 — Git before/after

5 Git HEADs identical before and after (ROOT `c2ee5a3a3e…`, API
`e8cee07c2c…`, WEB `6fb01b8838…`, ADMIN `9fa43befad…`, SUPER `a802e44b8a…`).
`git status --porcelain` identical before/after: ROOT shows exactly the 3
pre-existing unstaged doc edits (`docs/EVIDENCE-REGISTER.md`,
`docs/HANDOFF-CURRENT.md`, `docs/WORK-LEDGER.md`) + `.codex-remote-attachments/`
untracked, API shows only `?? tools/`, WEB/ADMIN/SUPER clean, staged=0
everywhere. No concurrent work detected. The three ROOT docs were not
opened for write this task.

## 3. Delta — files and SHA-256

```
579259a851c8763b2da0038434bfc3805f8d8017e2badff47ff302bf0d7cf20b  003_comparison.sql     (UNCHANGED — identical to the first delta's hash; not touched)
f31f3282409d4de66a09f453f47934dc4a616b860496e97471477156d1d17805  run_tests.sh           (PATCHED again — F5, F6c only)
```
`001_schema_roles.sql`, `002_fixtures.sql`, `README.md`, `README_REVIEW.md`,
`REPORT_EVIDENCE.md` remain the unmodified copies verified in the first
delta; re-verified byte-identical again before this task started. No
migration, no Laravel file, no `config/database.php`, no `LeadService.php`
was read for write, let alone changed.

## 4. F5 — effective-method matcher: real network membership

**The deceptive scenario reproduced (F5-NEG-MASK, mandatory):** HBA rewritten,
in this brand-new sandbox only, to:
```
2  host all all 0.0.0.0/32   scram-sha-256   (netmask 255.255.255.255 — does NOT match 127.0.0.1)
3  host all all 127.0.0.1/32 md5             (netmask 255.255.255.255 — the REAL match)
4  host all all ::1/128      scram-sha-256
5  host all all 0.0.0.0/0    md5             (netmask 0.0.0.0 — catch-all, also md5)
```
`pg_reload_conf()` returned `t`; `pg_hba_file_rules.error IS NULL` for all
rows (clean parse). Running the full harness against this HBA:
```
exit 70
AUTH_GATE_FAIL: effective HBA method for postgres is 'md5', not scram-sha-256
AUTH_GATE_FAIL: effective HBA method for fh_a1 is 'md5', not scram-sha-256
... (all 8 identities)
AUTH_GATE=FAIL — refusing to run any security or mutation scenario
```
Zero `A`/`B`/`C`/`D`/`H` scenarios appear in the output (none were run). The
OLD matcher (address-literal, no netmask) would have evaluated row 2
(`address='0.0.0.0'`) as a match on its naive literal check and reported
`scram-sha-256` — this is the exact false-PASS Codex identified, and it is
now closed. HBA was restored to the original all-scram file immediately
after, reloaded, and reverified at `0` non-scram rules before resuming.

**F5b (synthetic unit check, no file mutation, in every normal run):**
```
F5b PASS "0.0.0.0/32 no-match, 0.0.0.0/0 match" act=narrow=f wide=t
```
Directly exercises the membership predicate `hba_addr_matches_127()`:
`(address='0.0.0.0', netmask='255.255.255.255')` → `f` (no match),
`(address='0.0.0.0', netmask='0.0.0.0')` → `t` (matches, correctly — this IS
a real 0.0.0.0/0 catch-all). Verified independently via raw SQL before
wiring into the harness:
```sql
SELECT (family('127.0.0.1'::inet)=family(inet '127.0.0.1')) AND
       ((inet '127.0.0.1' & '255.255.255.255'::inet) = ('127.0.0.1'::inet & '255.255.255.255'::inet));
-- t
SELECT (family('0.0.0.0'::inet)=family(inet '127.0.0.1')) AND
       ((inet '127.0.0.1' & '255.255.255.255'::inet) = ('0.0.0.0'::inet & '255.255.255.255'::inet));
-- f
```

**AUTH09 (new):** all 7 matrix logins proven to connect via
`127.0.0.1:5432` (TCP), not a socket — `AUTH09 PASS "tcp 127.0.0.1:5432 x7
matrix logins" act=7/7`.

**Four claim layers, kept separate (no overclaiming):**
1. *File content*: `pg_hba_file_rules` with `error IS NULL` filtering — unchanged mechanism.
2. *Reload acceptance*: `pg_reload_conf()=t` + `pg_conf_load_time()` before/after differ or are both readable (AUTH07, unchanged from the first delta).
3. *Loaded/effective state*: inferred ONLY from fresh connections made AFTER reload behaving per the resolved policy (AUTH03/04/05/08/09 all run after AUTH07's reload) — this is **not** claimed as a direct read of the postmaster's in-memory HBA table, only as consistent behavioral evidence.
4. *On-wire protocol mechanism*: `F5_ON_WIRE_AUTH_METHOD = NOT_VERIFIED`. This harness has no packet capture and cannot distinguish an actual SCRAM exchange from an MD5 one at the wire level; `password_encryption=scram-sha-256` and a resolved HBA method of `scram-sha-256` are policy-level facts, not a protocol trace, and are never equated with one.

`HBA_LOADED_STATE` for this task: `VERIFIED_BY_FRESH_CONNECTION_BEHAVIOR` —
not `NOT_VERIFIED`, since AUTH03/04/05/08/09 all succeeded against fresh
post-reload connections consistent with the resolved policy in every normal
run, and the F5-NEG-MASK mutation test proved the SAME mechanism correctly
flips to FAIL when the policy is genuinely weaker.

## 5. F6c — real kill/wait verification

**Positive proof (every normal run, 3× in §7):** `H06c PASS` with
`kill_rc=0 wait_rc=137` recorded explicitly, e.g. run 1:
```
H06c PASS ... act=backend_pid=1836 kill_rc=0 wait_rc=137 reaped_after=30s status=ACTIVE
```
`137 = 128+SIGKILL(9)`, bash's documented exit status for a child terminated
by an uncaught signal — confirmed empirically (not assumed) across all runs
in this task, all on Linux containers.

**F6C-NEG-EARLY-EXIT (mandatory, reproduced without touching Laravel or any
product code):** `run_tests.sh`'s H06c scenario now reads
`pg_sleep(${H06C_SLEEP_SECONDS:-30})`, a test-only timing knob (default
unchanged at 30s). Scanning short values to land in the exact race window
Codex described ("child exits naturally in the gap AFTER the pre-kill check
and BEFORE the kill signal"):

| `H06C_SLEEP_SECONDS` | Result |
|---|---|
| 0 | `ASSERTION_FAIL` — "backend not confirmed active in pg_sleep" (child already gone before even the pre-kill check; too early for the targeted race) |
| 0.3 | `ASSERTION_FAIL` — **"child pid 8558 already gone before signal" / "kill -0 precheck failed rc=1"** — the pre-kill `state='active' AND query ILIKE '%pg_sleep%'` check passed, the child then exited naturally, and the NEW `kill -0` liveness precheck correctly caught it before any `kill -9` was attempted |
| 0.4 – 30 | `PASS` — child still alive at kill time, `kill_rc=0`, `wait_rc=137` |

At `H06C_SLEEP_SECONDS=0.3`: `fh_a5` was `ACTIVE` and the fingerprint was
unchanged throughout (the UPDATE in the short-lived transaction never
committed either way) — exactly as Codex required: the run correctly
reports `ASSERTION_FAIL`/`OVERALL=FAIL` **despite** `actor_status` and the
fingerprint both looking perfectly clean, because the kill/wait exit codes
themselves, not the downstream DB state, are what gate the verdict. No
Laravel code, no product file, and no other container was touched to
produce this; the knob lives only in this harness's own H06c scenario.

**Positive control — why a bare ROLLBACK before kill cannot reach PASS:**
if the child had exited naturally and `kill -0` had NOT been added, the old
code would call `kill -9` on a dead PID (`ESRCH`, discarded), call `wait` on
a dead PID (status likely `127` "no such process" under bash, also
discarded), and then check `actor_status`/fingerprint — both of which are
indistinguishable from a real SIGKILL outcome, because in BOTH cases the
transaction was simply rolled back (by SIGKILL in one case, by reaching
`ROLLBACK;` naturally in the other) and nothing was ever committed. This is
precisely why `kill_rc`/`wait_rc` — not DB state — must be the gate, and
why the F6C-NEG-EARLY-EXIT scan above is the only way to actually prove the
fix closes the gap rather than just reading the code.

## 6. Regression — F1/F2/F3/F4/F6a/F6b/H03 unaffected

Every normal run (§7) recorded all of F1a-d, F2a-c, F3a/F3b, F4a/F4b, F5a,
F5b, H06a, H06b, H03 with the exact same verdicts, expected/actual values,
and evidence text as the first delta's closing runs — no change in behavior
for anything outside F5/F6c. Manifest grew from 76 to 78 (`+AUTH09`, `+F5b`;
`AUTH01..AUTH09`, `F1a..H06c`), derived from the manifest string, never
hard-coded; `MISSING=[] DUPLICATED=[] UNDECLARED=[]` in every run.

## 7. Three final runs after the last script edit

No edit was made to `run_tests.sh` after the run labelled "Run 1" below (a
single syntax fix — a stray `ORDER BY line_number` on an already-aggregated
query, caught immediately by the very first run attempt, `42803` grouping
error — was applied BEFORE this Run 1; it is not hidden, see §8). The
F5-NEG-MASK and F6C-NEG-EARLY-EXIT negative controls used separate `WORKDIR`
values and/or a temporary HBA file, never touching the official script
between Run 1 and Run 3.

| Run | Exit | EXPECTED/RECORDED | PASS | ASSERTION_FAIL | HARNESS_ERRORS | EXPECTED_FINDINGS | FINDING_CONTRACT | FP before | FP after | OVERALL |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 0 | 78/78 | 77 | 0 | 0 | 1 | PASS | `8e69579551fcb199739f597de30e718e74400850ee06237494dbc2d9be0acaa4` | same | PASS_SCOPED |
| 2 | 0 | 78/78 | 77 | 0 | 0 | 1 | PASS | same | same | PASS_SCOPED |
| 3 | 0 | 78/78 | 77 | 0 | 0 | 1 | PASS | same | same | PASS_SCOPED |

`H06c`'s `kill_rc=0, wait_rc=137` in all three; `reaped_after` = 30s, 31s,
31s (bounded by the remaining `pg_sleep(30)`, as declared and measured in
the first delta — unchanged fact, re-confirmed here).

## 8. Intermediate failure disclosed, not hidden

The very first execution attempt in this sandbox (before "Run 1" above)
failed at the SQL level with:
```
ERROR: column "pg_hba_file_rules.line_number" must appear in the GROUP BY clause or be used in an aggregate function
```
Root cause: `hba_effective_method()`'s new row-collecting query had a
leftover `ORDER BY line_number;` AFTER the `string_agg(... ORDER BY
line_number)` aggregate — redundant and invalid once the query collapses to
one row. Fixed by removing the outer `ORDER BY`; verified against the raw
SQL directly (`§4`) before re-running the full harness, which then produced
Run 1 above with no further changes.

## 9. Delta/Impact

No product, RLS/ACL, migration, Laravel, or Git change. All effect confined
to a brand-new, `--internal`, no-published-port sandbox and to
`run_tests.sh` inside `f06-poc04-proof-closeout/`. `H06b`'s committed
revocation window, `H03`'s intra-tenant existence oracle (POC-only
construct; the real `leads` table has no UNIQUE constraint), and
`LARAVEL_WIRE_INTEGRATION`/credential provisioning/pooling/rotation remain
exactly as declared in the first delta — none of this task's changes touch
them. `VERIFIED_LIVE` facts in this report: all §4/§5 negative and positive
proofs, run directly in the new sandbox this task. `DOCUMENTED_PRIOR`:
everything attributed to the first delta's own report
(`REPORT_EVIDENCE_CLOSEOUT.md`) and to Codex's review findings as quoted in
the task prompt.

## 10. Resource state at end of task

`daleel-f06-poc04-gate-39jjf5-pg` left RUNNING (no stop/rm/prune), internal
network and volume intact, `/tmp/fh_work` evidence intact inside the
container, no published port. The prior closeout sandbox
(`daleel-f06-poc04-closeout-znnlfh-pg`) and all protected resources
(POC01-04, G2, acceptance, scratch) were not started, stopped, connected to,
or otherwise touched. No `docker prune`/`rm`/`volume rm`/`network rm` was
executed. All one-time test passwords (8 roles, 24-char random alphanumeric,
`umask 077`) were overwritten and deleted from both host and container
`/tmp` after the final run; the sandbox's own role credentials remain live
in its database for a reviewer's convenience, but no plaintext copy survives
this task. `grep -rl PASSWORD` over every file under `/tmp/fh_work` inside
the container returned nothing.
