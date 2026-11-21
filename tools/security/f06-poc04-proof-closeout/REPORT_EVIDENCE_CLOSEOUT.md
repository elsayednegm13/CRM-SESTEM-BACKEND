# REPORT_EVIDENCE_CLOSEOUT.md — SECURITY-POC04-PROOF-CLOSEOUT-01

## 1. Sandbox identity

| Field | Value |
|---|---|
| Container name | `daleel-f06-poc04-closeout-znnlfh-pg` |
| Container ID (full) | `3e93adbf24ff939960327970ef80e6e98ee804e4bc437922eac451b612c49ac1` |
| Network | `daleel-f06-poc04-closeout-znnlfh-net` (`5e28571800bc073f88582afc7b1a0488f83a2c6a580e71bcd9b48b61f1b0eee9`), `Internal=true` |
| Volume | `daleel_f06_poc04_closeout_znnlfh_pg_data` |
| Database / OID | `daleel_f06_poc04_closeout_znnlfh_synthetic` / `16384` |
| `system_identifier` | `7700574292682092582` (distinct from POC01 `7700445040430698534`, POC02 `7700478534754992166`, POC03 `7700516237007110183`, POC04 `7700553360591278118`, G2 `7700288866362540071`) |
| Image | `postgres:16` (16.15), local, no pull |
| Published port | **NONE** — `docker ps` shows `5432/tcp` with no host mapping |
| Resource limits | `--memory=384m` (402653184 bytes), `--cpus=1` (1000000000 nanocpus) |
| Label | `com.daleel.purpose=f06-poc04-closeout` |
| Egress | measured BLOCKED: `bash -c 'exec 3<>/dev/tcp/1.1.1.1/443'` → "Network is unreachable"; `getent hosts google.com` → `rc=2` (resolution fails) |
| HBA | all 5 effective rules `scram-sha-256`; `0` trust rules (verified before every run and restored to `0` after every mutation test) |

## 2. W0 — before/after

5 Git HEADs identical before and after this task (ROOT `c2ee5a3a3e…`, API
`e8cee07c2c…`, WEB `6fb01b8838…`, ADMIN `9fa43befad…`, SUPER `a802e44b8a…`);
`git status --porcelain` identical before/after in all 5 repos: ROOT shows
exactly the 3 pre-existing unstaged doc edits + `.codex-remote-attachments/`
untracked, API shows only `?? tools/`, WEB/ADMIN/SUPER clean. Staged=0
everywhere, both before and after. POC01/POC02/POC03/POC04's 7-file
directories were read-only for this task; their SHA-256 after this task are
byte-identical to their values at the start of this task (see §3).

## 3. Original-hash preservation

```
aa03d1ba2907ffdf92e8408c10a9dc67dd1a89de5119f3d122e4e640e97e41b1  001_schema_roles.sql   (POC04, read-only)
a0619f68b3b34a834e0013b50da698f4cf597c609c414c9f86875eb15b76866c  002_fixtures.sql       (POC04, read-only)
20d5cf2bec8ed8ac501d2ecf6ebbcde3ca19be32ccf8c788cb10a68a0db20065  003_comparison.sql     (POC04, read-only)
2997733f9db1eb1c2e0868b8b0acdae6a08545fdb8ad9a0ce63c6bbd8abb39fc  run_tests.sh           (POC04, read-only)
6d0f4eb748f7dcad03707d3c19ce87ab70f6bbbacce3c8b1ed45e8edc857d33f  README.md              (POC04, read-only)
2953ee06765c8312c91655a6f94f32d39e0d74ab73811d82bed631de698eaec5  README_REVIEW.md       (POC04, read-only)
70763792dca1ce30be279f4ff035dfa30a8408402c2a72ad0f331a3a8195dcaf  REPORT_EVIDENCE.md     (POC04, read-only)
```
All 7 verified identical immediately before copying (W0) and again
immediately before writing this report (post-check) — no drift. POC01,
POC02, POC03 were never opened for write in this task.

## 4. This directory's files and final SHA-256

```
aa03d1ba2907ffdf92e8408c10a9dc67dd1a89de5119f3d122e4e640e97e41b1  001_schema_roles.sql   (unmodified copy)
a0619f68b3b34a834e0013b50da698f4cf597c609c414c9f86875eb15b76866c  002_fixtures.sql       (unmodified copy)
579259a851c8763b2da0038434bfc3805f8d8017e2badff47ff302bf0d7cf20b  003_comparison.sql     (PATCHED — F3)
d9562f927289b97f8580e30604fc707f94b30ce5aac2f03fde4d05f3a9bd5879  run_tests.sh           (PATCHED — F5, F6a, F6b, F6c, H03)
6d0f4eb748f7dcad03707d3c19ce87ab70f6bbbacce3c8b1ed45e8edc857d33f  README.md              (unmodified copy)
2953ee06765c8312c91655a6f94f32d39e0d74ab73811d82bed631de698eaec5  README_REVIEW.md       (unmodified copy)
70763792dca1ce30be279f4ff035dfa30a8408402c2a72ad0f331a3a8195dcaf  REPORT_EVIDENCE.md     (unmodified copy)
53692cd0318f9656b375aa7a4f4e8f5f525965f2b40f1fdf0b8dd677801c9322  DIFF_FROM_POC04.md     (new)
7c1ce66812b908642962d2f262dc4b04350c0351fe8a87f370419d8bcf65aa01  README_CLOSEOUT.md     (new)
```
(This file's own hash is not meaningful to record inside itself.)

## 5. F3/F5/F6a/F6b/F6c/H03 — source finding → patch → negative proof → status

| # | Source finding (Codex) | Patch | Negative proof observed | Status |
|---|---|---|---|---|
| **F3** | Component 01 concatenates `code`,`name` with a bare comma: `code='x,y',name='z'` and `code='x',name='y,z'` serialize identically | `fh_fingerprint()` rebuilt on `jsonb_build_array(tag, cols...)::text` per component (new `fh_acl_list()` helper folds ACL lists the same way) | **F3a** inside the real harness: inserted A=(`code='x,y'`,`name='z'`) and B=(`code='x'`,`name='y,z'`), same id/tenant/owner/timestamp, each in its own `BEGIN;...;ROLLBACK`. Old-style inline text for both was byte-identical; `fh_fingerprint()` for A ≠ B (64-hex each). **F3b**: fingerprint after both rollbacks == pre-probe baseline. **Mutant**: redeployed component 01 with the OLD concatenation (keeping 02-05+18 only, for isolation) → F3a's own assertion correctly flagged `fp_A==fp_B` → `ASSERTION_FAIL`, `OVERALL=FAIL`. Fixed function redeployed from the captured `pg_get_functiondef()`; fingerprint confirmed back to `8e695795…` baseline before any further run. | **CLOSED_IN_POC** |
| **F5** | AUTH gate proved only "no effective rule is `trust`"; a matching `md5` rule would pass every password-behavior check too, so the gate could not actually tell `scram-sha-256` from `md5` | `auth_gate()` now (a) calls `pg_reload_conf()` and checks `pg_conf_load_time()` moved/responded before trusting `pg_hba_file_rules`, then (b) resolves the REAL first-matching rule (by `line_number`, the true precedence order) for `postgres`+ all 7 matrix logins via `hba_effective_method()` and requires it to be EXACTLY `scram-sha-256` | Live mutation: rewrote `pg_hba.conf` so the rule matching our actual test path (`127.0.0.1/32`, `0.0.0.0/0`) was `md5` (kept `::1`/replication on scram as a control), `pg_reload_conf()`, confirmed via `pg_hba_file_rules` that `md5` was now the effective method for that path, then ran the full harness: **`exit 70`, zero scenarios recorded**, `AUTH_GATE_FAIL: effective HBA method for <role> is 'md5', not scram-sha-256` for all 8 identities. Restored the original all-scram `pg_hba.conf`, reloaded, confirmed `0` non-scram rules and `0` trust rules before resuming. | **CLOSED_IN_POC** |
| **F6a** | H06a's recorded claim ("resolver yields nothing") was inaccurate — the scenario never calls a resolver; it queries `actor_identity_map` directly as `postgres` | Rewrote H06a to claim only what it demonstrates: mid-transaction the mutation IS visible (`SUSPENDED`), after `ROLLBACK` it is `ACTIVE` again, and the whole-DB fingerprint is identical before/after. No resolver or cross-connection claim is made. | Observed directly in runs 1-3 (and the two debugging runs before them): `mid=SUSPENDED after=ACTIVE fp_eq=1` every time. | **CLOSED_IN_POC** (accuracy fix; no adversarial mutant was separately run for this one since it is a claim-wording fix, not a detection-bypass fix) |
| **F6b** | The marker was `touch`ed with its exit code discarded, then `fh_a5` was suspended unconditionally — a silently-failed marker write would leave `fh_a5` suspended with no durable recovery record | Marker is now written WITH identifying content (`role_name=fh_a5`, pid, timestamp) and verified non-empty + content-matching BEFORE the `UPDATE ... SUSPENDED` is ever issued; a failed/unverifiable marker aborts with `HARNESS_ERROR` and the UPDATE is never sent | Negative control: pre-created a directory AT the exact marker path (so the write-redirect fails), set `WORKDIR` to that location, ran the full harness. Result: `H06b HARNESS_ERROR ... <marker precondition failed, fh_a5 left ACTIVE, UPDATE never issued> write_rc=1 content_ok=0`. Independently queried `actor_status` for `fh_a5` immediately after: **`ACTIVE`** (never touched). `HARNESS_ERRORS=1`, `OVERALL=FAIL`. | **CLOSED_IN_POC** |
| **F6c** | `sleep 3; kill -9` with no verification the UPDATE had executed or that the killed PID was genuinely inside an open transaction | Child now emits `H06C_ACK:<pg_backend_pid()>:<status>` right after the UPDATE+SELECT; the script polls the child's OWN stdout for this ACK (never a blind sleep), then independently confirms via `pg_stat_activity` that exactly that backend is alive and running `pg_sleep` (i.e. inside the open transaction) BEFORE any signal; only the spawned psql CLIENT pid is ever signalled | Negative control: ran a mutant copy of the script where the UPDATE statement referenced a nonexistent column (`actor_status_f6c_negative_control_broken`), so the transaction aborts before the ACK statement ever runs. Result: `H06c ASSERTION_FAIL ... <no ACK within 3s> UPDATE never confirmed before any kill was sent; refusing to call this a pass`. `fh_a5` confirmed `ACTIVE` throughout (the broken UPDATE never committed, and no real backend was ever killed). | **CLOSED_IN_POC** |
| **H03** | Nothing enforced that `H03` must stay exactly `EXPECTED_FINDING`; a mutation turning it into `PASS` (or duplicating/moving the finding elsewhere) could reach `OVERALL=PASS_SCOPED` undetected | Added a `FINDING_CONTRACT` check, independent of `PASS_N`/`FAIL_N`/`HARNESS_N`: requires `H03`'s own recorded verdict == `EXPECTED_FINDING`, `FINDING_N==1`, and the only id ever recording `EXPECTED_FINDING` is `H03`; folded into `MANIFEST_OK` so `OVERALL=PASS_SCOPED` is unreachable if it fails | Mutant copy of the script with `H03`'s `record` call changed to `record H03 PASS ...` (manifest count and every other scenario left untouched — `76/76`, `MANIFEST_COMPLETE=PASS`). Result: `FINDING_CONTRACT=FAIL (H03 verdict is 'PASS', not EXPECTED_FINDING)`, `OVERALL=FAIL`. | **CLOSED_IN_POC** |

F1, F2, F4 were reviewed and left unmodified — no functional defect was
demonstrated in them within this task's four-item scope (F3/F5/F6/H03).

## 6. Three final runs after the last script edit

No edit was made to `003_comparison.sql` or `run_tests.sh` after the run
below labelled "Run 1" (the mutant/negative-control copies used for §5 are
separate files in `/tmp` inside the sandbox and on the host, never the
official copies in this directory; the F3 mutant was applied by
`CREATE OR REPLACE FUNCTION` directly in the live database and reverted
immediately afterward from a captured `pg_get_functiondef()` dump, with the
fingerprint checked back to baseline before Run 1 began).

| Run | Exit | EXPECTED/RECORDED | PASS | ASSERTION_FAIL | HARNESS_ERRORS | EXPECTED_FINDINGS | MANIFEST_COMPLETE | FINDING_CONTRACT | FP before | FP after | OVERALL |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 0 | 76/76 | 75 | 0 | 0 | 1 | PASS | PASS | `8e69579551fcb199739f597de30e718e74400850ee06237494dbc2d9be0acaa4` | same | PASS_SCOPED |
| 2 | 0 | 76/76 | 75 | 0 | 0 | 1 | PASS | PASS | `8e69579551fcb199739f597de30e718e74400850ee06237494dbc2d9be0acaa4` | same | PASS_SCOPED |
| 3 | 0 | 76/76 | 75 | 0 | 0 | 1 | PASS | PASS | `8e69579551fcb199739f597de30e718e74400850ee06237494dbc2d9be0acaa4` | same | PASS_SCOPED |

All three runs: identical `(id, verdict, expected)` tuples for all 76
scenarios (not claimed byte-identical stdout, since evidence text such as
`H06c`'s `reaped_after=` seconds and `pg_backend_pid()` values legitimately
vary run to run). `H06c`'s backend-reap time was 31s, 31s, 31s across the
three runs — bounded by, and consistent with, `pg_sleep(30)` never polling
the client socket (see §7).

Two earlier runs on this same sandbox, made WHILE fixing the harness itself
(before "Run 1" above), are not hidden: the first run surfaced a real bug —
`record()`'s new H03-tracking line made the function return 1 for every
non-H03 id, which doubled every `F1x`/`F2x` scenario via the
`cond && record PASS || record ASSERTION_FAIL` pattern used throughout the
script (`RECORDED=83` against `EXPECTED=76`, 7 duplicated ids,
`MANIFEST_COMPLETE=FAIL`). The second run, after adding `return 0` to
`record()`, fixed the duplication but then an under-provisioned `H06c` wait
(`sleep 1` after `kill -9`) produced `H06c ASSERTION_FAIL` with `gone=1`
(backend not yet reaped). Root-caused (see §7) and fixed by making the
backend-reap check informational rather than a pass/fail gate. Both fixes
are in the script shipped in this directory; no run after that second fix
showed any `ASSERTION_FAIL`.

## 7. H06c backend-reap timing — why 30s, and why it is not weakened

`SELECT pg_sleep(30);` inside the open transaction waits on a latch/timeout
only; it does not add the client socket to its wait set, so PostgreSQL does
not notice a killed/closed client connection until the sleeping statement
returns and the backend next tries to write to that socket (at which point
it gets a broken pipe and aborts). This was confirmed experimentally on this
exact sandbox: a dedicated probe killed the psql client 1s after the ACK and
polled `pg_stat_activity` every second — the backend row did not disappear
until **t=30s**. This is a timing fact about `pg_sleep()`, not a safety gap:
`actor_status` and the whole-DB fingerprint are read through a SEPARATE
connection under Read Committed, so they reflect the correct, fully-restored
state (the UPDATE was never committed) the instant another session queries
them — independent of whether the killed backend has finished exiting.

## 8. H03/S2 and product-contract facts (read-only, unchanged from POC04)

`leads_actor` here has 6 columns and a POC-only `UNIQUE (tenant_id, code)`;
the real `leads` table (`2026_10_23_000036_create_leads.php`) has 18 columns
and **no UNIQUE constraint at all** (3 non-unique indexes only), so H03's
intra-tenant existence oracle is a property of this POC's own schema choice,
not a demonstrated product defect — it remains `OPEN` pending an owner
decision on any future unique business key. `LeadService::assignLead()`
permits authorised re-assignment for `ALL_TENANT` holders and refuses it for
`ASSIGNED`/`SELF`; this POC's blanket ownership immutability trigger must
not be read as a product requirement.

## 9. Secrets handling

8 one-time random alphanumeric passwords (24 chars each) were generated
locally with `umask 077`, supplied to `001_schema_roles.sql` via a psql
`-f` variable file (never via `-c`, never via shell history), and never
echoed to stdout/stderr/log/report. After the final run, all plaintext
copies of the passwords (the host-side variable file, the derived
host-side env-sourcing file, and the container-side copy) were overwritten
and deleted. The sandbox's roles and their SCRAM-hashed credentials remain
live in the database for the owner's/independent-reviewer's convenience, but
this task retains no readable copy of the plaintext values. No evidence log
under `/tmp/fh_work` inside the sandbox contains a password (checked by
grep for `PASSWORD` across every captured file).

## 10. Resource state at end of task

`daleel-f06-poc04-closeout-znnlfh-pg` is left RUNNING (no stop/rm/prune),
`--internal` network and dedicated volume intact, evidence under
`/tmp/fh_work` inside the container intact, no published port. POC01, POC02
(exited), POC03, POC04, G2, acceptance, and scratch were not started,
stopped, or otherwise touched by this task. No `docker prune`/`rm`/`volume
rm`/`network rm` was executed against anything.
