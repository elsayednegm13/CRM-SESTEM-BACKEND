# Diff from POC04 (f06-actor-poc-final-harden)

This directory is a literal copy of POC04 with patches confined to exactly
two files: `003_comparison.sql` and `run_tests.sh`. `001_schema_roles.sql`,
`002_fixtures.sql`, `README.md`, `README_REVIEW.md` and `REPORT_EVIDENCE.md`
are untouched copies (SHA-256 identical to the originals — see
`REPORT_EVIDENCE_CLOSEOUT.md`). The original POC04 directory itself was never
written to.

## 003_comparison.sql

- Added `fh_acl_list(aclitem[]) RETURNS jsonb`: folds an `aclexplode()` result
  into a sorted jsonb array of `[grantee, privilege]` pairs.
- Rewrote `fh_fingerprint()`: every component's "part" is now the `::text` of
  a `jsonb_build_array(tag, col1, col2, ...)` instead of bare `'||','||'`
  concatenation. This is the F3 fix (see §F3 below). No component's semantic
  coverage changed (still 01..17 + coverage marker); only the serialization
  changed.

## run_tests.sh

- `MANIFEST`: `AUTH01..AUTH06` → `AUTH01..AUTH08` (two new AUTH gate checks);
  added `F3a F3b` (two new negative-control scenarios). `76` total vs `72` in
  POC04 (`+2 AUTH, +2 F3`), count is still derived from the manifest string,
  never hard-coded.
- `record()`: tracks which id(s) produced `EXPECTED_FINDING`
  (`EXPECTED_FINDING_IDS`) and captures `H03`'s own verdict (`H03_VERDICT`);
  added an explicit `return 0` so the function's exit status never leaks into
  the `cond && record ... || record ...` call sites that depend on it.
- New `hba_effective_method()` helper + `AUTH07`/`AUTH08` inside `auth_gate()`:
  forces `pg_reload_conf()` and proves it took effect, then resolves the
  ACTUAL first-matching HBA rule (by `line_number`) for `postgres` and all 7
  matrix logins and requires it to be exactly `scram-sha-256` — not merely
  "not trust". This is the F5 fix.
- New F3 negative-control block (`F3a`/`F3b`) after the F2 controls: inserts
  two rows into `leads_actor` (same id, tenant, owner, timestamp; only
  `code`/`name` split differently) inside two separate `BEGIN;...;ROLLBACK`
  transactions, shows the OLD-style inline concatenation of the same fields
  is identical for both, and the deployed `fh_fingerprint()` is NOT; then
  confirms the fingerprint is back to the pre-probe baseline.
- `H06a`: replaced the "resolver yields nothing" scenario+claim with one that
  proves only what it can — mid-transaction visibility, full rollback,
  fingerprint invariance — and states explicitly that it makes no resolver or
  cross-connection claim. This is the F6a fix.
- `H06b`: the marker is now written with identifying content and verified
  on-disk (non-empty, contains `role_name=fh_a5`) BEFORE the `UPDATE ...
  SUSPENDED` is ever issued; a failed/unverifiable marker now aborts with
  `HARNESS_ERROR` and leaves `fh_a5` untouched, instead of suspending first
  and only touching the marker afterward. This is the F6b fix.
- `H06c`: replaced the blind `sleep 3; kill -9` with a self-identifying ACK
  (`H06C_ACK:<pg_backend_pid()>:<status>`) that the script polls for on the
  child's own stdout, then an independent `pg_stat_activity` check that the
  backend is alive and inside the open transaction (`pg_sleep`) BEFORE any
  signal is sent; only the spawned psql client PID is ever signalled. Backend
  reaping from `pg_stat_activity` is tracked and reported but NOT a pass/fail
  gate, since `pg_sleep()` does not poll the client socket and genuinely does
  not notice the closed connection until the sleep elapses (measured: ~30s –
  see `REPORT_EVIDENCE_CLOSEOUT.md`). This is the F6c fix.
- New `FINDING_CONTRACT` check before the final verdict: `OVERALL=PASS_SCOPED`
  is unreachable unless `H03`'s own recorded verdict is exactly
  `EXPECTED_FINDING`, `FINDING_N == 1`, and the only id that ever produced
  `EXPECTED_FINDING` is `H03`. This is the H03 fix.

## Not changed (this task's own scope: F3/F5/F6/H03)

F1 (SQLSTATE classification), F2 (fingerprint RC-capture contract) and F4
(effective PUBLIC EXECUTE via `acldefault`) are carried over verbatim — no
functional defect was found in them during this task, and the task's scope
explicitly excludes re-opening them without a demonstrated, tested need.

---

## SECURITY-POC04-TARGETED-GATE-01 — second delta (F5 + F6c only)

An independent Codex review of this directory returned F3=PASS_SOURCE,
F6a=PASS_SOURCE, F6b=PASS_SCOPED, H03=PASS_SOURCE, but **F5=PARTIAL** and
**F6c=PARTIAL**. This second delta touches `run_tests.sh` only — nothing
else in this directory changed (`003_comparison.sql` is byte-identical to
the hash recorded above: `579259a851c8763b2da0038434bfc3805f8d8017e2badff47ff302bf0d7cf20b`).

### F5 — real first-match network membership, not address-literal matching

Codex (VERIFIED_SOURCE): the prior `hba_effective_method()` treated
`address = '0.0.0.0'` as "matches everything", ignoring the separate
`netmask` column entirely. A rule `host all all 0.0.0.0/32 scram-sha-256`
(which matches ONLY the literal address `0.0.0.0`, never `127.0.0.1`) placed
before the real match `host all all 127.0.0.1/32 md5` would make the old
matcher wrongly report `scram-sha-256` as the effective method.

Fix:
- `hba_effective_method()` rewritten to walk every type/db/user-matching row
  in true `line_number` order and evaluate each one's REAL network
  membership of `127.0.0.1` via `(address & netmask) = (127.0.0.1 & netmask)`
  (new helper `hba_addr_matches_127()`), not string/CIDR-text comparison.
  `address='all'` always matches (checked first, no netmask needed).
  `address IN ('samehost','samenet')`, a null address/netmask, or any row
  the bitwise test cannot evaluate (e.g. family mismatch causing the query
  itself to error) now FAILS CLOSED immediately with an explicit
  `<FAIL_CLOSED:...>` marker instead of being silently skipped.
- `auth_gate()`: added **AUTH09** — every one of the 7 matrix logins (not
  only the `postgres` connection the gate itself happens to use) is proven
  to authenticate over the real TCP endpoint `127.0.0.1:<PORT>`, not a unix
  socket or an inherited `PGHOST`.
- New **F5b**: a synthetic, file-mutation-free unit check of the membership
  predicate itself — `(address='0.0.0.0', netmask='255.255.255.255')` must
  NOT match `127.0.0.1` while `(address='0.0.0.0', netmask='0.0.0.0')` (the
  real 0.0.0.0/0 catch-all) MUST match.
- Claim layers kept explicitly separate (no overclaiming): (1) file content
  via `pg_hba_file_rules`, (2) `pg_reload_conf()` acceptance +
  `pg_conf_load_time()` (AUTH07, unchanged), (3) the *loaded/effective*
  state is inferred only from fresh connections made AFTER reload actually
  behaving per policy — never claimed as a direct introspection of the
  postmaster's in-memory HBA table, (4) the on-wire SASL/MD5 protocol
  mechanism is explicitly **NOT_VERIFIED** — this harness has no
  packet-level capture and does not claim one.

### F6c — real `kill`/`wait` exit-status verification, not discarded

Codex (VERIFIED_SOURCE): `kill -9 "$H06C_PID" >/dev/null 2>&1` and
`wait "$H06C_PID" 2>/dev/null` both discarded their exit codes. If the child
finished naturally in the gap between the pre-kill `pg_stat_activity` check
and the `kill` call, `kill -9` on an already-reaped PID fails silently
(ESRCH), no signal is actually delivered, yet the old code still reached
`record H06c PASS` because the post-kill DB state (ordinary `ROLLBACK`)
looked identical to a real SIGKILL outcome — a false proof of SIGKILL.

Fix:
- Tightened the pre-kill backend check to `state = 'active'` (was
  `state <> 'idle'`) AND `query ILIKE '%pg_sleep%'`.
- New `kill -0 "$H06C_PID"` liveness precheck immediately before signalling;
  if the child is already gone, `record H06c ASSERTION_FAIL` with an
  explicit "already gone before signal" message — no kill is even attempted.
- `kill -9`'s own exit code (`H06C_KILL_RC`) and `wait`'s own exit status
  (`H06C_WAIT_RC`) are now both captured and REQUIRED: `kill_rc == 0` AND
  `wait_rc == 137` (128+SIGKILL under bash/Linux) are mandatory for PASS;
  any other value is `ASSERTION_FAIL` regardless of how clean
  `actor_status`/the fingerprint look afterward.
- `pg_sleep(30)` is now parameterized as `pg_sleep(${H06C_SLEEP_SECONDS:-30})`
  so the F6C-NEG-EARLY-EXIT negative control (below) can reproduce the exact
  race without touching Laravel or any product code — this is a test-only
  knob, default unchanged at 30s.

### Not changed in this second delta

F3, F6a, F6b, H03 — Codex's own review recorded these as
PASS_SOURCE/PASS_SCOPED; this task's scope is F5+F6c only, and no edit was
made to any code path specific to those four.
