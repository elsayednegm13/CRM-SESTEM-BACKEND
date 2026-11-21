# Review findings → patch → negative proof → status

Source of the findings: the owner-conveyed independent (Codex) review of
POC02 — `INDEPENDENT_REVIEW=PARTIAL`, `POC02_SQL_IDENTITY_REVIEW=PASS`
(static), `POC02_RLS_REVIEW=PARTIAL`, `POC02_HARNESS_REVIEW=FAIL`,
`FALSE_POSITIVE_RISK=HIGH`, `READY_FOR_INTEGRATION_DESIGN=NO`.

POC02's files were **not** modified. Everything below lives in this directory.

| # | Finding | Patch | Negative proof (it would catch a regression) | Status |
|---|---|---|---|---|
| **H1** HIGH | `expect_deny_mutation` accepted syntax/column/constraint errors as a security denial | `deny_verdict()` extracts the real SQLSTATE (`VERBOSITY=verbose`, `ERROR:  <state>: msg`) and accepts **only** the expected state, optionally requiring a message substring. 20 states (42601, 42703, 23xxx, 08xxx, 28xxx, 3D000, 22P02, …) are hard-listed as never-a-denial | `F01` syntax → `FORBIDDEN_STATE_42601`; `F02` undefined column → `42703`; `F03` unique violation → `23505`; each asserted as *rejected*. Mutant `m3` (expect 23505 instead of 42501) → `WRONG_STATE_42501`, exit 1 | **FIXED** |
| **H2** HIGH | no per-run proof of password auth / absence of `trust` | `AUTH01`–`AUTH05` every run: correct password works; empty password refused; wrong password refused with `28P01`; `database|session_user|current_user` asserted; `pg_hba_file_rules` trust-count and `password_encryption` asserted | `F07` runs a *denial* case with a wrong password and asserts it classifies as conn/auth, not as a security pass. `pg_hba` was also verified by hand: no-password → `fe_sendauth`, wrong password → `FATAL: password authentication failed` | **FIXED** |
| **S1** MEDIUM | `UPDATE … USING` guarded the OLD row, `WITH CHECK` did not pin the NEW owner → ownership/tenant transfer possible (esp. for admin) | `WITH CHECK` now pins tenant and allowed owner; `tenant_id` has no column `UPDATE` grant; `BEFORE UPDATE` trigger `leads_actor_lock_ownership` rejects any change of `owner_actor_id`/`tenant_id`/`id` with `ERRCODE 42501` | `B05` A1 transfers own row to A2 → `42501 owner_actor_id is immutable`; `B11` **admin** attempts the same → same denial; `B06` tenant transfer → `42501 permission denied for table` (column ACL); `B04` mass `UPDATE` with no `WHERE` touches exactly the 2 own rows. Mutant `m4` (wrong expected message) → exit 1 | **FIXED** |
| **H3** MEDIUM | AT18-class tests ran without `BEGIN/ROLLBACK` | every mutating or DDL/GRANT/ROLE scenario is wrapped in `BEGIN … ROLLBACK` (`D06`–`D11`, `D16`, `B05`–`B09`, `C02`, `C03`, `H01`–`H04`, `A03`–`A08`) | `G01` compares the full fingerprint before/after; the fingerprint was proven sensitive to a row edit, a `GRANT`, a new `CREATE POLICY` and `NO FORCE ROW LEVEL SECURITY` (four distinct hashes, all inside `ROLLBACK`) | **FIXED** |
| **H4** MEDIUM | fingerprint was row *counts* only; could pass silently or match two errors | `h01_fingerprint()` is an md5 over: row contents of all 5 tables, role attributes for `h01%`, role memberships, `relowner`/`relrowsecurity`/`relforcerowsecurity`/`relacl`, **column** ACLs (`attacl`), policies (name/cmd/qual/withcheck/roles), constraints, triggers, function `prosecdef`/owner/`proacl`/`proconfig`. Both before and after check `rc` first, and an unavailable baseline aborts with exit 96 | sensitivity demonstrated: `base ec04e6e2…` vs `row_change 25a3af87…` vs `acl_change a91d5e5b…` vs `pol_change dda1160c…` vs `rls_change 1b02ed18…`, returning to base after `ROLLBACK` | **FIXED** |
| **H5** MEDIUM | a control variable could skip scenarios; no manifest; "60" was a hard-coded expectation | explicit `MANIFEST` of 63 ids; every `record` appends its id; at the end missing / duplicated / undeclared ids and the count are computed from the manifest and reported; `MANIFEST_COMPLETE=FAIL` forces `OVERALL=FAIL`. The child invocation used by `F06` cannot skip anything — it is only reachable through the identity guard, which aborts it | mutant `m2` comments out one scenario → `MISSING=[A10]`, `MANIFEST_COMPLETE=FAIL`, exit 1; mutant `m1` (wrong expected value) → exit 1 | **FIXED** |
| **S2** MEDIUM | unique-key collision on a client-chosen id could reveal a hidden row's existence | `id` is DB-generated (`gen_random_uuid()`) and **not** in the `INSERT` column grant, so a client cannot supply a key to collide with; probing a hidden row by id through `UPDATE` returns 0 rows with no error | `H01` supplying an id → `42501 permission denied for table leads_actor`; `H02` `UPDATE … WHERE id=<hidden>` → 0 rows, no error; `H04` cross-tenant probe → `42501` RLS before uniqueness. **`H03` shows the residual channel honestly**: inserting a duplicate `code` inside the same tenant returns `23505`, which proves `A2-SECRET` exists although A1 cannot read it | **PARTIAL — in-tenant oracle OPEN by design decision, measured not hidden; cross-tenant closed** |

## Coverage gaps the review listed, and what was done

| Gap | Action |
|---|---|
| AT07/AT10/AT14 partial | `D01`–`D18`: `SET ROLE` to peer/owner, `pg_has_role`, zero `pg_auth_members`, anchor ACL (`has_table_privilege` × 3), role attributes, `FORCE RLS`, anchor ownership, **no PUBLIC EXECUTE on resolvers** (`aclexplode … grantee=0`), `CREATE FUNCTION` in `public` denied, `pg_temp` shadowing of *both* resolvers defeated, and `current_user`/`session_user` semantics measured in one assertion |
| AT17 did not test a genuinely polluted single session | `H05` uses one psql session with four `-c` statements: forge both GUCs → `RESET` → `DISCARD ALL` → re-read; result `2/2/2` |
| AT08 did not cover de-activation on a live actor | `H06` suspends `h01_a4` (committed), observes `0`, restores `ACTIVE`, observes `1`. Honest limit: this proves visibility **at the next statement**; revocation inside an already-open transaction is `NOT_VERIFIED`, and the role password remains valid after suspension |
| AT02 did not read back the new value | `A03`/`A07` update then `SELECT` the value inside the transaction; `A04` reads back owner+name of the inserted row; `A05` counts the deleted row |
| AT18d/e accepted any error | `D08`/`D09` now require `42501` **and** the specific message (`permission denied to grant role`, `permission denied to alter role`) |

## This harness's own failures, before they were fixed

Recorded as required, in order:

1. **First application of `001` failed** (`exit 3`): `h01_fingerprint()` was
   defined in `001` but reads the comparison tables created in `003`, and a
   `LANGUAGE sql` body is validated at creation. Fix: the function moved to the
   end of `003`. Nothing was created — `001` is one transaction and rolled back.
2. **`003` then failed**: `pg_policy.polcmd` and `pg_trigger.tgenabled` are
   `"char"`, so `text || "char"` is ambiguous (`operator is not unique`). Fix:
   explicit `::text` casts.
3. **First full harness run looked green (63/63) but its evidence column was
   wrong.** `deny_verdict()` is called through command substitution, so the
   `$STATE`/`$ERR` globals it set were invisible to the caller, and the report
   printed the *previous* query's stderr — `H01`'s evidence showed a
   connection error left over from `F07`. The verdicts themselves were computed
   inside the subshell and were correct, but the evidence was misleading. Fix:
   `deny_verdict` now returns `VERDICT|SQLSTATE|message` and the caller parses
   it; the denial rows now carry their own `sqlstate=42501` and real message.
   This is the same family of defect as POC02's lost `$?` — recorded, not hidden.
4. **A Python in-place edit rewrote the files with CRLF**, and bash then failed
   with `set: pipefail: invalid option name` / `$'\r': command not found`
   (exit 2). Fix: line endings normalised to LF; `bash -n` syntax check added
   to the workflow before running.

## Mutation testing of the final harness

Four mutants, each run against the live sandbox; all four correctly failed
with exit 1:

| Mutant | Injected defect | Detected as |
|---|---|---|
| `m1` | `A01` expects 3 rows instead of 2 | `ASSERTION_FAIL exp=3 act=2` |
| `m2` | `A10` commented out | `MISSING=[A10]`, `MANIFEST_COMPLETE=FAIL` |
| `m3` | `B05` expects `23505` instead of `42501` | `WRONG_STATE_42501` |
| `m4` | `B05`/`B11` expect a message that never appears | 2 × `WRONG_MESSAGE` |

## Still open / not provable here

- In-tenant existence oracle through tenant-wide uniqueness on a
  client-supplied value (`H03`) — **OPEN**. Closing it needs a business
  decision (DB-generated business keys, actor-scoped uniqueness, or accepting
  the leak), not a message tweak.
- Laravel/HTTP binding, credential provisioning/rotation/revocation,
  connection pooling, compromise of a process holding every credential:
  **NOT_EXECUTED / out of scope**.
- Revocation inside an open transaction: **NOT_VERIFIED**.
- This is still an internal review of my own work. An independent Codex pass on
  *this* directory is the appropriate next gate.
