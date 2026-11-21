# F1–F7: finding → patch → negative proof → status

Source: the owner-conveyed independent (Codex) review of POC03 —
`PARTIAL`, `POC03_HARNESS_REVIEW=FAIL`.

POC01/POC02/POC03 files were **not** modified; their SHA-256 values are
recorded before and after this task in `REPORT_EVIDENCE.md`. Everything below
lives in this directory and ran only against the POC04 sandbox.

**This is an internal review by the same tool that wrote the patch. A fresh
independent Codex pass on *this* directory is required for acceptance.**

---

### F1 — SQLSTATE classification (`POC03 run_tests.sh:139`)

*Finding.* A forbidden code such as `23505` could be accepted if a test
declared it as `expected_sqlstate`; and `42501` alone was treated as proof
without identifying which control refused.

*Patch.* `deny_verdict()` now evaluates in this order: connection/auth → empty
state → **`NON_SECURITY_STATES` rejection (before `expected` is consulted)** →
`SECURITY_STATES` membership (only `42501`) → expected match → **deny kind**
(`DENY_ACL` / `DENY_RLS` / `DENY_TRIGGER` / `DENY_OWNER`, derived from the
server message; `DENY_UNKNOWN` fails) → message substring. Every
`expect_deny` call now declares both the state **and** the kind.

*Negative proof.*
- In-suite: `F1a` syntax declared as expected → `NON_SECURITY_FAILURE_42601`;
  `F1b` undefined column → `NON_SECURITY_FAILURE_42703`; `F1c` real unique
  violation declared as expected → `NON_SECURITY_FAILURE_23505`; `F1d` a
  genuine `42501` with the **wrong kind** declared → `WRONG_KIND_DENY_TRIGGER`.
- Mutant `m1` rewrote `B07` into a real unique violation declaring
  `23505`/`DENY_RLS`: result `ASSERTION_FAIL act=NON_SECURITY_FAILURE_23505`,
  whole run `exit 1`.

*Exception, as instructed.* The oracle probe `H03` is recorded as
`EXPECTED_FINDING` in its own counter (`EXPECTED_FINDINGS=1`) and can never
become a control pass.

**STATUS: CLOSED_IN_POC**

---

### F2 — fingerprint RC capture (`POC03 run_tests.sh:177,194,376`)

*Finding.* The fingerprint was read through command substitution, so the
global `RC` could be stale and `printf` masked the query's failure.

*Patch.* `fp_read()` is called directly (never in `$( )`), writes stdout and
stderr to separate files, sets `FP_VALUE` / `FP_RC` / `FP_ERR`, and sets
`FP_OK=1` only when `rc == 0` **and** the value is exactly 64 lowercase hex
characters. The baseline read happens before any scenario and aborts the run
with exit `96` if the contract is not met; `G01` asserts the after-read
contract separately from `G02`'s comparison, so two failed reads can never
compare "equal".

*Negative proof.*
- `F2a` missing function → `rc=1`, `FP_OK=0`, rejected.
- `F2b` `SELECT 'not-a-hash'; SELECT 1/0;` → **non-empty stdout with rc≠0** →
  rejected.
- `F2c` `SELECT 'deadbeef'` → rc=0 but wrong shape → rejected.
- Mutant `m2` pointed the default fingerprint query at a non-existent
  function: the run aborted with **exit 96** before any scenario executed.

**STATUS: CLOSED_IN_POC**

---

### F3 — fingerprint scope (`POC03 003_comparison.sql:53/87`)

*Finding.* "FULL" overstated the coverage; `created_at`, function bodies,
defaults, `polpermissive` and schema ACLs were missing.

*Patch.* `fh_fingerprint()` is a SHA-256 over a deterministic ordered canonical
text with **declared** components `01..17`: table rows incl. `created_at`;
mapping rows; grants; both comparison tables; role attributes incl.
`rolconnlimit`/`rolconfig`; memberships incl. `grantor`; table
owner/ENABLE/FORCE RLS/effective table ACL; effective column ACLs; column
defaults; column type + notnull; policies incl. `polpermissive`; constraints;
triggers **plus the trigger function body**; functions with
`prosecdef`/owner/effective ACL/`proconfig`/`md5(prosrc)`; schema ACL for
`public`; `pg_default_acl`. A `COVERAGE_MARKER` line pins the declared set.
An explicit **NOT_COVERED** list is in the file header (sequences, extensions,
event triggers, publications, large objects, FDW, `pg_db_role_setting`,
statistics, anything outside schema `public`).

*Negative proof.* Nine independent in-transaction mutants, each changed the
hash and each rolled back to baseline `472e0191…`:

| mutation | hash |
|---|---|
| baseline | `472e019110ca6b09…` |
| `created_at` + 1s | `23a9a73c3b641e4d…` |
| `app_actor_is_admin` body | `902921b565994bea…` |
| column default on `name` | `b1de18f30639d2fd…` |
| new RESTRICTIVE policy | `fd5595b4d9a91520…` |
| `GRANT CREATE ON SCHEMA public` | `d767614162973a7a…` |
| new function with default ACL | `8e8c9354a953eb56…` |
| `ALTER DEFAULT PRIVILEGES` | `8cc2670dc1f8a6f7…` |
| trigger function body | `77f96ff841f3ea13…` |
| after all rollbacks | `472e019110ca6b09…` |

**STATUS: CLOSED_IN_POC** (coverage declared, not claimed as absolute)

---

### F4 — default privileges check (`POC03 run_tests.sh:281`)

*Finding.* `aclexplode(p.proacl)` yields nothing when `proacl IS NULL`, which
is exactly the case where PostgreSQL grants `EXECUTE` to `PUBLIC` by default.

*Patch.* `fh_effective_public_execute()` uses
`aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner)))`, reports the
`regprocedure` signature (so overloads are distinguished) and whether the ACL
was explicit or default. `fh_effective_schema_acl()` does the same for schema
privileges. `D15` asserts zero effective PUBLIC EXECUTE across the anchor
functions; `D19` asserts `USAGE=true, CREATE=false` on `public` for login
roles.

*Negative proof.*
- `F4a` creates a function **with the default ACL** inside a transaction: the
  detector reports it (`1`), then rollback.
- `F4b` creates one and `REVOKE ALL … FROM PUBLIC`: detector reports `0`.
- Mutant `m4` replaced the detector call with the old naive
  `aclexplode(p.proacl)` form: `F4a` then returned `0` and the run failed
  (`exit 1`) — i.e. the pre-fix check demonstrably missed the default grant.

**STATUS: CLOSED_IN_POC**

---

### F5 — authentication gate (`POC03 run_tests.sh:223`)

*Finding.* `AUTH05` checked the HBA file loosely, only `a1` was exercised, and
a failed auth did not stop the run.

*Patch.* A standalone `auth_gate()` runs before every mutating scenario and
`exit 70`s on the first problem. It checks: (1) zero effective `trust` rules
among rules whose `type` and `database` could match this test path, read from
`pg_hba_file_rules` with `error IS NULL`; (2) `password_encryption =
scram-sha-256`; (3) **all seven** matrix logins authenticate with the correct
password and report the expected `session_user`; (4) all seven are refused with
a missing password (`fe_sendauth`); (5) all seven are refused with a wrong
password (`28P01`); (6) the transport actually used is the expected in-container
TCP endpoint (`inet_server_addr()`/`inet_server_port()` = `127.0.0.1:5432`).

*Negative proof.* One HBA line in the POC04 sandbox only was changed to
`trust` and the server reloaded. The harness printed
`AUTH_GATE_FAIL: 1 effective trust rule(s) could match the test path`,
`AUTH_GATE=FAIL — refusing to run any security or mutation scenario`, exited
**70**, and **zero** A/B/C/D/H scenario lines were produced. HBA was then
restored and re-verified (`trust_rules=0`, password again required). `F5a`
additionally asserts zero trust rules anywhere, every run.

**STATUS: CLOSED_IN_POC**

---

### F6 — H06 revocation state safety (`POC03 run_tests.sh:355`)

*Finding.* Suspend and restore were two independent committed statements, so an
interruption between them left the actor suspended.

*Patch.* Three separate scenarios plus a recovery contract:
- `H06a` — mechanism inside **one** transaction that always rolls back; it
  proves the mapping-driven denial logic without any committed window, and its
  evidence line states explicitly that it does **not** prove cross-connection
  revocation.
- `H06b` — the cross-connection observation, confined to the dedicated actor
  `fh_a5` (reference actors are never touched), wrapped in a recovery marker
  file, with the restore verified by an independent read of `actor_status`
  before the result is accepted.
- `H06c` — a `psql` transaction that suspends `fh_a5` then sleeps is
  `kill -9`ed; the mapping is then asserted still `ACTIVE`, i.e. PostgreSQL
  rolled the aborted transaction back.
- Startup contract: a stale marker triggers an automatic idempotent restore
  (announced as `H06_RECOVERY`); a suspended `fh_a5` with **no** marker is an
  unexplained state and the run exits `95`
  (`BLOCKED_CLEANUP_REQUIRED`). A marker left at the end forces `OVERALL=FAIL`.

*Negative proof.*
- `M6a`: `fh_a5` suspended **with** a marker → run announced
  `H06_RECOVERY`, restored it, finished `PASS_SCOPED`, and `fh_a5` ended
  `ACTIVE`.
- `M6b`: `fh_a5` suspended **without** a marker → `exit 95`,
  `BLOCKED_CLEANUP_REQUIRED`, nothing else ran.
- `H06c` passes: after `SIGKILL` mid-transaction the status is `ACTIVE`.

*Honest limit.* `H06b`'s committed window still exists; the marker makes
recovery idempotent, it does not remove the window. Loss of the host mid-window
is **not** defended against beyond the next run's recovery, and nothing here
claims protection against that.

**STATUS: CLOSED_IN_POC for the in-transaction and interruption cases;
the committed-window risk in `H06b` is DECLARED, not eliminated.**

---

### F7 — POC vs product contract (acceptance constraint, not a fix)

Read-only comparison against the product source:

| Aspect | Product (VERIFIED_SOURCE) | POC04 |
|---|---|---|
| `leads` columns | **18** (4 uuid + 10 string + 1 unsignedInteger + 1 timestampTz + `timestampsTz()`→2), migration `2026_10_23_000036` | `leads_actor`, 6 columns |
| uniqueness | **no UNIQUE constraint at all**; three non-unique indexes (`tenant_id,pipeline_stage`), (`tenant_id,assigned_membership_id`), (`tenant_id,status`) | `UNIQUE (tenant_id, code)` — a POC construct |
| ownership | `assigned_membership_id` + `created_by_membership_id`; `LeadService::assignLead()` **permits authorised re-assignment** for `ALL_TENANT` holders and refuses it for `ASSIGNED`/`SELF` (`LeadService.php:149-161`) | blanket immutability of `owner_actor_id` via trigger |
| scoping | `ALL_TENANT` / `ASSIGNED` / `SELF` enforced in the application (`TenantAuthorizationService::allowsObject()`, per-query `orWhere` scoping, `LeadService.php:192-216`); RLS proves tenant isolation only | single `owner_actor_id`-or-admin predicate in RLS |
| identity | `tenant_staff_*` tables, memberships, RBAC, provider flows | one mapping table |

Consequences recorded, not acted on: the POC's ownership immutability **must
not** be imposed on the product; the `code` uniqueness contract was **not**
changed and no scope decision was invented; `S2` intra-tenant stays **OPEN**
pending an owner/business decision, and is reported as a finding rather than a
success. Because the product has no unique business key on `leads` today, the
oracle demonstrated here is a property of the POC construct.

**STATUS: DOCUMENTED — no product change, no invented decision**

---

## Adversarial questions, answered

| Question | Answer |
|---|---|
| Can a non-security SQL error pass if `expected_sqlstate` matches? | No — `NON_SECURITY_STATES` is rejected before `expected` is read; proved by `F1a–F1c` and mutant `m1`. |
| Can two broken reads produce "equal" fingerprints? | No — `FP_OK` requires rc=0 and a 64-hex value; `G01` asserts the read before `G02` compares. Proved by `F2a–F2c` and mutant `m2` (exit 96). |
| Can a default/trigger body/PUBLIC privilege change hide from the fingerprint? | No for the nine declared components tested; anything outside the declared set is listed as NOT_COVERED rather than implied. |
| Does a real `trust` rule stop all modifying SQL? | Yes — gate exits 70, zero scenarios run; demonstrated live and then restored. |
| Does `H06` restore even when interrupted? | In-transaction: yes (`H06c`, SIGKILL). Cross-connection: only via the idempotent marker on the next run; the window itself is declared. |
| Is a hidden `code` inside a tenant still discoverable? | Yes — `H03`, `EXPECTED_FINDING`, `23505`. OPEN. |
| Does POC ownership locking differ from the product? | Yes, and the product's authorised re-assignment is the correct behaviour; the POC lock is explicitly not a product recommendation. |
| Can a compromised PHP process holding every credential bypass this? | Yes. Out of threat model; no claim of protection. |
