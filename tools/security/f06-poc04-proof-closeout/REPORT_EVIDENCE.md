# POC04 (final harden) — sanitized evidence

No passwords, hashes, `PGPASSWORD` values, credential paths or environment
secrets appear here. All fixtures are synthetic. `set -x` was never enabled.

## Sandbox identity — `VERIFIED_RUNTIME_NEW_SANDBOX`

| Item | Value |
|---|---|
| container | `daleel-f06-final-harden-q8w2-pg` |
| container id | `889d7dbdc80b18c0eae32a69762f9cd4ac92710946623b22b3b74bd5e05cadee` |
| network | `daleel-f06-final-harden-q8w2-net`, **`Internal=true`** |
| network id | `3dcb91247be6e8f7451128e743b04b815a494eb4e1ccc8d4df95dc38fb973531` |
| volume | `daleel_f06_final_harden_q8w2_pg_data` (only non-root mount) |
| database / OID | `daleel_f06_final_harden_q8w2_synthetic` / `16384` |
| system_identifier | `7700553360591278118` |
| PostgreSQL | 16.15 (Debian 16.15-1.pgdg13+2), local `postgres:16` image — **no pull** |
| published host port | **NONE** (`Ports: 5432/tcp`, unmapped). Tests run via `docker exec` over TCP to the in-container `127.0.0.1:5432`, asserted live by `AUTH06` |
| limits | `--memory=384m --cpus=1` |
| labels | `com.daleel.purpose=f06-final-harden` on container, network and volume |

**Egress — measured:** `getent hosts deb.debian.org` → `DNS_BLOCKED`;
TCP to `1.1.1.1:443` → `EGRESS_BLOCKED`.

**Distinct from every protected / prior environment** (`system_identifier`):

| Environment | system_identifier | touched? |
|---|---|---|
| **POC04 (this)** | `7700553360591278118` | created here |
| POC03 | `7700516237007110183` | no (read-only hashes) |
| POC02 (stopped) | `7700478534754992166` | no |
| POC01 (running) | `7700445040430698534` | no |
| G2 | `7700288866362540071` | no |
| acceptance (RM02/DEV/Old TEST) | `7699972247235194919` | no |

Host ports 55432 / 55433 / 55437 / 55439 / 55441 / 55443 were untouched and
unnecessary — nothing was published.

## Authentication — `VERIFIED_RUNTIME_NEW_SANDBOX`

Every rule in this container's `pg_hba.conf` was set to `scram-sha-256`
(including the three `replication` rules the stock image ships as `trust`).
Observed:

```
count(*) FROM pg_hba_file_rules WHERE auth_method='trust'   ->  0
current_setting('password_encryption')                      ->  scram-sha-256
no password      -> psql: ... fe_sendauth: no password supplied
wrong password   -> FATAL:  password authentication failed for user ...
correct password -> auth_ok
inet_server_addr()/port (as used by the tests) -> 127.0.0.1:5432
```

The AUTH gate re-proves all of this for **all seven** matrix logins on every
run (`AUTH01`–`AUTH06`) and exits `70` before any mutating scenario on the
first problem. Adversarial scenarios always run as non-superuser, non-owner
`LOGIN` roles after real SCRAM authentication; `postgres` is used only for
fixtures, the fingerprint and catalog assertions.

## Runs, in order, including the failures

| Run | Result | Note |
|---|---|---|
| apply `001` → `003` → `002` | OK | baseline fingerprint `472e019110ca6b09715cdbf253d803868bbdc0a18f9791081bfbb3785123f4e4` |
| `ALTER ROLE fh_a5 PASSWORD` via `-c` | **FAILED** (`42601`) | psql variables are not interpolated with `-c`; redone from a file, then `fh_a5` proved to authenticate with its own distinct password while `fh_shared_a` rejects it |
| harness run 1 | `PASS_SCOPED`, 72 recorded | 71 PASS + 1 EXPECTED_FINDING, 0 ASSERTION_FAIL, 0 HARNESS_ERRORS |
| **final runs ×3** | `PASS_SCOPED` each | `EXPECTED_SCENARIOS=72 RECORDED=72 PASS=71 ASSERTION_FAIL=0 HARNESS_ERRORS=0 EXPECTED_FINDINGS=1 MANIFEST_COMPLETE=PASS`, fingerprint identical before/after each run |

Cross-run equality was asserted on normalized `(id, verdict, expected)`
columns (`final1==final2==final3`), not on raw log bytes — evidence strings
contain variable server text.

## Mutation tests — every one correctly failed

| Mutant | Injected defect | Outcome |
|---|---|---|
| `m1` | a real unique violation declared as the expected security denial (`23505`/`DENY_RLS`) | `B07 ASSERTION_FAIL act=NON_SECURITY_FAILURE_23505`, run `exit 1` |
| `m2` | fingerprint default query → non-existent function | run aborted **`exit 96`** before any scenario |
| `m3` | one scenario commented out | `MISSING=[A10]`, `MANIFEST_COMPLETE=FAIL`, `exit 1` |
| `m4` | detector reverted to naive `aclexplode(proacl)` | `F4a ASSERTION_FAIL act=0` — the pre-fix check misses a default-ACL grant, `exit 1` |
| `m5` (HBA) | one `host … 127.0.0.1/32 trust` rule, server reloaded | `AUTH_GATE_FAIL: 1 effective trust rule(s) could match the test path`, `exit 70`, **0** scenario lines; HBA then restored and re-verified (`trust_rules=0`) |
| `M6a` | `fh_a5` suspended **with** recovery marker | run announced `H06_RECOVERY`, restored it, `PASS_SCOPED`, `fh_a5` ended `ACTIVE` |
| `M6b` | `fh_a5` suspended **without** marker | `exit 95`, `BLOCKED_CLEANUP_REQUIRED`, nothing else ran |

## Fingerprint sensitivity (all probes inside `ROLLBACK`)

```
baseline                        472e019110ca6b09715cdbf253d803868bbdc0a18f9791081bfbb3785123f4e4
created_at + 1 second           23a9a73c3b641e4dc1e80f7e133114b69b0969bdf903843950b6b12c8cc76731
app_actor_is_admin() body       902921b565994bead3c2b01851cdbc1e15b693c08ac556c4aeed2aef0c4a4390
column default on name          b1de18f30639d2fdff7197462b3831fd77e1efe0ee55d86a82b0062686a32890
new RESTRICTIVE policy          fd5595b4d9a91520504f2d698a9bfc201b98e18c0e81dae7dbc0df143cdf6f26
GRANT CREATE ON SCHEMA public   d767614162973a7ad14ef393901bc5dde4f25f059b112b36c5671ba64d2eb016
new function with default ACL   8e8c9354a953eb5692221c4d2558889bd2348a05c983a6afc35b81a034c49782
ALTER DEFAULT PRIVILEGES        8cc2670dc1f8a6f79d108679ab8fbeb60028a083a9410cb07509faa6e0c00cc5
trigger function body           77f96ff841f3ea13746c4c4e6a1a02287d51c12f1479dd8f38dd34061b1ea4bd
after all rollbacks             472e019110ca6b09715cdbf253d803868bbdc0a18f9791081bfbb3785123f4e4
```

## Scenario results (final run 1 of 3; verdicts identical in runs 2 and 3)

Verdict vocabulary: `PASS` = positive assertion on data; `SECURITY_CONTROL_PASS`
= denial whose SQLSTATE **and** control kind **and** message matched;
`EXPECTED_FINDING` = a measured weakness, counted separately and never a pass.

```
AUTH01 PASS  0 effective trust rules        AUTH02 PASS  scram-sha-256
AUTH03 PASS  all 7 logins authenticate      AUTH04 PASS  missing password refused x7
AUTH05 PASS  wrong password refused x7      AUTH06 PASS  tcp 127.0.0.1:5432

A01 PASS 2                      A02 PASS Lead A1-one          A03 PASS legit-new-a1 (readback)
A04 PASS owner+name readback    A05 PASS 1 deleted            A06 PASS 5 (admin sees tenant A)
A07 PASS admin-edited readback  A08 PASS 1 inserted           A09 PASS 1 admin_grant
A10 PASS 1 (B1)

B01 PASS 0   B02 PASS 0   B03 PASS 2   B04 PASS 2 (mass UPDATE, no WHERE)
B05 SECURITY_CONTROL_PASS 42501/DENY_TRIGGER  "owner_actor_id is immutable"
B06 SECURITY_CONTROL_PASS 42501/DENY_ACL      "permission denied for table"
B07 SECURITY_CONTROL_PASS 42501/DENY_RLS      "row-level security"
B08 SECURITY_CONTROL_PASS 0 rows (USING)      B09 SECURITY_CONTROL_PASS 0 rows (USING)
B10 PASS 0
B11 SECURITY_CONTROL_PASS 42501/DENY_TRIGGER  (ADMIN ownership transfer refused)

C01 PASS 0   C02 SECURITY_CONTROL_PASS 0 rows   C03 SECURITY_CONTROL_PASS 42501/DENY_RLS
C04 PASS 0   C05 PASS 0

D01 SECURITY_CONTROL_PASS 42501/DENY_ACL  (SET ROLE fh_a2)
D02 SECURITY_CONTROL_PASS 42501/DENY_ACL  (SET ROLE fh_owner)
D03 PASS false,false,false      D04 PASS 0 memberships
D05 SECURITY_CONTROL_PASS 42501/DENY_ACL  (SELECT anchor)
D06 SECURITY_CONTROL_PASS 42501/DENY_ACL  (UPDATE anchor)
D07 SECURITY_CONTROL_PASS 42501/DENY_ACL  (CREATE ROLE)
D08 SECURITY_CONTROL_PASS 42501/DENY_ACL  (GRANT role)
D09 SECURITY_CONTROL_PASS 42501/DENY_ACL  (ALTER ROLE SUPERUSER)
D10 SECURITY_CONTROL_PASS 42501/DENY_OWNER (DISABLE RLS)
D11 SECURITY_CONTROL_PASS 42501/DENY_OWNER (CREATE POLICY)
D12 PASS 0 unsafe role attributes          D13 PASS true (ENABLE+FORCE RLS)
D14 PASS fh_owner owns the anchor          D15 PASS 0 effective PUBLIC EXECUTE
D16 SECURITY_CONTROL_PASS 42501/DENY_ACL   (CREATE FUNCTION in public)
D17 PASS fh_a1,fh_a1 / fh_owner,fh_a1 / NULL   (invoker / definer / wrong resolver)
D18 PASS 2|0  (pg_temp shadowing of both resolvers defeated)
D19 PASS fh_a1:true/false,fh_a2:true/false,fh_b1:true/false  (schema USAGE yes, CREATE no)
D20 PASS 3  (resolvers: SECURITY DEFINER + owner fh_owner + pinned search_path)

F1a PASS NON_SECURITY_FAILURE_42601   F1b PASS NON_SECURITY_FAILURE_42703
F1c PASS NON_SECURITY_FAILURE_23505   F1d PASS WRONG_KIND_DENY_TRIGGER
F2a PASS rc=1 ok=0                    F2b PASS non-empty stdout + rc!=0 rejected
F2c PASS wrong-shape value rejected   F4a PASS default-ACL function detected
F4b PASS revoked function not flagged F5a PASS no trust rule anywhere

H01 SECURITY_CONTROL_PASS 42501/DENY_ACL  (client cannot supply id)
H02 SECURITY_CONTROL_PASS 0 rows (probe by hidden id reveals nothing)
H03 EXPECTED_FINDING 23505 — UNIQUE(tenant_id,code) reveals a hidden row intra-tenant
H04 SECURITY_CONTROL_PASS 42501/DENY_RLS  (cross-tenant probe stopped by RLS first)
H05 PASS 2 2 2 in one polluted session (forge → RESET → DISCARD ALL)
H06a PASS in-tx resolver yields nothing (rollback-guaranteed; not cross-connection proof)
H06b PASS cross-conn 0 then 1, restore verified (committed window declared)
H06c PASS SIGKILL mid-tx leaves ACTIVE

G01 PASS fp(after) readable, 64 hex, rc=0
G02 PASS fp(before)==fp(after), components 01..17
```

## Deliverable hashes (after work) — `VERIFIED_SOURCE`

See the final report for the table; hashes were recomputed after the last
edit and the POC01/POC02/POC03 originals were re-hashed and found unchanged.

## Not claimed

`F06` is not closed in the product. `SCHEMA_FIDELITY = SCOPED_EQUIVALENT`
(6 columns vs the product's 18; no `tenant_staff_*`, no product triggers,
migrations 001–038 not applied). The product has **no** UNIQUE constraint on
`leads`, so the intra-tenant oracle measured in `H03` is a property of this
POC's construct and stays `OPEN` pending an owner decision.
`LARAVEL_WIRE_INTEGRATION = NOT_EXECUTED`. `PGBOUNCER_POOLING = NOT_VERIFIED`.
Revocation inside an open transaction: `NOT_VERIFIED`. The committed window in
`H06b` is declared, not eliminated. A compromised process holding all
credentials is out of the threat model. The review in `README_REVIEW.md` is
internal; an independent Codex pass on this directory is the next gate.
