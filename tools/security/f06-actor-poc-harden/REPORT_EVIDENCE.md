# POC03 (hardened) — sanitized evidence

No passwords, hashes, `PGPASSWORD` values or environment secrets appear here.
All fixtures are synthetic. Provenance is marked per item.

## Sandbox identity — `VERIFIED_RUNTIME_NEW_SANDBOX`

| Item | Value |
|---|---|
| container | `daleel-f06-harden01-h3k9q7-pg` |
| container id | `7f9eee24e9c75bc72ebf94ec31b0f7c162cc872341b8c92906f1626e3335e269` |
| network | `daleel-f06-harden01-h3k9q7-net`, **`Internal=true`** |
| network id | `0edf010b631c2ee1650e7a31e61c15eb95b350c9bce06c9bdfbdede05194aa33` |
| volume | `daleel_f06_harden01_h3k9q7_pg_data` (only non-root mount) |
| database | `daleel_f06_harden01_h3k9q7_synthetic`, OID `16384` |
| system_identifier | `7700516237007110183` |
| PostgreSQL | 16.15 (Debian 16.15-1.pgdg13+2) from the already-local `postgres:16` image — **no pull** |
| published host port | **none** (`Ports: 5432/tcp`, unmapped). Tests run via `docker exec` over TCP to `127.0.0.1:5432` inside the container |
| limits / usage | `--memory=384m --cpus=1`; host had ~2.7 GB free and 79 GB disk before creation |
| labels | `com.daleel.purpose=f06-harden01` on container, network and volume |

**Egress — measured, not assumed:** on this `--internal` network,
`getent hosts deb.debian.org` → `DNS_BLOCKED` and a TCP attempt to
`1.1.1.1:443` → `EGRESS_BLOCKED`. (POC01/POC02 used plain bridge networks where
the same probes showed egress *possible*; that is the difference here.)

**Distinct from every protected environment** (`system_identifier`):

| Environment | system_identifier | touched? |
|---|---|---|
| **POC03 (this)** | `7700516237007110183` | created by this task |
| POC02 (stopped) | `7700478534754992166` | no |
| POC01 (running) | `7700445040430698534` | no |
| G2 | `7700288866362540071` | no |
| acceptance (RM02/DEV/Old TEST) | `7699972247235194919` | no |

Ports in use before this task — 55432 scratch, 55433/55437 acceptance,
55439 G2, 55441 POC01, 55443 POC02 — were all left alone and none was needed,
because nothing was published.

## Authentication proof — `VERIFIED_RUNTIME_NEW_SANDBOX`

`pg_hba.conf` in this container only was set to `scram-sha-256` on **all seven
rules** (local, host loopback v4/v6, and the three `replication` rules the
stock image also ships as `trust`), then reloaded with `pg_ctl reload`.

```
SELECT count(*) FROM pg_hba_file_rules WHERE auth_method='trust'  ->  0
show password_encryption                                          ->  scram-sha-256
psql with no password      -> psql: error: ... fe_sendauth: no password supplied
psql with wrong password   -> FATAL:  password authentication failed for user ...
psql with correct password -> auth_ok
```

Re-proved inside every run as `AUTH01`–`AUTH05`. All adversarial scenarios run
as non-superuser, non-owner `LOGIN` roles after real SCRAM authentication;
`postgres` is used only for fixtures, the fingerprint and catalog assertions.

## Runs

| Run | Result | Note |
|---|---|---|
| apply `001` (1st) | **FAIL exit 3** | `h01_fingerprint()` referenced tables created in `003`; whole transaction rolled back |
| apply `003` (1st) | **FAIL exit 3** | `text || "char"` ambiguity on `polcmd`/`tgenabled` |
| apply `001`/`003`/`002` (fixed) | OK | baseline fingerprint `ec04e6e223e9850bc7cf9a506c2554d5` |
| harness run 1 | 63/63 but **evidence column stale** | `deny_verdict` subshell did not export `$STATE`/`$ERR`; verdicts correct, evidence misleading |
| harness run (CRLF) | **FAIL exit 2** | Python edit wrote CRLF; `set: pipefail: invalid option name` |
| **final runs ×3** | **PASS_SCOPED each** | `EXPECTED_SCENARIOS=63 RECORDED=63 PASS=63 ASSERTION_FAIL=0 HARNESS_ERRORS=0 MANIFEST_COMPLETE=PASS`, fingerprint `ec04e6e2…` before and after every run |

Cross-run comparison was done on the normalized `(id, verdict, expected)`
columns — `final1==final2==final3` — rather than claiming byte-identical logs,
because evidence strings legitimately contain variable error text.

## Mutation tests of the harness (all correctly failed, exit 1)

| Mutant | Injected defect | Detected as |
|---|---|---|
| m1 | `A01` expects 3 instead of 2 | `ASSERTION_FAIL exp=3 act=2` |
| m2 | `A10` commented out | `MISSING=[A10]` → `MANIFEST_COMPLETE=FAIL` |
| m3 | `B05` expects `23505` instead of `42501` | `WRONG_STATE_42501` |
| m4 | `B05`/`B11` expect an impossible message | 2 × `WRONG_MESSAGE` |

## Fingerprint sensitivity (all probes inside `ROLLBACK`)

```
base       = ec04e6e223e9850bc7cf9a506c2554d5
row edit   = 25a3af8769627197a42b11daa99f6b9b
GRANT      = a91d5e5bf7fe97cdd8d55819ecce2367
CREATE POLICY = dda1160c98685a0a943834da1116c42e
NO FORCE RLS  = 1b02ed1877d34d03bf7ec74c0fc4a47b
after      = ec04e6e223e9850bc7cf9a506c2554d5
```

## Scenario results (final run 1 of 3; identical verdicts in runs 2 and 3)

`PASS` = positive assertion on data. `SECURITY_CONTROL_PASS` = denial whose
SQLSTATE (and message, where specified) matched the expected control.

```
AUTH01 PASS  auth_ok                         AUTH02 PASS  refused(no password)
AUTH03 PASS  refused(28P01)                  AUTH04 PASS  db|session_user|current_user
AUTH05 PASS  0|scram-sha-256

A01 PASS 2            A02 PASS Lead A1-one           A03 PASS legit-new-a1 (readback)
A04 PASS owner+name of inserted row           A05 PASS 1 deleted
A06 PASS 4 (admin)    A07 PASS admin-edited (readback)   A08 PASS 1 inserted
A09 PASS 1 admin_grant                        A10 PASS 1 (B1)

B01 PASS 0 admin_grants under forged user_id  B02 PASS 0 (A2's row)
B03 PASS 2 (own, unchanged by forgery)        B04 PASS 2 (mass UPDATE, no WHERE)
B05 SECURITY_CONTROL_PASS 42501 "owner_actor_id is immutable on leads_actor"
B06 SECURITY_CONTROL_PASS 42501 "permission denied for table leads_actor"
B07 SECURITY_CONTROL_PASS 42501 "new row violates row-level security policy"
B08 SECURITY_CONTROL_PASS 0 rows (UPDATE of A2's row)
B09 SECURITY_CONTROL_PASS 0 rows (DELETE of A2's row)
B10 PASS 0 (A4 cannot see A1's row)
B11 SECURITY_CONTROL_PASS 42501 "owner_actor_id is immutable" (ADMIN attempt)

C01 PASS 0   C02 SECURITY_CONTROL_PASS 0 rows   C03 SECURITY_CONTROL_PASS 42501 RLS
C04 PASS 0   C05 PASS 0 (admin cannot cross tenants either)

D01 SECURITY_CONTROL_PASS 42501 "permission denied to set role"
D02 SECURITY_CONTROL_PASS 42501 (SET ROLE h01_owner)
D03 PASS false,false,false (pg_has_role)        D04 PASS 0 memberships
D05 SECURITY_CONTROL_PASS 42501 "permission denied for table actor_identity_map"
D06 SECURITY_CONTROL_PASS 42501 (UPDATE of the anchor)
D07 SECURITY_CONTROL_PASS 42501 "permission denied to create role"
D08 SECURITY_CONTROL_PASS 42501 "permission denied to grant role"
D09 SECURITY_CONTROL_PASS 42501 "permission denied to alter role"
D10 SECURITY_CONTROL_PASS 42501 "must be owner of table leads_actor" (DISABLE RLS)
D11 SECURITY_CONTROL_PASS 42501 (CREATE POLICY)
D12 PASS 0 unsafe role attributes               D13 PASS true (FORCE RLS)
D14 PASS h01_owner owns the anchor              D15 PASS 0 PUBLIC EXECUTE grants
D16 SECURITY_CONTROL_PASS 42501 "permission denied for schema public"
D17 PASS h01_a1,h01_a1 / h01_owner,h01_a1 / NULL   (invoker / definer / wrong-resolver)
D18 PASS 2|0 (pg_temp shadowing of both resolvers defeated)

F01 PASS rejects 42601   F02 PASS rejects 42703   F03 PASS rejects 23505
F04 PASS harness error on bad port               F05 PASS harness error on bad db
F06 PASS identity guard exits 98                 F07 PASS auth failure != security deny

H01 SECURITY_CONTROL_PASS 42501 (cannot supply id)   H02 SECURITY_CONTROL_PASS 0 rows
H03 PASS  oracle OPEN in-tenant — 23505 observed for a hidden row
H04 SECURITY_CONTROL_PASS 42501 RLS (cross-tenant probe)
H05 PASS 2/2/2 in one polluted session (forge → RESET → DISCARD ALL)
H06 PASS suspend→0 then restore→1

G01 PASS fingerprint before == after
```

## Deliverable hashes (`VERIFIED_SOURCE`)

```
587fbd4a05394b86813dc1c6699a1f10e3a619a9ad294a17825b1d4cd051a6fb  001_schema_roles.sql
dfeaf2e8c529151f6a07100ecdec886787e70c46cf42116e1c28c93cea9e4159  002_fixtures.sql
e5ffe0039054dbb9d5c23ed688e1fdf1d8f573cc9624d801827d1ddb001f5d49  003_comparison.sql
d64ffa3d955d8c0a6a68f90aa3e2a42c0a1b3d08e089dd89334ce2815eccfa2d  run_tests.sh
```

## Not claimed

`F06` is not closed in the product. `SCHEMA_FIDELITY = SCOPED_EQUIVALENT`
(6 columns vs the real `leads`' 18; no `tenant_staff_*`, no product triggers,
migrations 001–038 not applied). `LARAVEL_WIRE_INTEGRATION = NOT_EXECUTED`.
`PGBOUNCER_POOLING = NOT_VERIFIED`. In-tenant existence oracle via
tenant-wide uniqueness: **OPEN**. Revocation inside an open transaction:
**NOT_VERIFIED**. The review in `README_REVIEW.md` is internal, not independent.
