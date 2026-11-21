# F06 ACTOR POC (POC02) — sanitized evidence

No passwords, hashes, `PGPASSWORD` values, pgpass contents or environment
secrets appear in this file or in any file of this directory. All fixtures are
synthetic.

## Sandbox identity (all new, created for this task)

| Item | Value |
|---|---|
| container | `daleel-f06-actor-poc02-r2a7f3-pg` |
| container id | `cbf8914db0a21f6e7295d1aa54cfcbf1561b35ede353b59919a00ffb82a1b3ef` |
| network | `daleel-f06-actor-poc02-r2a7f3-net` (bridge, new) |
| network id | `10ff5b114861479e3fb2ad6a3b331be22456bc266122c74f90eb035b014900cc` |
| volume | `daleel_f06_actor_poc02_r2a7f3_pg_data` (new, only mount besides none) |
| database | `daleel_f06_actor_poc02_r2a7f3_synthetic` |
| DB OID | `16384` |
| system_identifier | `7700478534754992166` |
| PostgreSQL | 16.15 (Debian 16.15-1.pgdg13+2), from the already-present local `postgres:16` image — no pull |
| host binding | `127.0.0.1:55443` → container `5432` (loopback only) |
| container IP | `172.22.0.2` |
| limits | `--memory=384m --cpus=1` |

**Independence from protected environments** — distinct `system_identifier`
proves a different cluster in every case:

| Environment | system_identifier | status |
|---|---|---|
| **POC02 (this)** | `7700478534754992166` | created by this task |
| POC01 | `7700445040430698534` | untouched |
| G2 | `7700288866362540071` | untouched |
| acceptance cluster (RM02 / DEV / Old TEST) | `7699972247235194919` | untouched |

Ports in use before this task — `55432` (scratch), `55433`/`55437`
(acceptance), `55439` (G2), `55441` (POC01) — were all left alone; `55443` was
verified free before publishing. `55442` was *not* assumed available; it was
checked and simply not used.

## Authentication hardening (done inside this sandbox only)

The stock `postgres:16` image ships `trust` for `local`, `127.0.0.1/32` and
`::1/128`. Every adversarial result would be void under `trust`, so
`pg_hba.conf` in **this container only** was rewritten to `scram-sha-256` for
all of those (including the `replication` lines) and reloaded with
`pg_ctl reload`.

Verified afterwards:

```
pg_hba_file_rules: 7 rules, auth_method='trust' count = 0
show password_encryption  ->  scram-sha-256
psql without password     ->  "fe_sendauth: no password supplied"  (refused)
psql with password        ->  auth_ok
```

Every adversarial case below ran as a real password-authenticated `LOGIN`
role. `postgres` (superuser) was used only for fixture creation and for
counting rows in the fingerprint, never to produce a security verdict.

## Network egress — stated honestly

Docker's default `bridge` driver does **not** block outbound traffic. Measured
from inside the container: DNS resolves and an outbound TCP connection to
`1.1.1.1:443` succeeds. So **egress is possible and is NOT proven blocked**.
Mitigating facts: nothing in the POC initiates outbound traffic, no image was
pulled, and all data in the database is synthetic.

## Results — 3 independent runs, identical

`PASS=60 FAIL=0 HARNESS_ERRORS=0 OVERALL=PASS_SCOPED` on each of the three
runs; the `RESULTS` block was byte-identical across runs (verified with
`diff`); fixture fingerprint `5|5|1|3|3` before and after every run.

```
PREFLIGHT_OK target=daleel_f06_actor_poc02_r2a7f3_synthetic|7700478534754992166 host=127.0.0.1 port=5432
FIXTURE_FINGERPRINT_BEFORE=5|5|1|3|3

AT01a    PASS     exp=2                      act=2                        rc=0   as poc02_a1
AT01b    PASS     exp=0                      act=0                        rc=0   as poc02_a1
AT02a    PASS     exp=4                      act=4                        rc=0   as poc02_a2
AT02b    PASS     exp=1                      act=1                        rc=0   as poc02_a2
AT02c    PASS     exp=1                      act=1                        rc=0   as poc02_a2
AT02d    PASS     exp=1                      act=1                        rc=0   as poc02_a2
AT03a    PASS     exp=1                      act=1                        rc=0   as poc02_b1
AT03b    PASS     exp=0                      act=0                        rc=0   as poc02_b1
AT04a    PASS     exp=0                      act=0                        rc=0   as poc02_a1
AT04b    PASS     exp=0                      act=0                        rc=0   as poc02_a1
AT04c    PASS     exp=2                      act=2                        rc=0   as poc02_a1
AT05a    PASS     exp=deny                   act=0 rows affected          rc=0   as poc02_a1
AT05b    PASS     exp=deny                   act=rls/acl-error            rc=1   ERROR:  new row violates row-level security policy for table "admin_grants"
AT05c    PASS     exp=deny                   act=0 rows affected          rc=0   as poc02_a1
AT06a    PASS     exp=0                      act=0                        rc=0   as poc02_a1
AT06b    PASS     exp=deny                   act=0 rows affected          rc=0   as poc02_a1
AT06c    PASS     exp=deny                   act=rls/acl-error            rc=1   ERROR:  new row violates row-level security policy for table "leads_actor"
AT07a    PASS     exp=sql-error              act=denied                   rc=1   ERROR:  permission denied to set role "poc02_a2"
AT07b    PASS     exp=sql-error              act=denied                   rc=1   ERROR:  permission denied to set role "poc02_b1"
AT07c    PASS     exp=sql-error              act=denied                   rc=1   ERROR:  permission denied to set role "poc02_owner"
AT07d    PASS     exp=false,false,false      act=false,false,false        rc=0   as poc02_a1
AT07e    PASS     exp=0                      act=0                        rc=0   as postgres
AT08a    PASS     exp=1                      act=1                        rc=0   as poc02_a3
AT08b    PASS     exp=0                      act=0                        rc=0   as poc02_a3
AT08c    PASS     exp=0                      act=0                        rc=0   as poc02_a3
AT08d    PASS     exp=NULL                   act=NULL                     rc=0   as poc02_a3
AT09a    PASS     exp=2                      act=2                        rc=0   as poc02_a1
AT09b    PASS     exp=2                      act=2                        rc=0   as poc02_a1
AT09c    PASS     exp=0                      act=0                        rc=0   as poc02_a1
AT10a    PASS     exp=2                      act=2                        rc=0   as poc02_a1
AT10b    PASS     exp=0                      act=0                        rc=0   as poc02_a1
AT11a    PASS     exp=poc02_a1,poc02_a1      act=poc02_a1,poc02_a1        rc=0   as poc02_a1
AT11b    PASS     exp=poc02_owner,poc02_a1   act=poc02_owner,poc02_a1     rc=0   as poc02_a1
AT11c    PASS     exp=NULL                   act=NULL                     rc=0   as poc02_a1
AT12a    PASS     exp=0                      act=0                        rc=0   as poc02_a1
AT12b    PASS     exp=1                      act=1                        rc=0   as poc02_a4
AT12c    PASS     exp=0                      act=0                        rc=0   as poc02_a4
AT13a    PASS     exp=1                      act=1                        rc=0   as poc02_tenant_a_shared
AT13b    PASS     exp=1                      act=1                        rc=0   as poc02_tenant_a_shared
AT13c    PASS     exp=1                      act=1                        rc=0   as poc02_tenant_a_shared
AT13d    PASS     exp=0                      act=0                        rc=0   as poc02_tenant_a_shared
AT13e    PASS     exp=0                      act=0                        rc=0   as poc02_a1
AT14a    PASS     exp=0                      act=0                        rc=0   as postgres
AT14b    PASS     exp=true                   act=true                     rc=0   as poc02_a1
AT14c    PASS     exp=false,false,false      act=false,false,false        rc=0   as poc02_a1
AT14d    PASS     exp=poc02_owner            act=poc02_owner              rc=0   as postgres
AT17a    PASS     exp=2                      act=2                        rc=0   as poc02_a1
AT17b    PASS     exp=2                      act=2                        rc=0   as poc02_a1
AT17c    PASS     exp=2                      act=2                        rc=0   as poc02_a1 (2 stmts)
AT18a    PASS     exp=sql-error              act=denied                   rc=1   ERROR:  permission denied for table actor_identity_map
AT18b    PASS     exp=sql-error              act=denied                   rc=1   ERROR:  permission denied for table actor_identity_map
AT18c    PASS     exp=sql-error              act=denied                   rc=1   ERROR:  permission denied to create role (needs CREATEROLE)
AT18d    PASS     exp=sql-error              act=denied                   rc=1   ERROR:  permission denied to grant role "poc02_a2" (needs ADMIN option)
AT18e    PASS     exp=sql-error              act=denied                   rc=1   ERROR:  permission denied to alter role (needs SUPERUSER)
AT18f    PASS     exp=sql-error              act=denied                   rc=1   ERROR:  must be owner of table leads_actor
AT18g    PASS     exp=sql-error              act=denied                   rc=1   ERROR:  must be owner of table leads_actor
AT15     PASS     exp=5|5|1|3|3              act=5|5|1|3|3                rc=0   no fixture drift
AT16a    PASS     exp=rc!=0                  act=rc=2                     rc=2   bad port rejected
AT16b    PASS     exp=rc!=0                  act=rc=2                     rc=2   bad db rejected
AT16c    PASS     exp=rc=98                  act=rc=98                    rc=98  identity guard aborts

PASS=60 FAIL=0 HARNESS_ERRORS=0
FIXTURE_FINGERPRINT_AFTER=5|5|1|3|3
PGBOUNCER_POOLING=NOT_VERIFIED (no pooler in this sandbox)
OVERALL=PASS_SCOPED
```

## What the key cases actually establish

- **AT04/AT05** — `poc02_a1`, authenticated with its own real password, sets
  `app.context_mode`/`app.tenant_id`/`app.user_id` to A2's values and still
  reads `0` rows from `admin_grants` and `0` of A2's leads; its admin writes
  are refused either by an explicit RLS error or by `0` rows affected. **This
  is the gap POC01's T06 left open.**
- **AT06** — the same credential forging tenant B gets `0` rows and no write.
  Tenant isolation from POC01 is preserved under the new actor anchor.
- **AT13 (differential)** — on the *same* database: the GUC-anchored model
  leaks across tenants (AT13a) and across actors (AT13b), POC01's tenant-only
  anchor blocks tenants (AT13d) but still leaks across actors (AT13c), and the
  new model blocks the actor read (AT13e). The three models differ exactly
  where the theory says they should.
- **AT11** — measured, not assumed: inside `SECURITY DEFINER`,
  `current_user = poc02_owner` while `session_user = poc02_a1`; the
  deliberately wrong resolver keyed on `current_user` returns `NULL`.
- **AT10** — a `pg_temp` function named `app_actor_tenant()` plus
  `search_path = pg_temp, public` does not redirect the policy; A1 still sees
  exactly its own 2 rows, and a `pg_temp.app_actor_is_admin()` returning
  `true` yields `0` admin rows.
- **AT08** — the suspended actor A3 *authenticates successfully* (`SELECT 1`
  → `1`), which is what makes its `0`-row results an authorization denial
  rather than a login failure; `app_actor_tenant()` returns `NULL` for it.
- **AT18** — A1 cannot read or write `actor_identity_map`, cannot create
  roles, cannot grant itself another role, cannot make itself superuser, and
  cannot disable RLS or add a policy on `leads_actor`.
- **AT16** — the harness fails loudly on a bad port, a nonexistent database,
  and a wrong expected `system_identifier` (exit 98), so a green run cannot be
  the result of a broken harness.

## Not claimed

`F06` is not closed in the product. `SCHEMA_FIDELITY = SCOPED_EQUIVALENT`
(5-column `leads_actor`, no triggers, no `tenant_staff_*`, migrations 001–038
not applied). `LARAVEL_WIRE_INTEGRATION = NOT_EXECUTED`.
`PGBOUNCER_POOLING = NOT_VERIFIED`. Provisioning, rotation, revocation,
connection fan-out and HTTP-session→SQL-login binding are
`DEFERRED_REAL_SYSTEM_INTEGRATION`.
