# F06 ACTOR POC (POC02) — per-actor SQL identity anchor

**POC only. Not production code. Not wired to Laravel, to any migration, or to
any protected environment (G2 / RM02 / DEV / Old TEST / scratch / host:5432).
F06 is NOT closed in the product by anything in this directory.**

POC01 (`../f06-poc/`) proved a per-**tenant** SQL login stops cross-tenant
access even with every GUC forged, but its T06 showed that **actor**
impersonation inside one tenant still worked, because one SQL role still
served every staff member and `app.user_id` remained a forgeable GUC.

POC02 closes that specific gap in a sandbox: identity is anchored on the
**authenticated SQL login** (`session_user`), resolved through a mapping table
that no login role can read or write.

## The anchor

```
leads_actor / admin_grants RLS policies
        │
        ├── public.app_actor_tenant()    ┐ SECURITY DEFINER, owner = poc02_owner
        ├── public.app_actor_id()        │ SET search_path = pg_catalog, public
        └── public.app_actor_is_admin()  ┘ keyed on  session_user
                     │
                     └── public.actor_identity_map   (owner poc02_owner,
                          role_name → tenant/actor/status/is_admin)
                          zero privileges for every login role
```

No policy and no resolver reads `app.tenant_id`, `app.user_id` or
`app.context_mode`. Those GUCs are still *settable* by an attacker — they are
simply not consulted, which is what AT04/AT06/AT09 demonstrate.

`session_user` rather than `current_user` is deliberate and verified, not
assumed (AT11): inside a `SECURITY DEFINER` function `current_user` becomes the
function **owner**, so keying on it there resolves every caller to
`poc02_owner` — `003`'s `poc02_wrong_actor_tenant_via_current_user()` exists
purely to prove that trap returns NULL. `session_user` stays the login that
authenticated the session and is not moved by `SET ROLE` (which is denied
anyway, AT07).

## Files

| File | Role |
|---|---|
| `001_schema_roles.sql` | `poc02_owner` (NOLOGIN owner), 6 LOGIN roles, `actor_identity_map`, the three resolvers + identity probes, `leads_actor`, `admin_grants`, FORCE RLS, grants |
| `002_fixtures.sql` | synthetic fixtures: tenants A/B; actors A1 plain, A2 admin, A3 suspended, A4 plain peer, B1 plain; 5 leads; 1 admin grant |
| `003_comparison.sql` | the two weaker models for the differential proof: `leads_baseline_guc` (GUC anchor = today's product shape) and `leads_tenant_only` (POC01's anchor) |
| `run_tests.sh` | AT01–AT18 (60 assertions) + harness self-failure checks |
| `REPORT_EVIDENCE.md` | sanitized results for all three runs, sandbox identity, pre-fix failures |
| `README_REVIEW.md` | internal adversarial review of POC01's harness and what POC02 does differently |

## Re-running — on a NEW sandbox only

`run_tests.sh` refuses to run unless `current_database()` **and**
`system_identifier` match the expected sandbox (exit 98). Point it at a
protected database and it stops before executing a single test. Do not raise
that guard to make it run somewhere else.

1. Create fresh, uniquely named Docker resources (never reuse POC01/G2/RM02
   names), publish only on `127.0.0.1` with a port you verified is free, and
   start `postgres:16` **from a locally present image** (no pulls).
2. Harden `pg_hba.conf` inside that new container only: the stock image ships
   `trust` for `127.0.0.1`/`::1`/local, which would silently invalidate every
   adversarial case. POC02 sets all of them to `scram-sha-256` and verifies a
   password-less connection is refused.
3. Generate one-time passwords locally, outside any Git repo, with tight file
   permissions. Never commit, print, or paste them.
4. Apply `001` (needs `-v pw_a1=… pw_a2=… pw_a3=… pw_a4=… pw_b1=… pw_shared=…`),
   then `002`, then `003`, as superuser.
5. Export `PGPOC2_SUPERUSER_PW`, `PGPOC2_A1_PW`, `PGPOC2_A2_PW`,
   `PGPOC2_A3_PW`, `PGPOC2_A4_PW`, `PGPOC2_B1_PW`, `PGPOC2_SHARED_PW` and run
   `HOST=… PORT=… DB=… EXPECT_SYSID=… bash run_tests.sh`.

Every test runs inside `BEGIN … ROLLBACK`; the fixture fingerprint is asserted
identical before and after each run, so repeated runs leave the sandbox
unchanged.

## Known limits — do not overclaim

- `SCHEMA_FIDELITY = SCOPED_EQUIVALENT`. `leads_actor` has 5 columns; the real
  `leads` table has 14, plus triggers, audit tables, `tenant_staff_*` identity
  tables and SECURITY DEFINER auth functions that are **not** reproduced here.
  Migrations 001–038 were not applied.
- `LARAVEL_WIRE_INTEGRATION = NOT_EXECUTED`. Nothing here is connected to the
  application. The hard part of adopting this model — binding an HTTP session
  to one SQL login per actor — is untouched.
- `PGBOUNCER_POOLING = NOT_VERIFIED`. No pooler exists in this sandbox (and
  none is documented in the product). A transaction pooler in front of
  per-actor logins is a real open design question, not a solved one.
- `DEFERRED_REAL_SYSTEM_INTEGRATION`: provisioning, rotation and revocation of
  one LOGIN per (tenant, actor); connection count and pool fan-out as actors
  grow; what happens to the anchor during password rotation; how admin status
  changes propagate. None of this is designed or costed here.
- Docker's default `bridge` network does **not** block egress. This sandbox can
  reach the internet; it simply never does. All data in it is synthetic.
