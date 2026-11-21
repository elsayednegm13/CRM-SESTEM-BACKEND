# F06 POC — Sanitized Test Evidence

Sandbox: container `daleel-f06-poc01-pg-7e21poc01`, network
`daleel-f06-poc01-net-7e21poc01`, volume `daleel_f06_poc01_pg_data_7e21poc01`,
database `daleel_f06_poc01_synthetic`, PostgreSQL 16.15,
`system_identifier = 7700445040430698534` (distinct from G2's
`7700288866362540071` and the RM02 acceptance cluster's
`7699972247235194919` — confirmed independent, not a reused cluster).
Port `127.0.0.1:55441` published (loopback only); internal container port
`5432` used for the test harness itself. `pg_hba.conf` hardened in this
sandbox to require `scram-sha-256` over TCP for `127.0.0.1/::1` (the stock
image ships `trust` for loopback, which would have invalidated every
adversarial test below — this was fixed before any test ran).

All adversarial/legitimate SQL below ran as real password-authenticated
`LOGIN` roles over TCP (`poc_runtime_tenant_a`, `poc_runtime_tenant_b`,
`poc_runtime_shared`), never as `postgres`/superuser and never over the
local trust socket. Every statement ran inside `BEGIN ... ROLLBACK`; fixture
row counts were identical before and after all three runs
(`leads_baseline=2, leads_fixed=2, poc_actor_bound_grants=1,
poc_staff_memberships=4`).

Ran 3 times, identical results each time.

## T01–T12 results (run 3, verbatim summary)

```
T01                                           PASS
T02                                           PASS
T03b_BASELINE_VULN_REPRO                      CONFIRMED_VULNERABLE
T03                                           PASS
T04                                           PASS
T05_NO_CROSS_MEMBERSHIP                       PASS
T05                                           PASS
T06_ACTOR_ISOLATION                           OPEN_CONFIRMED_IMPERSONATION_SUCCEEDS
T07_LEGITIMATE_STILL_ALLOWED                  PASS
T07_MALFORMED_FAILS_CLOSED                    PASS
T07_SUSPENDED_FAILS_CLOSED                    PASS
T08_PGBOUNCER_POOLER                          NOT_VERIFIED_NO_POOLER_IN_POC
T08_SESSION_REUSE_GUC_NO_EFFECT               PASS
T09                                           PASS
T10                                           DOCUMENTED_IN_REPORT_SCOPED_EQUIVALENT
T11                                           PASS
T12                                           PASS
```

## What each result actually means

- **T01/T02 (PASS):** `poc_runtime_tenant_a`/`poc_runtime_tenant_b` can read
  and update their own tenant's `leads_fixed` row. The fix does not break
  legitimate access.
- **T03 (PASS):** `poc_runtime_tenant_a`, authenticated with its own real
  password, sets `app.tenant_id` to tenant B's id and `app.context_mode` to
  `TENANT` (the exact forging technique that works against the real
  `leads` table today) and gets **0 rows** back from `leads_fixed` — the
  forged GUC has no effect because the policy never reads it.
- **T03b (CONFIRMED_VULNERABLE, baseline contrast only, not scored into the
  fix):** the *same* forged-GUC technique against `leads_baseline`
  (today's real architecture, reproduced from scratch) returns **1 row**
  from tenant B. This is the control case proving the vulnerability is
  real and reproducible outside G2, not merely asserted.
- **T04 (PASS):** the same forged-GUC attempt against `leads_fixed`, this
  time trying `UPDATE`/`INSERT`/`DELETE` on tenant B's row, is rejected by
  Postgres with `ERROR: new row violates row-level security policy for
  table "leads_fixed"` — no row changed.
- **T05 / T05_NO_CROSS_MEMBERSHIP (PASS):** `poc_runtime_tenant_a` cannot
  `SET ROLE poc_runtime_tenant_b` (`ERROR: permission denied to set role`),
  and a live catalog check confirms zero `pg_auth_members` rows linking the
  two tenant roles in either direction.
- **T06_ACTOR_ISOLATION (OPEN — reported honestly, not swept under PASS):**
  `poc_runtime_tenant_a`, still authenticated only as tenant A's shared
  role, sets `app.user_id` to staff **A2** (the tenant's admin, a different
  person) and successfully reads A2's `company.administer` grant row from
  `poc_actor_bound_grants`. The tenant anchor fix does **not** close this:
  one SQL role still serves every staff member of a tenant, so actor
  identity is still a forgeable GUC. `ACTOR_ISOLATION = OPEN/NOT_PROVEN`,
  exactly as the task required this POC to admit if true.
- **T07 (PASS on all three sub-checks):** a *suspended* staff id
  (`...a003`) yields 0 rows from the actor-bound table (fails closed); an
  invalid, non-UUID `app.user_id` value raises a hard Postgres error
  (`invalid input syntax for type uuid`) rather than silently passing; and
  the legitimate tenant-A read still works immediately afterward (the
  fail-closed probes did not break the real path).
- **T08 (PASS / NOT_VERIFIED split):** within one already-open
  `poc_runtime_tenant_a` session, flipping `app.tenant_id` back and forth
  never changes what `leads_fixed` returns (always tenant A's own row) —
  because the policy never consults that GUC. **Connection pooling
  (PgBouncer) is not modeled in this POC and is explicitly marked
  `NOT_VERIFIED`**, per the product's own documented absence of a
  configured pooler.
- **T09 (PASS):** live, non-superuser catalog check confirms both tenant
  roles are `rolsuper=f, rolbypassrls=f, rolcreatedb=f, rolcreaterole=f,
  rolinherit=f`, and `leads_fixed` has `relforcerowsecurity = t`.
- **T10:** a source-level comparison against the real
  `2026_10_23_000036_create_leads.php` and `LeadService.php`, not a DB
  check — see "Known limits" in `README.md`: this POC uses a 5-column
  reduced schema (`id, tenant_id, name, assigned_staff_id, created_at`),
  not the full `leads` column set (phone/email/city/country/source/
  campaign/pipeline_stage/interest_level/estimated_value_minor/status/
  created_by_membership_id/last_contacted_at). No triggers, no
  `tenant_staff_users`/`tenant_staff_memberships` real tables, no
  `SECURITY DEFINER` functions were reproduced.
- **T11/T12 (PASS):** `leads_baseline=2, leads_fixed=2,
  poc_actor_bound_grants=1, poc_staff_memberships=4` before and after
  every one of the three full runs — no permanent fixture drift from any
  adversarial attempt.

## Explicitly NOT claimed

- This does not prove the real product's `leads` table is fixed — only
  that the anchor *technique* (per-tenant LOGIN role instead of a GUC)
  works against a schema that reproduces the real RLS predicate shape.
- This does not close actor-level impersonation within a tenant.
- This does not model connection pooling, provisioning/rotation of
  per-tenant roles at scale, or any Laravel-side change.
- `F06` is **not** `CLOSED` anywhere in this POC or its report.
