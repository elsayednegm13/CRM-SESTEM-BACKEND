# F06 ACTOR POC — HARDENED (POC03)

**POC only.** Not production code, not wired to Laravel, no migration, and it
closes **nothing** in the product. `F06` stays OPEN; `T4b` and `F16` are out of
scope. POC01 (`../f06-poc/`) and POC02 (`../f06-actor-poc/`) are untouched
originals — this is a separate, copied-and-fixed line.

## Why this exists

An independent review of POC02 returned `POC02_HARNESS_REVIEW = FAIL`,
`FALSE_POSITIVE_RISK = HIGH`, `POC02_RLS_REVIEW = PARTIAL`. This directory
addresses those findings and re-runs the proof under a harness designed so a
broken test cannot read as a security pass. See `README_REVIEW.md` for the
finding-by-finding record and `REPORT_EVIDENCE.md` for results.

## What the model is

Identity is anchored on the **authenticated SQL login** (`session_user`),
resolved through a mapping table that no login role can read or write:

```
LOGIN (one per tenant+actor)
   └── session_user
         └── SECURITY DEFINER resolvers, owner h01_owner,
             SET search_path = pg_catalog, public
               ├── public.app_actor_tenant()
               ├── public.app_actor_id()
               └── public.app_actor_is_admin()
                     └── public.actor_identity_map   (owner h01_owner;
                          zero privileges for every login role)
                            └── RLS on leads_actor / admin_grants
```

No policy or resolver reads `app.tenant_id`, `app.user_id` or
`app.context_mode`. Those GUCs remain settable by an attacker and are simply
never consulted.

Added over POC02:

- **Ownership/tenant immutability** — RLS `WITH CHECK` cannot compare OLD and
  NEW, so a `BEFORE UPDATE` trigger (`leads_actor_lock_ownership`) rejects any
  change to `owner_actor_id`, `tenant_id` or `id`, raising SQLSTATE `42501`
  so the refusal classifies as a privilege denial rather than a constraint
  error. `tenant_id` additionally has no column-level `UPDATE` grant.
  `owner_actor_id` *is* grantable on purpose, so the trigger is a live control
  and not unreachable dead code.
- **No client-chosen primary key** — `id uuid DEFAULT gen_random_uuid()` and
  no `INSERT` privilege on the `id` column, which removes the key-collision
  existence oracle.
- **Deliberate `UNIQUE (tenant_id, code)`** — kept so the *remaining*
  in-tenant existence channel is measured instead of hidden (see
  `EXISTENCE_ORACLE` below).

## Files

| File | Role |
|---|---|
| `001_schema_roles.sql` | owner role, 6 LOGIN roles, anchor table, resolvers + identity probes, `leads_actor`, `admin_grants`, FORCE RLS, ownership trigger, column-level grants |
| `003_comparison.sql` | the two weaker anchors (GUC / tenant-only) for the differential, plus `h01_fingerprint()` |
| `002_fixtures.sql` | synthetic fixtures (tenants A/B; A1 plain, A2 admin, A3 suspended, A4 plain peer, B1 plain) |
| `run_tests.sh` | 63 scenarios under an enforced MANIFEST, SQLSTATE-classified denials, auth proofs, negative controls |
| `README_REVIEW.md` | every review finding → patch → negative proof → status |
| `REPORT_EVIDENCE.md` | sanitized evidence, sandbox identity, runs, pre-fix failures |

Apply order: `001` → `003` → `002` (`003` creates the tables that
`h01_fingerprint()` reads and `002` populates).

## Re-running — on a NEW sandbox only

`run_tests.sh` refuses to run unless `current_database()`,
`system_identifier` **and** `session_user` match what it expects (exit 98), and
it aborts if the baseline fingerprint cannot be computed (exit 96). Do not
raise that guard to make it run elsewhere. Never point it at G2 (55439),
acceptance/RM02/DEV/Old TEST (55433/55437), scratch (55432), POC01 (55441) or
the stopped POC02 (55443).

1. Create fresh uniquely-named Docker resources. Prefer `--internal` for the
   network and **publish no host port** — this sandbox did both, and egress
   was then *measured* blocked rather than assumed.
2. Use a locally present `postgres:16` image; do not pull.
3. In the new container only, set every `pg_hba.conf` rule to
   `scram-sha-256` (the stock image ships `trust` for local/loopback, which
   would void every adversarial result) and verify
   `SELECT count(*) FROM pg_hba_file_rules WHERE auth_method='trust'` is `0`.
4. Generate one-time passwords locally, outside any Git repo, with tight
   permissions; never commit, print or paste them.
5. Apply `001` with `-v pw_a1=… pw_a2=… pw_a3=… pw_a4=… pw_b1=… pw_shared=…`,
   then `003`, then `002`, as superuser.
6. Export `H01_SU_PW H01_A1_PW H01_A2_PW H01_A3_PW H01_A4_PW H01_B1_PW
   H01_SHARED_PW` and run `HOST=… PORT=… DB=… EXPECT_SYSID=… bash run_tests.sh`.

Every mutating scenario runs inside `BEGIN … ROLLBACK`, and the full
fingerprint (rows, owners, role attributes, memberships, table **and** column
ACLs, policies, constraints, triggers, function security) is asserted
identical before and after each run. `H06` is the one scenario that commits:
it suspends `h01_a4`, observes the denial, then restores `ACTIVE`; the final
fingerprint check is what proves the restore happened.

## Known limits — do not overclaim

- `SCHEMA_FIDELITY = SCOPED_EQUIVALENT`. `leads_actor` has 6 columns. The real
  `leads` table (migration `2026_10_23_000036_create_leads.php`) has **18**
  columns, plus the real `tenant_staff_*` identity tables, triggers, audit
  tables and SECURITY DEFINER auth functions — none reproduced. Migrations
  001–038 were not applied.
- `EXISTENCE_ORACLE`: the client-chosen-key channel is **mitigated and proved**
  (H01/H02). A tenant-wide `UNIQUE` on a client-supplied business value
  (`code`) **remains an in-tenant existence oracle** — H03 measures it
  returning `23505` for a row the actor cannot see. Cross-tenant the same
  probe is stopped by RLS first (H04). This is recorded as **OPEN, scoped to
  inside one tenant**; it is not papered over by suppressing the message.
- `LARAVEL_WIRE_INTEGRATION = NOT_EXECUTED`. Binding an HTTP session to one
  SQL login per actor, credential provisioning/rotation/revocation,
  connection fan-out and pooling are all untouched
  (`DEFERRED_REAL_SYSTEM_INTEGRATION`).
- `PGBOUNCER_POOLING = NOT_VERIFIED` — no pooler here, none documented in the
  product.
- A compromised PHP process holding *all* actor credentials is **not**
  defended against by anything here; single-connection isolation does not
  imply process-level isolation.
- `H06` proves revocation is visible to the **next statement**. Revocation
  *inside an already-open transaction* was not tested (`NOT_VERIFIED`), and
  the role's password stays valid after an actor is suspended — the denial
  comes from the mapping, not from the credential.
