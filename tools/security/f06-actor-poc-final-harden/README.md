# F06 ACTOR POC — FINAL HARDEN (POC04)

**POC only.** Nothing here is production code, nothing is wired to Laravel, no
migration was touched, and **F06 is not closed in the product**. T4b and F16
remain out of scope. POC01 / POC02 / POC03 are untouched originals; this is a
separate copied-and-fixed line created for SECURITY-POC03-FINAL-HARDEN-01.

## Why this exists

The independent (Codex) review of POC03 returned `PARTIAL` with
`POC03_HARNESS_REVIEW=FAIL` and seven findings (F1–F7). This directory closes
F1–F6 with negative proofs and documents F7 as an acceptance constraint, not a
product change. `README_REVIEW.md` has the finding-by-finding record;
`REPORT_EVIDENCE.md` has the sanitized runs.

## The model (unchanged in principle from POC03)

Identity is anchored on the **authenticated SQL login** (`session_user`),
resolved through a mapping table no login role can read or write:

```
LOGIN per (tenant, actor)  ──session_user──►  SECURITY DEFINER resolvers
                                              (owner fh_owner,
                                               SET search_path=pg_catalog,public)
                                                 ├─ public.app_actor_tenant()
                                                 ├─ public.app_actor_id()
                                                 └─ public.app_actor_is_admin()
                                                      └─ public.actor_identity_map
                                                         (owner fh_owner; zero
                                                          privileges for logins)
                                                            └─ RLS: leads_actor,
                                                                    admin_grants
```

No policy and no resolver reads `app.tenant_id`, `app.user_id` or
`app.context_mode`; those GUCs stay settable and are simply never consulted.

## What changed versus POC03

| Area | Change |
|---|---|
| SQLSTATE classification | a fixed NON_SECURITY set is rejected **before** the expected code is consulted, so a test declaring e.g. `23505` can never pass; a denial must also match a declared **kind** (`DENY_ACL` / `DENY_RLS` / `DENY_TRIGGER` / `DENY_OWNER`) derived from the server message |
| Fingerprint read | `fp_read()` is never called in a command substitution; it writes stdout/stderr/rc to files and enforces a contract (rc=0 **and** 64 lowercase hex) |
| Fingerprint coverage | components `01..17` declared explicitly (now including `created_at`, column defaults, column types/notnull, `polpermissive`, function bodies, trigger function bodies, schema ACL, default privileges, effective ACLs via `acldefault`), plus an explicit NOT_COVERED list |
| Effective PUBLIC EXECUTE | `aclexplode(COALESCE(proacl, acldefault('f', proowner)))`, so a function left with PostgreSQL's default ACL is detected; schema USAGE/CREATE checked too |
| AUTH gate | a standalone gate runs **before any mutating scenario** and exits `70` if any matrix login's correct password fails, a missing or wrong password is accepted, `password_encryption` is not scram, the transport is not the expected in-container TCP endpoint, or any effective HBA rule that could match the test path is `trust` |
| Revocation (H06) | split into `H06a` (in-transaction, rollback-guaranteed), `H06b` (cross-connection using the dedicated actor `fh_a5`, with an idempotent recovery marker and a verified restore) and `H06c` (SIGKILL mid-transaction leaves the mapping untouched). A suspended `fh_a5` with no marker makes the run exit `95` as `BLOCKED_CLEANUP_REQUIRED` |
| Fixtures | `created_at` pinned to fixed timestamps (the fingerprint now covers it); dedicated actor `fh_a5` added so reference actors are never suspended |

## Files

| File | Role |
|---|---|
| `001_schema_roles.sql` | owner role, 7 LOGIN roles, anchor table, resolvers + probes, `leads_actor`, `admin_grants`, FORCE RLS, ownership trigger, column-level grants |
| `003_comparison.sql` | the two weaker anchors (GUC / tenant-only), `fh_effective_public_execute()`, `fh_effective_schema_acl()`, and `fh_fingerprint()` with declared coverage |
| `002_fixtures.sql` | synthetic fixtures with pinned timestamps |
| `run_tests.sh` | 72 scenarios under an enforced manifest, AUTH gate, SQLSTATE+kind classifier, fingerprint contract, F1/F2/F4/F5 negative controls, H06a/b/c |
| `README_REVIEW.md` | F1–F7: finding → patch → negative proof → status |
| `REPORT_EVIDENCE.md` | sandbox identity, auth proofs, runs, mutants, fingerprint sensitivity |

Apply order: **`001` → `003` → `002`** (`003` defines the fingerprint over the
comparison tables, `002` fills every table).

## Re-running — on a NEW sandbox only

The harness refuses to run unless `current_database()`, `system_identifier`
and `session_user` all match (exit `98`), the baseline fingerprint satisfies
its contract (exit `96`), `fh_a5` is `ACTIVE` (exit `95`), and the AUTH gate
passes (exit `70`). Never point it at G2 (55439), acceptance/RM02/DEV/Old TEST
(55433/55437), scratch (55432), POC01 (55441), POC02 (55443) or POC03.

1. New uniquely-named Docker resources; `--internal` network and **no
   published host port** (this sandbox used both, and egress was then
   *measured* blocked); locally present `postgres:16`, no pull; `--memory=384m
   --cpus=1`.
2. In the new container only, set **every** `pg_hba.conf` rule to
   `scram-sha-256` and verify
   `SELECT count(*) FROM pg_hba_file_rules WHERE auth_method='trust'` is `0`.
3. One-time passwords generated locally outside Git with `umask 077`; never
   printed, committed or passed through a shell history you keep. Supply them
   to `001` with `-v pw_a1=… pw_a2=… pw_a3=… pw_a4=… pw_a5=… pw_b1=…
   pw_shared=…` (psql variables only work from a file or stdin, not with `-c`).
4. Export `FH_SU_PW FH_A1_PW FH_A2_PW FH_A3_PW FH_A4_PW FH_A5_PW FH_B1_PW
   FH_SHARED_PW` and run `HOST=… PORT=… DB=… EXPECT_SYSID=… bash run_tests.sh`.

Every mutating scenario runs inside `BEGIN … ROLLBACK`. `H06b` is the only
scenario that commits; it is confined to `fh_a5`, guarded by a recovery marker,
and the final fingerprint comparison is what proves the restore.

## Known limits — do not overclaim

- `SCHEMA_FIDELITY = SCOPED_EQUIVALENT`. `leads_actor` has 6 columns; the real
  `leads` (migration `2026_10_23_000036`) has **18**. No `tenant_staff_*`
  tables, no product triggers, no audit tables, migrations 001–038 not applied.
- **The product has no UNIQUE constraint on `leads` at all** (only three
  non-unique indexes). The `UNIQUE (tenant_id, code)` here is a POC construct
  kept deliberately so the existence channel is measurable; the intra-tenant
  oracle it exposes (`H03`) is therefore a property of this POC, not a
  demonstrated product defect. It stays `OPEN` pending an owner decision on any
  future unique business key.
- **Ownership immutability here contradicts the product.** `LeadService::assignLead()`
  permits authorised re-assignment for `ALL_TENANT` holders and refuses it for
  `ASSIGNED`/`SELF`. The POC's blanket immutability must **not** be carried into
  the product contract.
- `LARAVEL_WIRE_INTEGRATION = NOT_EXECUTED`; credential provisioning, rotation,
  revocation, connection fan-out and pooling are untouched.
- `PGBOUNCER_POOLING = NOT_VERIFIED`.
- A compromised PHP process holding **all** actor credentials is outside the
  threat model and is not defended against.
- `H06b` has an inherent committed window between suspend and restore; the
  marker makes recovery idempotent but does not make the window disappear.
  Revocation inside an already-open transaction remains `NOT_VERIFIED`, and a
  suspended actor's password stays valid — the denial comes from the mapping,
  not from the credential.
