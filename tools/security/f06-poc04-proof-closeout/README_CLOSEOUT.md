# F06 ACTOR POC04 — PROOF CLOSEOUT (SECURITY-POC04-PROOF-CLOSEOUT-01)

**POC only.** Nothing here is production code, nothing is wired to Laravel,
no migration was touched, and F06/T4b remain OPEN in the product. This
directory closes four proof-harness gaps that an independent (Codex) review
found in `../f06-actor-poc-final-harden/` (POC04): F3 (fingerprint
serialization ambiguity), F5 (AUTH gate did not prove the actually-loaded
HBA *method*, only absence of `trust`), F6 (H06a's claim was inaccurate,
H06b's marker precondition could be skipped, H06c's kill was unverified),
and H03 (nothing enforced that the intra-tenant oracle finding could not
silently vanish/duplicate/change). It is a literal copy-and-patch of POC04,
not a new identity model — see `DIFF_FROM_POC04.md` for the exact patch.

## Scope

- Patched: `003_comparison.sql`, `run_tests.sh` only.
- Untouched copies (SHA-256 identical to POC04's originals): `001_schema_roles.sql`,
  `002_fixtures.sql`, `README.md`, `README_REVIEW.md`, `REPORT_EVIDENCE.md`.
- POC01/POC02/POC03/POC04 originals were never written to (verified by hash
  before and after — see `REPORT_EVIDENCE_CLOSEOUT.md`).
- F1 (SQLSTATE classification), F2 (fingerprint RC-capture contract) and F4
  (effective PUBLIC EXECUTE) were reviewed but NOT modified — no defect was
  demonstrated in them for this task's four-item scope.

## Sandbox used

A brand-new, uniquely-named, `--internal` Docker network with **no published
host port**, a dedicated volume, and the locally-present `postgres:16` image
(no pull): container `daleel-f06-poc04-closeout-znnlfh-pg`, network
`daleel-f06-poc04-closeout-znnlfh-net`, volume
`daleel_f06_poc04_closeout_znnlfh_pg_data`, database
`daleel_f06_poc04_closeout_znnlfh_synthetic`. Full identity, resource limits
and egress-block proof are in `REPORT_EVIDENCE_CLOSEOUT.md`. Every HBA rule
was forced to `scram-sha-256` before any adversarial test ran; `0` trust
rules were verified before AND after every run.

## Re-running

Same contract as POC04 (`README.md` §"Re-running"), with two additions:

- `EXPECT_SYSID` must be this sandbox's own `system_identifier` — see
  `REPORT_EVIDENCE_CLOSEOUT.md`. The script refuses to run against any other
  database (`exit 98`).
- The manifest is now 76 scenarios (`AUTH01..AUTH08`, `A`, `B`, `C`, `D`,
  `F1a..F1d`, `F2a..F2c`, `F3a`, `F3b`, `F4a`, `F4b`, `F5a`, `G01`, `G02`,
  `H01..H06c`) — never run it against POC01/POC02/POC03/POC04's databases or
  against G2/acceptance/DEV/scratch; the identity guard will refuse (`exit
  98`) but do not rely on that as the only safeguard.

## Known limits — unchanged from POC04, still true here

Everything POC04's `README.md` §"Known limits" states is still true
verbatim in this closeout (6-column `leads_actor` vs the product's 18;
no UNIQUE constraint on the real `leads` table so H03's intra-tenant oracle
is a POC-only property, not a demonstrated product defect; ownership
immutability here contradicts `LeadService::assignLead()`'s authorised
`ALL_TENANT` reassignment and must not be carried into the product;
`LARAVEL_WIRE_INTEGRATION`/`PGBOUNCER_POOLING` = not executed/not verified;
a compromised PHP process holding all credentials is outside the threat
model). One addition from this task's own testing: `H06c`'s backend-reap
timing is bounded by the remainder of `pg_sleep(30)` (PostgreSQL does not
poll the client socket during a plain `pg_sleep`), measured at ~30-31s —
this does NOT weaken the safety claim (status/fingerprint are MVCC-correct
immediately via a separate connection) but is now stated rather than assumed.

## Second delta — SECURITY-POC04-TARGETED-GATE-01 (F5 + F6c only)

An independent Codex review of this directory found F3/F6a/F6b/H03 sound
(PASS_SOURCE/PASS_SCOPED) but flagged two real proof gaps, both fixed in
`run_tests.sh` only (see `DIFF_FROM_POC04.md` for the exact patch and
`REPORT_EVIDENCE_TARGETED_GATE.md` for the evidence):

- **F5**: the HBA matcher ignored the `netmask` column and treated
  `address='0.0.0.0'` as a universal match; it now evaluates real network
  membership (`address & netmask`) for every candidate row in true
  `line_number` order and fails closed on anything it cannot parse
  (`samehost`/`samenet`/unparseable).
- **F6c**: `kill`/`wait` exit codes were discarded, so a child that exited
  naturally right before the signal could still read back as a false
  "SIGKILL proof". `kill`'s and `wait`'s own exit codes are now required
  (`kill_rc==0`, `wait_rc==137`), with a `kill -0` liveness precheck
  immediately before signalling.

`REPORT_EVIDENCE_CLOSEOUT.md` (the first delta's evidence) is kept as
**historical** — it predates this second fix and must not be read as
describing the current F5/F6c behavior.

## Stop condition

This task closes six named proof-harness gaps across two deltas and nothing
else. It does not remediate F06 or T4b in the product, does not touch
migrations, does not wire anything to Laravel, and does not commit to Git.
See `REPORT_EVIDENCE_TARGETED_GATE.md` for the current (F5/F6c) evidence
record and verdict, and `REPORT_EVIDENCE_CLOSEOUT.md` for the historical
first delta (F3/F5/F6/H03 as they stood before this second fix).
