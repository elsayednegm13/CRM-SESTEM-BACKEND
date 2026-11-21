# P1: protected first Provider installation bootstrap

Status: **source-only implementation; runtime acceptance NOT_RUN; deployment is NOT authorized.**
Owner scope: DCRM-V1-P1-FIRST-PROVIDER-BOOTSTRAP-SOURCE, 2026-11-07.
Backend engineer and source QA hats only. UI, workspace handoff documents and final
portable evidence packaging are parent-owned. R13 remains LIVE_LOCKED; G3, RC1
and production remain NO-GO. No database, SQL engine, Docker, HTTP or browser was
used for this implementation.

## Contract and caller map

The parent-owned Super Admin setup UI/Next bridge calls the existing stateful
Laravel API topology, obtaining `/sanctum/csrf-cookie` and forwarding credentials,
exact approved Origin/Host and `X-XSRF-TOKEN` as for Provider login.

| Endpoint | Body | Success |
| --- | --- | --- |
| `POST /api/v1/super/setup/status` | JSON `{}` | 200 `data: {state: "AVAILABLE"}` |
| `POST /api/v1/super/setup` | JSON object containing `bootstrap_secret`, `email`, `password`, `password_confirmation` only | 201 `data: {status: "created", next: "LOGIN_AVAILABLE"}` |

## Optional MFA routine login and settings

Provider password login returns `AUTHENTICATED` for accounts without confirmed MFA and `MFA_REQUIRED` for confirmed accounts. The authenticated settings endpoints are `GET /api/v1/super/auth/mfa/settings`, `POST /api/v1/super/auth/mfa/settings/enroll/start`, and `POST /api/v1/super/auth/mfa/settings/enroll/confirm`. Start requires the current password and emits a short-lived, session-bound pending setup response; confirmation requires a real TOTP code, stores encrypted factor state through the existing MFA service, revokes the current session by rotating `auth_version`, and displays recovery codes once. High-risk Provider step-up remains a separate true-factor contract.

Both responses include `meta.request_id`, `Cache-Control: private, no-store` and
`Pragma: no-cache`. Creation returns no ID, email, password, proof or authenticated
session. Status is only an advisory check, not a reservation. Errors retain the
existing safe error envelope and request ID: 403 `PROVIDER_SETUP_DISABLED` for
invalid/expired configuration or proof; 409 `PROVIDER_SETUP_UNAVAILABLE` for
ineligibility or persistence failure; 422 `PROVIDER_SETUP_INPUT_INVALID` for
invalid JSON/identity; 419 for CSRF and 429 for rate limiting. Existing Host/Origin
denial codes remain unchanged. Existing exception response handling applies
private/no-store to errors throughout `/api/v1/super/*`.

Source path:
`routes/api.php` -> enclosing `RequireProviderOrigin` -> setup-only
`ForceProviderBootstrapCsrf` -> `RequireProviderBootstrapRequest` -> existing
`throttle:5,60` -> `ProviderBootstrapController` -> `ProviderBootstrapService` ->
existing `ProviderDatabaseContext::run`/`pgsql_provider` -> marker lock -> seal ->
identity and grants -> existing `SecurityAuditWriter::appendProviderMutation`.
Any committed insert in one of the seven attested tables also seals this marker.

The existing middleware priority/stateful stack still applies. A direct request
without an attached session fails 419 rather than manufacturing a session.
Setup explicitly runs the framework `ValidateCsrfToken` token verifier. Laravel
13's inherited `Sec-Fetch-Site: same-origin` shortcut, exclusions, read-verb and
unit-test skips are disabled for these two routes only. The setup layer does not
modify any existing login/MFA/issuer middleware or create a CSRF exemption.

## Explicit secure configuration

Server-only names, all disabled/empty by default:

- `PROVIDER_BOOTSTRAP_ENABLED`: explicitly `true` to allow the temporary flow.
- `PROVIDER_BOOTSTRAP_SECRET`: exactly 64 hexadecimal characters supplied by the
  owner through protected server-side secret management. **No real secret is
  generated, printed, checked in, placed in a URL or exposed to Next public env.**
  Documentation placeholder only: `<OWNER_SUPPLIED_64_HEX_SERVER_SECRET>`.
- `PROVIDER_BOOTSTRAP_EXPIRES_AT`: explicit integer Unix epoch seconds, strictly
  in the future, with at most 3600 seconds remaining at each check. No default
  or sliding TTL. Placeholder only: `<OWNER_CHOSEN_FUTURE_EPOCH_SECONDS>`.
- `PROVIDER_BOOTSTRAP_ALLOW_LOOPBACK_HTTP`: default false. HTTP is allowed only
  with this explicit flag, `APP_ENV=local`, and both API and Origin hosts in
  exact localhost/127.0.0.1/::1 or reserved `.localhost` loopback names.

External API requests must be HTTPS and have an HTTPS Origin. Host/Origin must
also pass both existing Provider and CORS allowlists. Trusted proxy forwarding,
secure cookies, Sanctum stateful domains and DNS/TLS remain operator deployment
prerequisites; this change does not widen trust in forwarded headers. Existing
HTTPS configuration does not automatically enable setup.

The secret comparison is case-sensitive `hash_equals` over the exact configured
hex text. The policy checks configuration/expiry before any Provider data access,
checks submitted proof before identity validation/data access, and checks proof
and expiry again after the marker lock. The creation-only global rate counter runs
after successful secret verification but before identity validation or Provider
data access; it is not an account existence lookup. Sensitive policy
and service arguments use `SensitiveParameter`. No new logger or external
compromised-password lookup is introduced. Owner passwords are 14-72 **UTF-8
bytes**, valid UTF-8 without NUL, with lower/upper case, number, symbol and exact
confirmation. Email uses the existing `EmailAddressNormalizer`.

Only creation attempts with a valid secret consume the existing cache-backed
fixed-hour global counter (20 attempts/hour); the post-increment count rejects
attempt 21 before identity validation or Provider data access. Invalid identity
with a valid secret still consumes a creation attempt. Status and invalid/missing
secrets do not spend this shared quota. Both routes retain existing per-IP
`throttle:5,60`, including secretless status and invalid-secret requests. The setup
request middleware performs configuration/transport checks only; global accounting
belongs to the creation service after constant-time secret verification.
Use a supported shared, atomic cache for multi-worker deployments; a per-process
array cache is not an acceptable production global limiter. Cache failure is not
an authorization fallback. These operational guarantees require runtime proof.

## Durable fresh-install attestation (migration 070, SOURCE ONLY)

New `2026_11_07_000070_create_provider_installation_setup.php` sorts after 069.
It requires an existing PostgreSQL migration transaction. It does not change any
existing table owner, RLS policy, ACL, role, issuer, authority or protected migration.

Before creating a marker it sets `SET LOCAL row_security = off` and locks all
seven relevant public tables against writes during attestation. It reads **every**
table, without early success/short-circuit emptiness:

- `provider_users`, `users`, `tenant_staff_users`, `tenants`;
- `security_audit_events`, `provider_control_operations`, `provider_approval_requests`.

Any row, including historical audit data without a current Provider root, produces
a SEALED marker. Missing tables/role/visibility/lock privileges abort the migration.
`row_security=off` is not BYPASSRLS: a principal subject to filtering must fail,
not attest filtered emptiness. Nothing grants new visibility to existing tables.
A privileged migration principal with legitimate full visibility is a prerequisite;
there is no runtime "assume fresh" recovery if migration cannot attest emptiness.

The new singleton has smallint primary key with `CHECK (id = 1)`, `sealed` boolean,
and nullable `completed_at`. Historical populated installs are sealed with unknown
completion time (`NULL`); successful setup seals with its transaction timestamp.
Runtime needs SELECT and UPDATE of `sealed, completed_at` only on this new table,
granted to `dl_provider`, with PUBLIC revoked. The migration rejects runtime
membership in the new marker's owner and removes default-ACL grants on this new
table before granting its narrow runtime privileges. No runtime INSERT, UPSERT, DELETE,
TRUNCATE, ID update or sequence grant is added. A narrowly scoped trigger rejects
reopening, repeat updates after sealing, deletion and truncation. The trigger
guard function is not SECURITY DEFINER and PUBLIC EXECUTE is revoked.

### Post-migration population invalidation (P1-SEC-01 remediation)

Initial attestation alone is insufficient: legitimate writes can populate an
installation after migration. Migration 070 therefore installs AFTER INSERT
**FOR EACH ROW** triggers on all seven attested tables, while the same table locks
are still held. Zero inserted rows cause no trigger call. Each row hook invokes
new `public.provider_installation_setup_seal_on_population()`, created and owned
by the migration principal. Its entire action is a fixed, qualified update of
marker row 1 from unsealed to sealed, with `clock_timestamp()` completion time.
It has no arguments, dynamic SQL, payload-dependent names, credential handling,
protected-table reads/writes, account creation or auth/issuer operation. An already
sealed or absent marker produces no update; absence still prevents setup.

This one new function is intentionally **SECURITY DEFINER**, with
`SET search_path = pg_catalog` and PUBLIC EXECUTE revoked. It is invoked by
attached triggers, not exposed as an application function or API. Its narrow
purpose is to remove bootstrap authority without granting protected-table or
marker privileges to every legitimate writer. No owner, ACL, RLS policy or role
on existing resources is changed; only these new insert hooks are added. No new
runtime privilege on any protected table is granted. The marker's permanent-seal
guard remains enforced, and later inserts cannot rewrite its completion time.

The definer is a privileged boundary: an untrusted owner, replace privilege,
schema ownership, inherited/default function grants or ability to disable triggers
would invalidate the source argument. Future DB acceptance must prove the actual
function owner is the trusted migration principal, fixed search path/body, no
PUBLIC or unexpected effective EXECUTE/replace grants, and trigger firing under
each legitimate non-owner writer **without** direct marker privileges. Trigger
creation/visibility failure must roll back the migration, not omit a hook. The
hook may add marker-lock waits/deadlocks to legitimate inserts; a trigger failure
can fail those writes closed. This availability tradeoff is intentional, not a
grant of read/create/auth authority. No ACL/trigger/definer runtime proof was run.

Committed population remains sealed even if its rows are later deleted. Population
and seal roll back together if that insert transaction fails. A supported insert
that commits before bootstrap must first acquire/update the same marker and makes
setup unavailable. If setup holds it first, the insert hook waits until setup
commits (then no-ops) or rolls back (then seals). This is commit-order serialization,
not a claim that source simulations prove PostgreSQL scheduling. Status can still
be momentarily AVAILABLE before a concurrent insert commits; creation rechecks.

**Provenance and privilege limits:** source cannot attest an actual database,
owner, inherited/default grants, role memberships, trusted public schema, search
path or historic backup provenance. Future acceptance must inspect effective ACLs
(including inherited privileges and effective removal of default grants), schema ownership and full-row visibility
before declaring this attestation valid. A malicious schema owner/superuser can
rewrite schema/disable triggers, and a restored or manually erased all-empty
pre-marker database is indistinguishable from a genuinely new database. This is
not a cryptographic installation-history or malicious-DBA defense. No such DB
checks were executed here. Operators must not reopen/replace a marker manually.

## Creation transaction, replay and supported paths

`ProviderDatabaseContext::run` receives a server-generated UUID, not caller role,
tenant ID or actor ID, and establishes the existing transaction-local Provider
identity. Within that same transaction the service:

1. Selects singleton row 1 `FOR UPDATE`; absent, unreadable, sealed or inconsistent
   marker is unavailable. It never inserts/upserts a replacement.
2. Rechecks **any** `provider_users` existence, not just team-manage holders.
3. Rechecks secret/expiry after waiting and reads the active capability catalog
   inside the transaction; `provider.team.manage` must be ACTIVE. It needs no new
   write/lock privileges on the reference capability table.
4. Updates the locked marker to sealed with the transaction timestamp, requiring
   exactly one updated row, **before** inserting any Provider or audit data.
5. Creates one ACTIVE, email-verified Provider with `Hash::make` of the owner's
   password, `mfa_enrolled_at=NULL`, auth/authorization versions both 1.
6. Grants all ACTIVE capability keys, as the old CLI did.
7. Uses existing `PROVIDER_TEAM_MEMBER_CREATED` audit taxonomy, self-attributed
   actor and target UUID, request ID, empty allowlisted metadata. Its insert and
   the Provider insert see an already-sealed marker, so population hooks no-op.
   Any insert/audit/commit failure rolls back user, grants, audit **and early seal**.

Only the new unauthenticated setup creation path remains supported, serialized
on this marker. `provider:bootstrap-root {email}` retains its command/required
argument shape for caller discovery but always returns failure, without reading
the argument, data access, generated password, credential output or side effects.
The former `handle(SecurityAuditWriter, ProviderDatabaseContext)` implementation
is deliberately retired. Callers must migrate to the protected setup UI/API;
this is a documented behavioral incompatibility, not a successful CLI install.
Independent review identified an actual legacy caller:
`tools/security/core01-g3/isolated-first-fixture.php:39` uses `proc_open` to invoke
`artisan provider:bootstrap-root`, then expects `Temporary password:` output at
line 42. This fixture is **UNSUPPORTED/BLOCKED before reuse**: the command now
returns failure, and the harness may already have consumed its own retry marker.
Do not run, fix or reauthorize that fixture through P1; no alternate creator,
auth bypass, reset or fixture credential output is restored. A separately reviewed
fixture path is future scope. The W1 fixture manifest's prohibition is not a caller.
Old tests expecting CLI creation/password output are intentionally obsolete; no
existing tests or fixture sources were rewritten.

Existing authenticated `ProviderTeamService` is untouched. It requires an existing
MFA-authorized team-manage actor with step-up, so it cannot establish the first
Provider in an empty install. Test fixtures, manual SQL and schema-owner writes
are not supported installation bootstrap interfaces. No install-on-startup hook,
password reset, tenant identity, root replacement or second auth stack is added.

Both concurrent setup callers lock the same singleton. At READ COMMITTED, after
the first commit the waiter sees sealed=true; stronger isolation may fail with a
serialization error, also a denied setup. An audit/uniqueness failure aborts the
whole transaction. A lost successful HTTP response cannot be retried to create
another account: the client must continue at normal login. This mechanism does
not guarantee success delivery or idempotent success responses.

## Existing security boundaries and downstream impact

- Login creates an authenticated routine session for an unenrolled account and a
  pending genuine-MFA challenge for an enrolled account. Creation itself logs
  nobody in and issues no receipt/session/step-up authority.
- `ProviderAuthorizationService::current` still requires enrolled MFA. Issuer,
  authority generation, session binding, R13 locks and 503 guards are untouched.
- Tenant/company provisioning, first tenant administrator activation, W2/W3,
  plans and tenant RLS remain outside P1. A successful setup is not proof of
  company creation, full browser login or release readiness.
- The Super Admin Security Settings screen can enroll a factor using the
  authenticated API. Runtime browser acceptance remains a separate gate.
- P2 optional MFA and sensitive-action authority are separate owner-authorized
  work. P3-P4 company lifecycle, immutable tenant identity and first administrator,
  W2 customers/leads, W3 sales, W4 tenant invoicing and W5 platform billing remain
  independent scope; platform and tenant sales invoices must not be conflated.

## Offline tests and honest acceptance limits

Run standalone `tests/Support/P1Bootstrap/p1-bootstrap-offline-test.php` with an
installed PHP 8.3+ and vendor autoload. Do **not** invoke Artisan, Laravel bootstrap,
Composer test scripts or PHPUnit configuration for this phase. On this Windows
host validation uses `php -n` with per-command mbstring, intl and openssl extension
flags; no PDO driver is loaded. No installed files or PHP ini are modified.

The suite exercises actual policy, service, `ProviderDatabaseContext`,
`SecurityAuditWriter`, controller, framework hashing, existing Origin middleware,
framework CSRF verifier (including encrypted X-XSRF-TOKEN), and cache rate limiter.
Persistence/transaction storage and population-hook effects are explicit in-memory
models. The adapters acknowledge context-setting strings but do not execute SQL
or the definer function. C06 models serialized requests and early-seal rollback;
C11 models post-migration population of each of the seven tables, populate/delete,
population rollback and both serialized commit orders. They are **not real
concurrent PostgreSQL or trigger proof**. C14 inspects the exact fixed definer
body, all-table hook loop and row-trigger form, not migration execution/ACLs.
C08 uses the actual limiter to verify status/invalid proof spend no global quota
and valid-proof attempt 21 fails before identity/Provider access. C12 verifies backend
response shape only; UI verification belongs to the parent.

C01-C14 cover success, invalid/missing/expired proof/config, password/email/input
negatives, existing Provider, seal/missing marker, serialized contender, replay,
CSRF/Host/Origin/transport/rates, redacted output, unchanged security source
boundaries, populated-install denial, frontend-facing contract, CLI deprecation
and migration source integrity. Raw logs and numeric command exits are external:
`I:\WORK\DALEEL-CRM-AUDITS\DCRM-V1-P1-FIRST-ROOT-20261107-190047\logs\p1-*`.
Review-fix attempts, revision baseline, hashes and evidence are under
`logs\p1-review-fix\`; all prior logs are retained unchanged.
Failures and reruns must both be retained. Independent security review is a parent
acceptance gate, not something this single-agent source suite proves.

NOT_RUN: real migration fresh/upgrade, SQL parsing/execution, RLS/ACL/effective
role identity, audit-trigger behavior, real locking/concurrency, HTTP/cookie/CSRF,
bridge/browser/TLS, persistent dev DB ineligibility probe, isolated full regression
and production acceptance. The persistent dev database is owner-reported populated;
it is ineligible by design, not connected to or newly proven here. Graphify was
queried first; STALE_NON_BLOCKING_DEVIATION is retained, no repair/reindex/update.

## Future authorized deployment and rollback (plan only)

Deployment requires a new explicit owner authorization and a new isolated fresh
and genuine populated-upgrade database. Attest effective owner/non-owner roles,
visibility, effective grants (including defaults/inheritance), trusted schema,
transactional migration application and absence of unexpected marker permissions.
Prove empty fresh marker, sealed upgrade even with audit-only history, visibility
failure abort, absent marker denial, trigger/ACL negatives, post-migration insert
and populate/delete sealing for each of all seven tables, zero-row insert no-op,
definer owner/search-path/effective EXECUTE proof, early-seal insertion/audit
rollback, two-process population/setup races in both commit orders, two-setup
race with at most one winner, replay, real direct/stateful
CSRF denials, TLS/Host/Origin allowlists, shared-cache rate limits, response privacy
and existing MFA login flow. Do not use the populated persistent dev DB as a test
fixture. Preserve inherited authority, R13 and 503 security gates throughout.

After a successful install the operator disables bootstrap and removes its secret
from protected server configuration; changing or re-enabling config cannot reopen
the sealed database. Secret issuance time is not stored: the contract enforces a
maximum remaining one-hour configuration window at every use, with an explicit
absolute expiry, not a separately attested issuance-age claim.

For source rollback restore only this task's owned file deltas from the captured
pre-task worktree baseline, preserving inherited dirty bytes; do not reset/clean
Git. Disable setup/config routes before rollback and stop the deprecated CLI from
being reinstated as an alternate first-root path. **Never drop, truncate, reset or
unseal a deployed marker.** `down()` throws intentionally. If migration 070 has
been applied, preserve it and its seal and use a reviewed forward-only migration
for any future fix. Removing source does not authorize DB changes or restore old
unsafe bootstrap behavior. No commit, deploy or migration is authorized by this
document.
