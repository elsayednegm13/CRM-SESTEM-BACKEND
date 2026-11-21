# Tenant Staff Identity and Dynamic RBAC Foundation

Control: `DALEEL_CRM_FND_ID_01_REV1_DIRECT_ACCOUNTS_DYNAMIC_RBAC_TEST_FIRST`
Canonical policy: [ADR-0012](../../docs/decisions/ADR-0012-admin-managed-accounts-dynamic-tenant-rbac.md), SHA-256 c95918712acfe57313aabdd0cd298e36967282c088ee823bd524c8f2d6b742a1
Status: additive identity schema from FND-ID-01 plus bounded host-first staff authentication and role-view enforcement from FND-ID-02. Provisioning, account CRUD, recovery and DB rollout remain separate controls.

## Scope and policy

Provider directly creates the first Company Admin under a future approved provisioning transaction; a Company Admin directly creates employees within the same tenant. No invitation entity, token, acceptance route, or outbox is part of the current policy. Initial password change is optional. There is no `must_change_password` field. Tenant staff and Provider identity remain independent, and equal emails across tenants or realms do not link accounts.

The FND-ID-02 routes use tenant-local staff principals and a separate session guard. The legacy global `users` model and Provider identity realm are not used as tenant staff fallback. Provider provisioning and the historical founder-acceptance route remain separate legacy source. Tenant forgot/reset/verification endpoints fail closed until an authorized tenant-local recovery design is implemented. No account CRUD, role edit, or permission-grant endpoint is added.

## Additive schema (migrations 23–25)

- `tenant_staff_users`: UUID staff principal; immutable `tenant_id`; tenant-scoped canonical email uniqueness; display email/name; active/disabled state; auth version; non-null Argon2id hash. Disabled rows retain their email reservation.
- `tenant_staff_memberships`: exactly one retained membership per staff principal (unique staff user ID plus deferred presence check); composite tenant/staff and tenant/actor references; immutable owner/provenance; provider operation provenance for the first Admin and same-tenant staff membership provenance for later staff.
- `tenant_staff_membership_roles`: additive mapping to existing tenant-owned `roles`; assignments are positive, historical, and independently revocable. No parallel role registry is created.
- `tenant_staff_permission_grants`: positive, per-membership grants with a foreign key to existing global `permissions`, scope validated against active catalog metadata, delegable catalog entry required, and append-only grant/revocation history.
- `tenant_staff_password_reset_tokens`: SHA-256 token digest only, tenant/staff composite FK, expiry, and consume-once transition. No raw token or global password broker relation.
- `tenant_staff_security_events`: tenant/staff and Provider-operation actor references, fixed event vocabulary, empty safe metadata, append-only trigger. Passwords, token values, and hashes are not audit metadata.

All new tenant tables enable and FORCE PostgreSQL RLS, have tenant-scoped policy predicates requiring tenant and actor context, and explicitly revoke `PUBLIC` table privileges. No role, membership, schema, database, or default-privilege grants are created. Foreign keys enforce same-tenant staff, membership, role, actor, and target links. Migrations 1–22 remain unchanged and forward-only migration `down()` methods throw.

RLS reads the existing transaction-local `app.context_mode`, `app.tenant_id`, and `app.user_id` helpers. FND-ID-02 adds one narrow pre-authentication function owned by a dedicated NOLOGIN, non-owner, non-superuser, NOBYPASSRLS role. It independently resolves the exact hostname and active environment-domain record before looking up a tenant-local email, and returns a password hash only for an active tenant, active staff user, and active membership. Its role-bound policies expose only that exact host/tenant/email lookup. The function client receives EXECUTE only and has no direct staff-table SELECT. Authenticated handlers use a different non-owner NOBYPASSRLS runtime principal and set transaction-local tenant/actor GUCs on the same PostgreSQL connection and transaction as protected SQL. A GUC is still not identity proof: a direct SQL client holding an application credential can set custom GUC values, so database network and credential isolation remain mandatory. Provider operation inserts remain unavailable under the tenant-only RLS context.

## Account construction and permission resolution

`TenantStaffAccountFactory::build()` canonicalizes through the existing `EmailAddressNormalizer`, validates a nonempty display name and the existing 12-character / 1024-byte password bounds, hashes with `argon2id`, and returns an unsaved persistence payload. It does not persist, log, authenticate, or force password rotation. The model hides the password hash and uses guarded attributes.

`EffectivePermissions::resolve()` is pure and accepts already-loaded role grants, direct grants, and a decoded catalog snapshot. It returns the positive union, keeps scopes distinct, lets `ALL_TENANT` dominate narrower scopes for one key, drops `NONE`, requires direct grants to be catalog-delegable, and returns `null` (deny the complete snapshot) for unknown/inactive/malformed/out-of-scope input. Synthetic `test.*` keys exist only in unit-test fixtures; none are inserted into the product catalog.

## Delegation boundary and current CRM map

The current catalog contains only `company.administer`, `role.view`, `role.manage`, `member.view`, and `member.manage`. Existing `member.manage` and `role.manage` do not prove the action-level limits needed for each actual CRM section. No direct-grant mutation service or role-management endpoint is implemented; `DELEGATION_RUNTIME_NOT_IMPLEMENTED` is an intentional security boundary. Staff may request help manually from an authorized colleague; no in-product request flow exists. Role labels do not imply privileges or department membership.

The report-local `EXISTING_CRM_SECTIONS_PERMISSION_MAPPING.md` inventories every real tenant CRM route, actual Sidebar item, current backend endpoint/key, and gaps. The new evaluator is not wired to current legacy authorization routes. Later UI integration must hide denied navigation, deny direct URLs/API server-side, enforce row/data scope, and refresh permissions without re-login.

## Transaction model for a later authorized service

The intended future write is one physical PostgreSQL transaction: resolve the trusted tenant host first; acquire the tenant/capacity and authority lock in the approved order; validate the authenticated actor and delegable subset; insert or change staff identity/membership; attach existing tenant roles and positive scoped grants; increment the affected authorization/session version where required; append the safe audit record and Provider operation result; commit. Any failure—including audit or final-admin/seat invariant failure—rolls back all writes. Idempotency and retry semantics must be explicit. This service and its concurrency guarantees are not implemented here.

## Tests and acceptance layers

Focused PHP tests cover canonical email, tenant-host parsing, tenant-specific login throttling, no global-user auth routing, restricted session-provider behavior, role-plus-direct permission union and scope, schema source contracts, and migration 26's narrow ACL contract. These source tests do not replace actual migration, RLS/session-identity, restricted-role, HTTP/cookie/CSRF, browser, or deployment proof. See the FND-ID-02 complete report for independent source and runtime evidence.

## Explicit follow-on dependencies

1. Complete source test and safe local commit evidence for this foundation.
2. Establish the exact TEST-only migration coordinator; if qualified, one isolated scratch may prove migrations and SQL constraints. Never replay/reset old DBs.
3. Separately specify and implement Provider-atomic first Admin creation.
4. Implement tenant-local recovery, password change, verification, MFA, credential rehash and audited revocation as separately authorized work.
5. Establish granular CRM permission/action catalog and authenticated delegation policy before role/direct-grant write APIs.
6. Implement staff/role/profile APIs, session invalidation, last-Admin and seat invariants, and audit transaction.
7. Integrate the tenant CRM UI only in a separately authorized frontend control and prove real browser direct-route/data-scope behavior.
8. Obtain separate approval for DEV migration/rollout; no automatic next batch.
