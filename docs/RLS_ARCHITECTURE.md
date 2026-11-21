# PostgreSQL RLS boundary (Control 08)

## Protected and global tables

`tenants` is the tenant root. `tenant_memberships`, `roles`, `role_permissions` and `membership_roles` are tenant-owned. All five have ENABLE and FORCE ROW LEVEL SECURITY. `users` and `password_reset_tokens` are global Identity tables; `permissions`, `role_templates`, and `role_template_permissions` are global reference tables; `migrations` is framework bookkeeping. Global tables need their own application access/field policies and do not inherit tenant RLS.

## Context lifecycle

`RlsDatabaseContext` is the only application entry for `set_config(..., true)`. It starts a database transaction, clears `app.context_mode`, `app.user_id`, and `app.tenant_id` in that transaction, then sets only server-derived values. Request resolution uses `TENANT_DISCOVERY` with the authenticated global user ID. The membership SELECT policy exposes only that user's ACTIVE membership. The service switches to `TENANT` using the RLS-visible membership row, then validates the tenant. Protected operations start a new transaction with the immutable `TenantContext` and recheck user, membership, tenant and RBAC under the existing guard. Commit/rollback removes top-level local settings; a successful nested savepoint scope restores its prior values before returning to an outer transaction. On SQL failure the savepoint rollback restores them; attempting SQL cleanup inside the aborted scope would mask the original error. The same physical connection may then serve A, B, or no tenant without retaining a prior grant.

SQL helpers `app_rls_context_mode`, `app_rls_current_user_id`, and `app_rls_current_tenant_id` are SECURITY INVOKER and return NULL for absent/malformed values. Policies fail closed when mode or UUID is absent. `tenants` has SELECT/UPDATE policies only; ordinary runtime INSERT/DELETE are denied. `tenant_memberships` has a narrow discovery SELECT plus tenant-scoped SELECT and tenant-scoped writes. The three RBAC tables require TENANT mode and matching row `tenant_id` for all CRUD operations.

## Roles and operations

The migration/owner role runs DDL and controlled fixtures. The API runtime role must have `rolsuper=false`, `rolbypassrls=false`, no table ownership, no schema CREATE, and only approved table privileges. The current tenant-first write guard uses `SELECT ... FOR UPDATE` on `tenants`, requiring the runtime role's UPDATE table privilege; RLS still restricts it to the current tenant. No tenant-update HTTP route exists. A column-level UPDATE grant may narrow this later only after verifying lock behavior. FORCE subjects a non-superuser table owner to policies too; a superuser remains a bypass and must never be used as runtime proof. Production migration credentials must not be supplied to the API process. Grant runtime privileges explicitly after schema creation; `migrate:fresh` recreates tables and discards grants. Queue workers, scheduler and console jobs must use a reviewed runtime context path before tenant access.

The internal 07B disposable bootstrap uses the migration/fixture connection only; it is not customer provisioning. Global account disable now performs target-user discovery and switches to that active tenant before the last-admin invariant check. Provider reporting, recovery and break-glass operations must use a separately audited path, never a silent BYPASSRLS API role or disabled RLS.

## Future tenant-owned migration contract

Every future Leads, Customers, Deals, Tasks, Files, Reports or Integrations table must have `tenant_id uuid NOT NULL`, FK to `tenants`, tenant-leading indexes, and composite tenant FKs for relationships. Its migration must enable and FORCE RLS, add SELECT, INSERT WITH CHECK, UPDATE USING+WITH CHECK, and DELETE USING policies tied to the transaction-local tenant context, then prove runtime non-owner status, no-context denial, A/B raw SELECT/INSERT/UPDATE/DELETE isolation and application object-level authorization. Dedicated/sharded databases use the same canonical tenant UUID and policy contract per placement. No business table is production-ready from Control 08 alone.

## Limits

RLS does not replace authentication, RBAC, object policy, safe SQL or SQL-injection prevention. Custom GUCs are application-controlled and could be forged by arbitrary SQL execution under the runtime credential. Foreign-key/unique enforcement may reveal existence through constraint outcomes; never return raw SQL errors to clients. Superuser, BYPASSRLS, table maintenance and application-secret compromise are outside this tenant boundary. Control 10A adds a separately FORCE-protected audit table with an INSERT-only ordinary runtime path (see `docs/SECURITY_AUDIT.md`). Control 10B adds a distinct provider identity/DB role and provider audit INSERT policy (see `docs/PROVIDER_SECURITY.md`); provider provisioning/recovery actions remain future work.
