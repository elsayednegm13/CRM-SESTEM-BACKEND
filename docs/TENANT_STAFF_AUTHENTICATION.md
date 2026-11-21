# Tenant Staff Authentication Foundation

Status: bounded FND-ID-02 implementation; production ingress, database-role provisioning, and browser deployment are not implied.

## Host and realm selection

Tenant API routes require a canonical hostname under the configured `BASE_DOMAIN`, exactly one tenant slug label, a matching active `tenant_hostnames` row, and the active `tenant_registry_domains` row for the expected scope. The hostname resolver connection has only the existing exact-host registry read capability. `.localhost` is accepted only when `APP_ENV` is `local` or `testing`, the opt-in is true, and the configured local test domain exactly matches `BASE_DOMAIN`. Provider and marketing/API route hosts do not become tenant selectors. No `tenant_id`, slug, actor, email, origin, cookie, or `X-Tenant-*` request value selects the tenant.

The service uses Laravel/Symfony's effective request host. No proxy is trusted by default. A deployment must configure only known ingress proxy addresses and block direct-origin access before trusting forwarded host headers. Production DNS, proxy, TLS, and tenant-domain ownership are outside this control.

## Pre-authentication database boundary

`lookup_tenant_staff_credentials` is a forward-only migration 26 function. A dedicated NOLOGIN function-owner role is not a table owner, superuser, or `BYPASSRLS` role. It has only selected-column reads and inherits the hostname resolver's exact-host policy. The function uses a fixed `pg_catalog, pg_temp` search path and schema-qualified tables, verifies active hostname/base-domain/environment scope, checks the tenant is `ACTIVE`, and then matches only `(tenant_id, canonical_email)`. It returns credential data only for an `ACTIVE` staff user with an `ACTIVE` same-tenant membership. Unknown, disabled, suspended, and mismatched identities return no row.

The auth-client group receives only `EXECUTE` on the function. It has no direct SELECT on tenant staff tables and no membership in the function-owner role. This is a private application trust boundary, not an authentication protocol for arbitrary database clients: a party holding the auth-client database credential can call the function with chosen registered hosts and emails. Keep the credential private to Laravel and restrict PostgreSQL network reachability.

## Session and request context

`tenant_staff` is a session-only guard using a custom user provider. The provider loads a session principal by UUID using a safe column list; it does not query by email, verify passwords, or fetch the password hash. Login password verification occurs only after host-bound pre-auth lookup and requires an Argon2id hash. Successful login rotates the server session and records the exact host, tenant, staff user, membership, auth version, authorization version, and authentication time in the server-side session.

Every tenant request resolves the host first. The session-context middleware starts a transaction on `pgsql_tenant_runtime`, clears transaction-local context, checks the host/tenant binding, sets `app.context_mode=TENANT`, `app.tenant_id`, and `app.user_id` from the validated server-side principal, and rechecks tenant, staff status/version, and membership status/version. All protected queries in that handler use the same named connection and open transaction. Commit or rollback clears `SET LOCAL` values. Missing/invalid context does not query protected tables successfully under RLS.

The cookie is HttpOnly, SameSite=Lax, and host-only. Secure is false only for the local application environment and true otherwise. Sanctum's stateful API middleware still supplies browser-session and CSRF handling; tenant routes use the explicit `tenant_staff` guard, so Provider auth does not act as a tenant staff fallback. The Provider routes and guard remain unchanged.

## Routes and authorization

- `POST /api/v1/auth/login`, `GET /api/v1/auth/me`, and `POST /api/v1/auth/logout` use the host-first tenant staff realm.
- Tenant forgot/reset/verification paths return an explicit not-implemented response and do not call Laravel's global user password broker or global users table.
- `GET /api/v1/company/roles` is the one wired company action. It recomputes the active tenant staff member's effective positive permission union from existing active role grants, direct positive grants, and catalog metadata. `role.view` is required on the server; absent, invalid, inactive, or unknown grants deny. The endpoint lists active role labels only and provides no role mutation.
- Company context/permission snapshot endpoints remain unavailable until their tenant-local contracts are implemented. No Provider provisioning, staff CRUD, grant delegation, or frontend menu integration is included.

Login errors are generic for unknown, disabled, wrong-password, inactive-membership, and suspended-tenant cases. The login limiter uses separate `(tenant_id, normalized email, IP)` and IP-only buckets at the existing 5/15-minute and 100/15-minute baselines. Passwords, hashes, session IDs, tokens, cookies, and request bodies are not included in structured auth logs.

## Required deployment setup

Provision separate credentials for `pgsql_hostname_resolver`, `pgsql_tenant_auth`, and `pgsql_tenant_runtime`. The migration requires pre-created NOLOGIN groups `daleel_hostname_resolver`, `daleel_tenant_auth_lookup`, `daleel_tenant_auth_client`, and `daleel_tenant_runtime`; the dedicated auth function owner inherits only the hostname resolver role. The application LOGIN roles must inherit only their exact group, have no table ownership, and have neither superuser nor `BYPASSRLS`. Do not give regular staff requests the migration owner or a privileged Provider credential.

Before non-local use, provision the active hostname domain row with the correct database-owned environment scope; configure exact SPA origins, trusted-proxy IP addresses, HTTPS, Secure cookies, and network rules. No production database role, credential, DNS, ingress, or TLS operation was performed in this control.

## Recovery and limits

Tenant password reset, email verification, password change/rehash, MFA, durable login-event insertion, and account revocation flows are not implemented. Existing global reset tokens must never be reused. The DB runtime principal can set custom GUC values if directly used by an attacker; RLS is a row-scope layer, not proof of actor identity. Only trusted Laravel code may derive context, and arbitrary SQL access under application credentials remains outside the boundary. Pool/worker reuse, browser CORS/CSRF behavior, and production proxy behavior require their own actual runtime evidence.
