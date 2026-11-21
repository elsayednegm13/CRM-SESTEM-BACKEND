# Tenant Registry Foundation

## Scope and authority

`tenants.slug` remains the single canonical tenant identity. The schema adds no parallel slug registry. Slugs are lowercase DNS labels, reserved infrastructure labels are rejected, and database guards prevent slug edits and tenant deletion. Retaining the tenant row is the permanent reservation; no automatic reuse path exists.

Version 1 reserves these slugs: `admin`, `api`, `assets`, `auth`, `billing`, `cdn`, `docs`, `help`, `mail`, `marketing`, `root`, `static`, `status`, `superadmin`, `support`, and `www`. This list is an engineering baseline, not a purchase or DNS decision. Extending it requires a reviewed forward migration and matching application validation.

## Host registry

`tenant_hostnames` stores one platform-generated host for a tenant. The composite foreign key binds the row to the same tenant ID and canonical slug. The host must equal `{tenant_slug}.{base_domain}`; custom-domain aliases cannot be represented. Mapping rows and tenant rows cannot be updated or deleted through the runtime roles, and database triggers preserve those identities even for more privileged writers.

`BASE_DOMAIN` is read from environment configuration and has no fallback. The value must be lowercase ASCII DNS labels; IP literals, bare `localhost`, Unicode/IDNA input, ports, paths, user-info, wildcards, trailing dots, and numeric top-level labels are rejected. A scoped local/test exception permits a canonical multi-label `.localhost` base only when `APP_ENV` is exactly `local` or `testing`, `TENANCY_ALLOW_LOCALHOST_BASE_DOMAIN=true`, `TENANCY_LOCAL_TEST_BASE_DOMAIN` exactly equals `BASE_DOMAIN`, and the database's DBA-provisioned active domain row is classified `LOCAL_TEST`. Staging/production and all other environments reject `.localhost` even if the opt-in is set. An unconfigured `.localhost` suffix is never implicitly accepted.

The database stores an immutable `environment_scope` (`LOCAL_TEST` or `NON_LOCAL`) in its versioned active-domain row. SQL enforces that `.localhost` belongs only to `LOCAL_TEST` and other canonical names to `NON_LOCAL`; only the database owner/DBA can write this table, while application roles receive SELECT only. PostgreSQL cannot infer PHP `APP_ENV`, so the app environment gate and database domain-classification constraint are separate proofs. The exact configured base is server configuration, never request input. Ordinary configured synthetic DNS names such as `example.test` remain valid without the `.localhost` exception. This does not prove DNS, wildcard routing, TLS, proxy trust, browser sessions, or host-first tenant resolution.

The table starts empty in product migrations; a deliberate database-owner/DBA action must configure the active domain before registration can succeed. The application configuration and active database value must agree.

The schema currently supports mapping version 1 and one host mapping per tenant. Domain rotation requires a reviewed versioned migration and a coordinated host cutover. Do not update stored host rows in place.

## Database roles and connection boundaries

Migrations require the following pre-created, non-login, non-superuser, non-`BYPASSRLS` group roles. The migrations fail closed if the Provider writer or host resolver role is absent or unsafe. Product migrations do not create roles, passwords, memberships, or runtime credentials.

| Role | Required access | Forbidden access |
| --- | --- | --- |
| `daleel_provider_registry_writer` | Insert tenants through the existing approved Provider policy; insert and read back only the hostname row bound to the approved operation; read the Provider authorization facts required by the existing invoker helper; read active-domain configuration | Host or slug update/delete; tenant runtime tables beyond the existing Provider contract; superuser or RLS bypass |
| `daleel_hostname_resolver` | Read the exact requested host row under `HOST_RESOLUTION`; read active-domain configuration | Provider, user, tenant credential, customer, or business tables; all writes |
| Tenant runtime principal | No registry write authority; tenant-scoped data access remains governed by existing RLS | Host create/update/delete or registry configuration changes |

The migration owner is separate from all runtime roles. Production credentials and memberships are an infrastructure rollout concern. The existing `daleel_dev_app` role is not presumed equivalent to either new role. The scratch tests used `NOLOGIN` roles and PostgreSQL `SET ROLE`; they did not create or grant login access in the persistent TEST databases.

## Provider write primitive

`TenantHostnameRegistry` accepts the existing `pgsql_provider_control` transaction connection and the approved tenant ID/slug. It derives the host from `config('tenancy.base_domain')`, inserts idempotently, then verifies an existing row matches the same intent. A different mapping raises a non-enumerating conflict. PostgreSQL RLS additionally requires a valid, approved `company.provision` operation whose canonical slug and target tenant match.

This primitive is not yet called by `ProviderControlOperationService::executeProvision`. The existing Provider approval/founder flow remains unchanged by this control. End-to-end company provisioning with host creation is therefore not implemented and must be integrated in a separately reviewed batch within the same transaction.

## Resolver boundary

The resolver role can read one exact host mapping after a trusted server component sets `app.context_mode=HOST_RESOLUTION` and `app.host_resolution_hostname`. The database role and policy keep this lookup separate from Provider reads. The GUC is a query filter; it does not prove that a gateway validated the external Host header.

The mapping returns only tenant identity and host metadata. It does not grant access, establish an authenticated user, or check whether a tenant is suspended. Trusted ingress, request-host verification, lifecycle checks, tenant-local staff authentication, secure sessions, CSRF, and browser/session proof remain future work (FND-02B/FND-03).

## Test and rollout status

The migrations were applied only to the uniquely named FND-02A scratch database in the isolated TEST cluster. Persistent `daleel_dev`, `daleel_test`, and the ENV-02 recovery database were not migrated. Applying the legacy migrations plus these additive migrations to DEV requires separate owner approval, role preflight, explicit `BASE_DOMAIN` configuration, backup/recovery readiness, and a fresh catalog check.
