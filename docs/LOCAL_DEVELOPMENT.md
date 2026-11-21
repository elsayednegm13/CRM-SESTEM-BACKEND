# Local development

## Requirements

- PHP 8.3–8.5 and Composer 2.x; the validated workspace uses PHP 8.4.26 for Composer and Artisan and Laravel 13.34.0.
- PHP `fileinfo`, `intl`, and `pdo_pgsql` are enabled. PostgreSQL is required for identity persistence. Redis is not needed for local auth proof but remains the staging/production queue, cache, lock, rate-limit, and session target.
- No local `.env` is tracked. Copy `.env.example` only when local configuration is needed, generate a private `APP_KEY` locally, and never commit `.env`.

## Safe local commands

```powershell
composer install
php artisan route:list --path=api/v1
php artisan test
php artisan serve --host=localhost --port=8000
```

Use `http://localhost:8000` consistently for browser auth; do not mix `localhost` and `127.0.0.1`. The local frontends are `http://localhost:3000`, `:3001`, and `:3002`.

The dependency check setting is disabled by default. Liveness never contacts PostgreSQL or Redis. Readiness reports `not_configured` until explicit read-only checks are enabled. For real proof, configure only an isolated disposable PostgreSQL target and enable the probe deliberately.

The test harness uses array cache/rate-limit stores, sync queue, and array sessions only in PHPUnit configuration. These are `TEST_ONLY`; they do not replace the Redis architecture. Migrations cover global `users`, `password_reset_tokens`, `tenants`, `tenant_memberships`, six RBAC tables, and RLS policies for five current tenant tables; never run them against an unknown, shared, or production database. The existing local listener at `127.0.0.1:5432` has unverified ownership and is forbidden as a proof target. Use a separately identified disposable PostgreSQL instance for tests.

`GET /api/v1/company/context`, `/company/authorization`, and `/company/roles` can be exercised only after a controlled disposable proof user, ACTIVE tenant and sole ACTIVE membership exist. The 07B company-admin bootstrap is an internal local/testing service gated by `TENANCY_DISPOSABLE_BOOTSTRAP=true`; its fixture is not customer provisioning. No public tenant creation, role bootstrap, or RBAC mutation endpoint exists. `X-Tenant-ID` and frontend tenant markers do not select a company.

Staging/production must use Redis sessions and separate API, queue-worker, and scheduler processes. Require TLS, secure cookies, secret-managed credentials, exact approved CORS origins, and `APP_DEBUG=false`.

Composer setup/post-create hooks that generate keys, touch SQLite files, publish assets, or run migrations require review before use. Optimized autoloading is deferred locally because its workspace scan stalled; measure the target build environment separately.

Historical RefreshDatabase tests use a migration-owner connection. Dedicated RLS tests and HTTP proof must use a separate non-owner, non-BYPASSRLS role. Recreate runtime grants after migrate:fresh, which drops and recreates tables. See docs/RLS_ARCHITECTURE.md.
