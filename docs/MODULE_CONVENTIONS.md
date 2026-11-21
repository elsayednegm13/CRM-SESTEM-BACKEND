# Module conventions

Current implementation shape:

```text
app/Modules/
  Shared/Http/       transport contracts, middleware, cross-cutting HTTP
  System/Http/       health and readiness endpoints
  Identity/
    Domain/          global email and status rules
    Application/     login, rate limiting, account/session use cases
    Infrastructure/  global User persistence adapter
    Http/            auth endpoints and session middleware
  Tenancy/
    Domain/          immutable TenantContext, scope enum, safe tenant/authorization failures
    Application/     membership resolution, authorization, mutations, invariant, redacted events
    Infrastructure/  tenant/member/role models, guarded repository, RLS DB context
    Http/            company-context middleware and read-only authorization endpoints
```

Future modules may grow into `Domain/`, `Application/`, `Infrastructure/`, and `Http/` when real behavior exists. Do not create placeholder modules ahead of their authorized batch. Domain rules belong to the owning module; controllers translate HTTP and delegate. Identity stays global. A tenant-owned repository subclasses `TenantScopedRepository`, fixes its table name, validates module fields, and receives only a server-resolved TenantContext; it must never expose an unscoped query builder. Future business modules must invoke tenant authorization for each action and server-loaded object. No Leads, Billing, Payments, CMS, or other business module is implemented yet.
