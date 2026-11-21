# Daleel CRM API architecture

## Current scope

This repository is a standalone Laravel modular-monolith API. Implemented areas are shared HTTP foundation, health/readiness, global Identity with first-party browser session authentication, 07A tenant isolation, 07B company RBAC, 08 PostgreSQL RLS for current tenant tables, 10A durable security audit, and 10B separate provider identity/MFA/capability/approval foundations. Ordinary company access derives its sole active company from the authenticated user's membership. Authentication alone grants no company access or capability. No subscription, lead, billing, CMS, customer provisioning, provider registration, or public registration behavior exists.

The API is authoritative for identity and later business state. Marketing/CMS belongs to `daleel-crm`; tenant CRM belongs to `daleel-crm-admin`; provider control plane belongs to `daleel-crm-super-admin`. Frontends consume versioned REST JSON and never connect to PostgreSQL directly.

## Module boundaries

`app/Modules/Shared` owns cross-cutting HTTP and audit contracts. `app/Modules/System` owns health endpoints. `app/Modules/Identity` owns global tenant-user identity and authentication. `app/Modules/Tenancy` owns company resolution, RBAC, and the tenant persistence guard. `app/Modules/Provider` owns the isolated provider guard, MFA, authorization and internal approval primitive. Future modules may use `Domain/`, `Application/`, `Infrastructure/`, and `Http/` layers when real behavior exists. Cross-module calls use narrow application contracts or typed internal events.

07B adds permission catalog and versioned role template reference tables, tenant-owned roles, role grants, and membership assignments. `CompanyAdminBootstrap` is internal and restricted to local/testing with an explicit disposable flag. It instantiates a company-admin role from a template snapshot; no public provisioning or role mutation HTTP route exists. Role mutations require fresh context and capability, enforce delegation ceilings, and serialize on the tenant row before checking the effective-admin invariant. Global account disable also preserves that invariant. Authorization is uncached.

Tenant-owned data will use shared PostgreSQL with mandatory `tenant_id`, immutable request-scoped context, tenant-aware repositories, RBAC, RLS for the five current tenant tables, and shard-ready design. No tenant placement or business schema exists yet. A future `TenantPlacementResolver` will map verified tenant UUIDs to physical placement; business logic must not embed database names. Each future tenant business table needs its own RLS policy and A/B proof before production data is allowed. See `docs/RLS_ARCHITECTURE.md`.

## Runtime boundaries

API, Redis queue workers, and scheduler are separate logical processes. Production queue, cache, locks, rate-limit, and session direction is Redis. Local auth proof intentionally uses file sessions. S3-compatible object storage is a future adapter. Tenant-scoped cache keys must include tenant identity; cache is never financial authority. Dependency health probes are read-only and report Redis as `not_configured` unless a real Redis check is enabled.

## Local topology

| Surface | Address |
|---|---|
| Marketing website | `http://localhost:3000` |
| Tenant CRM | `http://localhost:3001` |
| Super Admin | `http://localhost:3002` |
| Backend API | `http://localhost:8000` |
| API base | `http://localhost:8000/api/v1` |
