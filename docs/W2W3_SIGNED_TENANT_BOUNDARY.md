# W2/W3 Signed Tenant Boundary

## Scope

Migration `2026_11_08_000071_enforce_signed_tenant_boundary_on_w2_w3_tables.php`
is a forward-only source repair for the tenant tables introduced by migrations
066 and 069. It does not replace the application tenant context or change
existing table grants.

## Policy contract

| Tables | Existing product filter | Added independent gate |
|---|---|---|
| `customers`, `customer_contacts`, `customer_addresses`, `lead_conversions` | Existing 066 tenant policy | Restrictive signed boundary for `daleel_tenant_runtime` |
| `sales_pipelines`, `sales_pipeline_stages`, `deals`, `deal_stage_transitions`, `sales_tasks`, `sales_activities` | Existing 069 tenant-GUC policy | Restrictive signed boundary for `daleel_tenant_runtime` |

The added policy uses both `USING` and `WITH CHECK` with
`public.core01_signed_tenant_allowed(tenant_id)`. This combines with existing
permissive policies; it does not delete or relax them.

## Admission and runtime limits

Before creating any policy, the migration checks that all ten tables exist,
have a UUID `tenant_id`, RLS and FORCE RLS enabled, and do not already have a
conflicting boundary policy. It also checks the signing function's security
definer flag, expected owner, and intended execute ACL.

This document is source-contract evidence only. The migration has not been
applied, no manifest entry was added, and no database/HTTP/browser test was
executed in the associated remediation.
