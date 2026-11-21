# W3 Sales and activities — source contract

This document describes source-only routes. No database, HTTP, browser, RLS, or transaction acceptance was executed in this change.

All endpoints are under `/api/v1/company`, use the existing Host-derived tenant context, authenticated tenant-staff session, CSRF/origin middleware, and `{data,meta}` envelope.

| Endpoint | Permission | Contract |
| --- | --- | --- |
| `GET/POST /pipelines` | `deals.view` / `pipelines.manage` | Tenant pipeline list or a pipeline with ordered `OPEN/WON/LOST` stages. |
| `GET/POST /deals`, `GET /deals/{id}` | `deals.view` / `deals.manage` | Tenant customer/contact/pipeline-staged deals; decimal strings and ISO-4217 currency. |
| `POST /deals/{id}/transition` | `deals.manage` | Requires current stage and optimistic `version`; conflicts map to `409 SALES_CONFLICT`. |
| `GET/POST/PATCH /tasks`, `POST /tasks/{id}/complete` | `tasks.view` / `tasks.manage` | Task/follow-up has exactly one tenant customer or deal target. |
| `GET /activities?customer_id=&deal_id=&page=&per_page=` | `activities.view` | Server-side tenant-scoped commercial timeline, descending by `occurred_at`; response exposes only identifier, linked IDs, event type, `actor_present` boolean (not the membership ID), and timestamp. |

`sales_activities` is a commercial timeline, not a replacement for existing security audit. Runtime authorization scopes, RLS efficacy, cross-tenant rejection, race behavior, CSRF, HTTP, and browser behavior remain `NOT_RUN` pending a separately authorized owned database environment.

### Activity response data minimization (W3 stabilization)

The `GET /activities` response uses `{data,meta}`. Each item contains `id`, `customer_id`, `deal_id`, `task_id`, `event_type`, `actor_present` (boolean), and `occurred_at`. The raw `actor_membership_id` and `metadata` are not public response fields. The frontend validates the public fields it consumes before rendering. All change endpoints must preserve the existing same-origin XSRF cookie/header contract; no CSRF bypass is permitted.
