# API conventions

- All HTTP contracts live under `/api/v1`; API routes do not share frontend routes.
- Success envelope: `{ "data": {}, "meta": { "request_id": "uuid" } }`.
- Error envelope: `{ "error": { "code": "STABLE_CODE", "message": "Safe message" }, "meta": { "request_id": "uuid" } }`.
- Current stable errors include `RESOURCE_NOT_FOUND`, `VALIDATION_FAILED`, `AUTH_UNAUTHENTICATED`, `AUTH_INVALID_CREDENTIALS`, `AUTH_SESSION_EXPIRED`, `AUTH_CSRF_INVALID`, `AUTH_EMAIL_VERIFICATION_INVALID`, `AUTH_PASSWORD_RESET_INVALID`, `AUTH_RATE_LIMITED`, `RATE_LIMITED`, `TENANT_MEMBERSHIP_REQUIRED`, `TENANT_CONTEXT_INTEGRITY_ERROR`, `TENANT_UNAVAILABLE`, `TENANT_CONTEXT_REQUIRED`, `TENANT_SELECTOR_NOT_ALLOWED`, and `INTERNAL_ERROR`.
- Every request receives a server-generated UUID unless a valid UUID `X-Request-ID` is supplied. It is returned in JSON metadata and the `X-Request-ID` header.
- Never return stack traces, SQL, exception class names, credentials, tokens, cookies, or raw payloads.
- Authentication routes are documented in `openapi.yaml`. Browser auth uses Sanctum's stateful session and CSRF cookie flow; no bearer token or Personal Access Token API is exposed.
- Registration is disabled. `/auth/me`, logout, and email verification require an authenticated server session. Login, forgot password, and reset password use exact local Origin allowlisting and auth-specific limits.
- `GET /company/context` requires the Control 05 session, fresh identity validation, exactly one active membership, and an ACTIVE tenant. It returns only company ID/name/slug/timezone/locale and membership ID/status. `X-Tenant-ID` is rejected; `tenant_id` in the query or body is invalid. Cookie or frontend role/company markers have no authority. There is no ordinary company list or switch endpoint.
- `GET /company/authorization` returns the current membership's active roles, unioned grants, and authorization version. `GET /company/roles` requires `role.view` and lists active roles in the resolved company only. Both use the 07A guard. No RBAC mutation HTTP route exists in 07B. `AUTHORIZATION_DENIED` is a safe 403.
- Unscoped grants use `null`; scopeable grants use a fixed scope enum. `TEAM` and `NONE` grant no object access in 07B. Object facts must be loaded server-side from the same tenant; client role, scope, and company markers have no authority.
- The general API limiter is not authorization. Identity, payment, webhook, export, and other route-specific policies remain separate concerns.
- Keep controllers thin, validate input at the boundary, bound list sizes, allowlist sort/filter fields, and authorize each resource operation in its owning module.
- OpenAPI is tracked at `docs/openapi.yaml`; additive compatibility and deprecation belong to the released API version.
