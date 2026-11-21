# Daleel CRM API

Standalone Laravel modular-monolith API. Current foundations include versioned HTTP/health, global tenant-user session auth, strict company isolation and RBAC, PostgreSQL RLS, durable security audit, and a separate provider identity/session/MFA/capability/approval primitive. There is no public provider registration, tenant provisioning/recovery, billing, Leads, Customers, or production deployment in this control.

Read the contracts in [`docs/`](docs/):

- [Architecture](docs/ARCHITECTURE.md)
- [API conventions](docs/API_CONVENTIONS.md)
- [Security baseline](docs/SECURITY_BASELINE.md)
- [Provider security boundary](docs/PROVIDER_SECURITY.md)
- [Durable security audit](docs/SECURITY_AUDIT.md)
- [PostgreSQL RLS boundary](docs/RLS_ARCHITECTURE.md)
- [Local development](docs/LOCAL_DEVELOPMENT.md)
- [Module conventions](docs/MODULE_CONVENTIONS.md)
- [OpenAPI foundation](docs/openapi.yaml)

The local API base is `http://127.0.0.1:8000/api/v1`. Health routes are `/health`, `/health/live`, and `/health/ready`; provider routes are under `/super`. Migrations must target an explicitly verified PostgreSQL database with migration-owner credentials. Ordinary tenant and provider API processes require distinct non-owner DB roles.
