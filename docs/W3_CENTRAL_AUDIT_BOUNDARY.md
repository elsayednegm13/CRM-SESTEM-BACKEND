# W3 central audit boundary — source review

`sales_activities` is a tenant-scoped commercial timeline. It is not the central security audit and is not asserted as such.

The existing `TenantStaffAuditWriter` only accepts fixed staff- or role-targeted event types and writes an always-empty metadata shape to `tenant_staff_security_events`. Customer, contact, address, lead-conversion, deal and task targets cannot be represented through its public methods.

`SecurityAuditWriter` accepts only the fixed `AuditEventType` taxonomy and its methods require either `TenantContext` or provider/founder contexts plus a transaction/target contract. Current tenant-staff W2/W3 request handlers provide `TenantStaffContext`; adapting it would change a security-audit contract, its event taxonomy and likely the protected audit schema/test suite.

Result: `AUDIT_CONTRACT_BLOCKED_SEPARATE_SECURITY_CONTRACT`. The smallest safe follow-up is a separately authorized forward-only central-audit design that specifies an immutable business target model, event vocabulary, transaction behavior, redacted metadata and tenant-runtime write boundary, followed by DB/RLS acceptance. This W3 source change does not add a parallel security logger or alter ACL/RLS/auth/audit tables.
