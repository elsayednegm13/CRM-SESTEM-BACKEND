# W2 Customers, Contacts, and Lead Conversion — Source Contract

This contract is source-only until a separately authorized owned PostgreSQL acceptance run. It does not claim HTTP execution.

All endpoints live below the existing authenticated, Host-resolved `/api/v1/company` route group. Client `tenant_id`, role, and tenant selector values are rejected by the existing middleware; tenant identity comes from the server context.

| Endpoint | Permission | Result |
|---|---|---|
| `GET /customers?search=&page=&per_page=` | `customers.view` | `{data: Customer[], meta: {page, per_page, total, request_id}}` |
| `POST /customers` | `customers.manage` | `201 {data: Customer, meta}` |
| `GET /customers/{id}` | `customers.view` | Customer with tenant-bound contacts and addresses |
| `PATCH /customers/{id}` | `customers.manage` | Updated customer |
| `POST /customers/{id}/contacts` | `customers.manage` | `201` contact; one primary contact per customer at the DB boundary |
| `GET /customers/{id}/contacts` | `customers.view` | Tenant-bound contact list |
| `PATCH /customers/{id}/contacts/{contact}` | `customers.manage` | Updated contact; primary contact selection is tenant/customer scoped |
| `GET /customers/{id}/addresses` | `customers.view` | Tenant-bound address list |
| `POST /customers/{id}/addresses` | `customers.manage` | `201` address with GENERAL/BILLING/SHIPPING role |
| `PATCH /customers/{id}/addresses/{address}` | `customers.manage` | Updated address |
| `POST /leads/{id}/convert` | `leads.convert` and `customers.manage` | `201` conversion; matching replay returns the original conversion, different intent returns `409 LEAD_CONVERSION_CONFLICT` |

`2026_11_06_000066_create_customers_contacts_and_lead_conversions.php` is additive, forward-only source and was not executed. It proposes tenant-leading foreign keys, FORCE RLS, `PUBLIC` revocation, exact runtime column grants, unique tenant/source-lead conversion linkage, and tenant-local exact normalized email/phone duplicate constraints. Runtime RLS, transaction behavior, and HTTP responses remain `NOT_RUN`.

`2026_11_06_000067_extend_customer_contact_and_address_runtime_grants.php` is a separate source-only follow-up. It grants only the runtime columns required for contact and address updates after 066; it changes no inherited role, RLS, ACL, or security-definer contract. Neither migration was executed.

The central audit writers currently expose only fixed security/tenant-staff vocabularies whose targets do not include customer, contact, address, or lead conversion. W2 deliberately does not invent a parallel audit channel. Conversion retains its tenant/member/time record in `lead_conversions`; central audit-event integration requires a separately reviewed, forward-only vocabulary and schema contract.
