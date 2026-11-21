-- CORE-01 G2 — acceptance cluster fixtures (port 55460).
-- Run as postgres superuser (bypasses RLS; synthetic test cluster only).
-- Creates correct base-domain registry, two tenants with immutable slugs
-- from creation, hostname mappings, and staff identity with argon2id hash.
--
-- Instruction 5 / instruction 7 compliance:
--   - Slugs al09-a / al09-b are set at INSERT time (never UPDATE — slugs are immutable).
--   - Hostnames al09-a.daleel.localhost / al09-b.daleel.localhost from creation.
--   - Staff email al09-admin@proof.invalid, password hash = Secfix06TestPass! (argon2id).
--   - tenant_registry_domains: daleel.localhost, mapping_version=1, LOCAL_TEST, is_active=true.
--   - Staff user + membership seeded in a single block with triggers disabled:
--     * tenant_staff_user_requires_membership: deferred, fires at COMMIT (needs both rows)
--     * provider FK chain requires a bootstrap provider_control_operations record
--     * Triggers disabled/re-enabled within the transaction (superuser privilege, test cluster only)
--
-- Identity guard: must be run against the G2 acceptance cluster only.
-- The build script verifies system_identifier before calling this file.
\set ON_ERROR_STOP on

-- ── 1. Registry domain ───────────────────────────────────────────────────────
INSERT INTO tenant_registry_domains (mapping_version, base_domain, environment_scope, is_active)
VALUES (1, 'daleel.localhost', 'LOCAL_TEST', true);

-- ── 2. Tenants (slugs from creation — immutable after INSERT) ────────────────
INSERT INTO tenants (id, display_name, slug, status, timezone, default_locale, created_at, updated_at)
VALUES (
    'a0000001-0001-4001-8001-000000000001',
    'AL09 Tenant A', 'al09-a', 'ACTIVE', 'Asia/Riyadh', 'ar', NOW(), NOW()
);

INSERT INTO tenants (id, display_name, slug, status, timezone, default_locale, created_at, updated_at)
VALUES (
    'a0000001-0001-4001-8001-000000000002',
    'AL09 Tenant B', 'al09-b', 'ACTIVE', 'Asia/Riyadh', 'ar', NOW(), NOW()
);

-- ── 3. Hostname mappings ─────────────────────────────────────────────────────
INSERT INTO tenant_hostnames (tenant_id, tenant_slug, base_domain, hostname, mapping_version)
VALUES ('a0000001-0001-4001-8001-000000000001', 'al09-a', 'daleel.localhost', 'al09-a.daleel.localhost', 1);

INSERT INTO tenant_hostnames (tenant_id, tenant_slug, base_domain, hostname, mapping_version)
VALUES ('a0000001-0001-4001-8001-000000000002', 'al09-b', 'daleel.localhost', 'al09-b.daleel.localhost', 1);

-- ── 4. Provider user + operations + staff (single transaction, triggers disabled) ──
-- The tenant_staff_user_requires_membership trigger is DEFERRABLE INITIALLY DEFERRED
-- and fires at COMMIT. The tenant_staff_membership_creator_check requires exactly
-- one of created_by_membership_id or created_by_provider_operation_id to be non-null.
-- For bootstrap insertion we must: disable triggers, insert all interdependent rows,
-- then re-enable. This is the authorized approach for test cluster fixture seeding.
BEGIN;

ALTER TABLE provider_users              DISABLE TRIGGER ALL;
ALTER TABLE provider_control_operations DISABLE TRIGGER ALL;
ALTER TABLE tenant_staff_users          DISABLE TRIGGER ALL;
ALTER TABLE tenant_staff_memberships    DISABLE TRIGGER ALL;

-- Provider user (required by FK on provider_control_operations)
INSERT INTO provider_users (id, email, password, status, auth_version, authorization_version, created_at, updated_at)
VALUES (
    'd0000001-0001-4001-8001-000000000001',
    'al09-provider@proof.invalid',
    '$argon2id$v=19$m=65536,t=4,p=1$NUVyMVNQNE1FYTJORnpRSw$t8gcLjmWuSyiGIBao2NH35XVtIrFcUVY9I7U7lngOGU',
    'ACTIVE', 1, 1, NOW(), NOW()
);

-- Bootstrap provision operations (SUCCEEDED, satisfies membership FK)
INSERT INTO provider_control_operations (
    id, action_key, requester_provider_user_id,
    idempotency_key_hash, intent_digest,
    target_tenant_id, status, result_reference,
    display_name, canonical_slug, timezone, founder_email, first_admin_display_name,
    reason, ticket_reference,
    expires_at, completed_at, created_at, updated_at
) VALUES (
    'e0000001-0001-4001-8001-000000000001', 'company.provision',
    'd0000001-0001-4001-8001-000000000001',
    'a09a000000000000000000000000000000000000000000000000000000000001',
    'a09b000000000000000000000000000000000000000000000000000000000001',
    'a0000001-0001-4001-8001-000000000001', 'SUCCEEDED',
    'b0000001-0001-4001-8001-000000000001',
    'AL09 Tenant A', 'al09-a', 'Asia/Riyadh', 'al09-admin@proof.invalid', 'AL09 Admin',
    'acceptance test bootstrap', 'g2-test-bootstrap',
    NOW() + interval '1 year', NOW(), NOW(), NOW()
);

INSERT INTO provider_control_operations (
    id, action_key, requester_provider_user_id,
    idempotency_key_hash, intent_digest,
    target_tenant_id, status, result_reference,
    display_name, canonical_slug, timezone, founder_email, first_admin_display_name,
    reason, ticket_reference,
    expires_at, completed_at, created_at, updated_at
) VALUES (
    'e0000001-0001-4001-8001-000000000002', 'company.provision',
    'd0000001-0001-4001-8001-000000000001',
    'a09a000000000000000000000000000000000000000000000000000000000002',
    'a09b000000000000000000000000000000000000000000000000000000000002',
    'a0000001-0001-4001-8001-000000000002', 'SUCCEEDED',
    'b0000001-0001-4001-8001-000000000002',
    'AL09 Tenant B', 'al09-b', 'Asia/Riyadh', 'al09-other@proof.invalid', 'AL09 Tenant B Admin',
    'acceptance test bootstrap', 'g2-test-bootstrap',
    NOW() + interval '1 year', NOW(), NOW(), NOW()
);

-- Staff users (password = Secfix06TestPass!, argon2id, m=65536 t=4 p=1, verified PASS)
INSERT INTO tenant_staff_users (
    id, tenant_id, canonical_email, display_email, display_name,
    password_hash, status, auth_version, created_at, updated_at
) VALUES (
    'b0000001-0001-4001-8001-000000000001',
    'a0000001-0001-4001-8001-000000000001',
    'al09-admin@proof.invalid', 'al09-admin@proof.invalid', 'AL09 Admin',
    '$argon2id$v=19$m=65536,t=4,p=1$NUVyMVNQNE1FYTJORnpRSw$t8gcLjmWuSyiGIBao2NH35XVtIrFcUVY9I7U7lngOGU',
    'ACTIVE', 1, NOW(), NOW()
);

INSERT INTO tenant_staff_users (
    id, tenant_id, canonical_email, display_email, display_name,
    password_hash, status, auth_version, created_at, updated_at
) VALUES (
    'b0000001-0001-4001-8001-000000000002',
    'a0000001-0001-4001-8001-000000000002',
    'al09-other@proof.invalid', 'al09-other@proof.invalid', 'AL09 Tenant B Admin',
    '$argon2id$v=19$m=65536,t=4,p=1$NUVyMVNQNE1FYTJORnpRSw$t8gcLjmWuSyiGIBao2NH35XVtIrFcUVY9I7U7lngOGU',
    'ACTIVE', 1, NOW(), NOW()
);

-- Staff memberships (one per tenant, created_by_provider_operation_id satisfies creator check)
INSERT INTO tenant_staff_memberships (
    id, tenant_id, staff_user_id, status, authorization_version,
    created_by_provider_operation_id, joined_at, created_at, updated_at
) VALUES (
    'c0000001-0001-4001-8001-000000000001',
    'a0000001-0001-4001-8001-000000000001',
    'b0000001-0001-4001-8001-000000000001',
    'ACTIVE', 1,
    'e0000001-0001-4001-8001-000000000001',
    NOW(), NOW(), NOW()
);

INSERT INTO tenant_staff_memberships (
    id, tenant_id, staff_user_id, status, authorization_version,
    created_by_provider_operation_id, joined_at, created_at, updated_at
) VALUES (
    'c0000001-0001-4001-8001-000000000002',
    'a0000001-0001-4001-8001-000000000002',
    'b0000001-0001-4001-8001-000000000002',
    'ACTIVE', 1,
    'e0000001-0001-4001-8001-000000000002',
    NOW(), NOW(), NOW()
);

-- Re-enable triggers
ALTER TABLE provider_users              ENABLE TRIGGER ALL;
ALTER TABLE provider_control_operations ENABLE TRIGGER ALL;
ALTER TABLE tenant_staff_users          ENABLE TRIGGER ALL;
ALTER TABLE tenant_staff_memberships    ENABLE TRIGGER ALL;

COMMIT;

-- ── 5. Verify ─────────────────────────────────────────────────────────────────
SELECT 'registry_domain=' || base_domain || ' env=' || environment_scope || ' active=' || is_active::text
  FROM tenant_registry_domains WHERE mapping_version = 1;
SELECT 'tenant_a_slug=' || slug FROM tenants WHERE id = 'a0000001-0001-4001-8001-000000000001';
SELECT 'tenant_b_slug=' || slug FROM tenants WHERE id = 'a0000001-0001-4001-8001-000000000002';
SELECT 'hostname_a=' || hostname FROM tenant_hostnames WHERE tenant_id = 'a0000001-0001-4001-8001-000000000001';
SELECT 'hostname_b=' || hostname FROM tenant_hostnames WHERE tenant_id = 'a0000001-0001-4001-8001-000000000002';
SELECT 'staff_a_email=' || canonical_email FROM tenant_staff_users WHERE id = 'b0000001-0001-4001-8001-000000000001';
SELECT 'staff_a_hash_prefix=' || left(password_hash, 15) FROM tenant_staff_users WHERE id = 'b0000001-0001-4001-8001-000000000001';
SELECT 'membership_a_op=' || created_by_provider_operation_id::text FROM tenant_staff_memberships WHERE id = 'c0000001-0001-4001-8001-000000000001';
