#!/usr/bin/env bash
# CORE-01 G2 — build the isolated synthetic sandbox database and seed subjects.
#
# Non-destructive by construction:
#   * d1_fresh / d1_upgrade are NEVER written. d1_fresh is used only as a
#     read-only CREATE DATABASE ... TEMPLATE source (a copy, not a mutation).
#   * The only database written is g2_core01 (g2_ prefix enforced by the guard).
#   * No role / LOGIN change, no shared Docker config change, no new network.
#
# Every write path is gated by g2_guard_assert (see guard.sh): live identity
# (system_identifier + published port) is verified against the single
# authorized sandbox before anything is created or seeded.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./guard.sh
source "$SCRIPT_DIR/guard.sh"

readonly G2_DB="g2_core01"
readonly TEMPLATE_DB="d1_fresh"

# 1. Assert identity BEFORE any write. Refuses on mismatch / forbidden target.
g2_guard_assert "$G2_DB"

# 2. Recreate g2_core01 from the d1_fresh template (full 65-migration schema,
#    signing key id=1 ACTIVE), connecting to the 'postgres' maintenance DB.
#    WITH (FORCE) drops any idle connection to the stale partial g2_core01.
#    The template read of d1_fresh does not modify it.
echo "[build-g2] (re)creating $G2_DB from TEMPLATE $TEMPLATE_DB ..." >&2
docker exec -i "$G2_ALLOWED_CONTAINER" psql -U postgres -d postgres -v ON_ERROR_STOP=1 <<SQL
DROP DATABASE IF EXISTS ${G2_DB} WITH (FORCE);
CREATE DATABASE ${G2_DB} TEMPLATE ${TEMPLATE_DB};
SQL

# 3. Seed the synthetic AL09/AL11 subjects (A + B) as superuser (BYPASSRLS).
#    Statuses ACTIVE and versions = 1 so the register_attempt PZ403 join in
#    migration 057 is satisfied by genuine rows — the test asserts real
#    behaviour, nothing is stubbed to force a pass. password_hash is a non-null
#    placeholder: the service-layer tests never perform a password comparison
#    (they call register() with a pre-built context, not the login path).
echo "[build-g2] seeding synthetic subjects A + B into $G2_DB ..." >&2
# The bootstrap membership's creator must pre-exist (BEFORE trigger
# tenant_staff_membership_creator_valid), so we seed the REAL provisioning
# lineage: a provider user + one company.provision provider_control_operation
# per tenant, then each founder membership references its op via
# created_by_provider_operation_id. tenant_staff_users additionally carries a
# DEFERRED constraint trigger (tenant_staff_user_requires_membership) whose
# SELECT runs SECURITY DEFINER as daleel_b10b_owner (no BYPASSRLS) and is
# therefore filtered by FORCE RLS: it only sees the membership when the session
# is in TENANT context for that tenant. So each tenant is seeded in its own
# transaction with SET LOCAL app.context_mode/tenant_id/user_id matching that
# tenant. No trigger is disabled, no role privilege is changed; this mirrors how
# the application itself inserts under tenant RLS context.
g2_guard_psql "$G2_DB" -v ON_ERROR_STOP=1 <<'SQL'
-- Global provider lineage (no tenant RLS context required; target_tenant_id
-- has no FK, so these may precede the tenant rows).
BEGIN;
INSERT INTO provider_users (id, email, password, status) VALUES
  ('d0000001-0001-4001-8001-000000000001','g2-provisioner@proof.invalid','$argon2id$v=19$m=65536,t=4,p=1$c2VlZHBsYWNlaG9sZGVy$c2VlZHBsYWNlaG9sZGVycGxhY2Vob2xkZXJzZWVk','ACTIVE')
ON CONFLICT (id) DO NOTHING;
INSERT INTO provider_control_operations
  (id, action_key, requester_provider_user_id, idempotency_key_hash, intent_digest, target_tenant_id, reason, ticket_reference, expires_at, display_name, canonical_slug, timezone, founder_email) VALUES
  ('e0000001-0001-4001-8001-000000000001','company.provision','d0000001-0001-4001-8001-000000000001',
   repeat('a',64), repeat('b',64),'a0000001-0001-4001-8001-000000000001','G2 synthetic provisioning A','G2-AL09-A', now()+interval '1 day',
   'AL Proof Tenant A','al09-proof-a','UTC','al09-a@proof.invalid'),
  ('e0000001-0001-4001-8001-000000000002','company.provision','d0000001-0001-4001-8001-000000000001',
   repeat('c',64), repeat('d',64),'a0000001-0001-4001-8001-000000000002','G2 synthetic provisioning B','G2-AL09-B', now()+interval '1 day',
   'AL Proof Tenant B','al09-proof-b','UTC','al09-b@proof.invalid')
ON CONFLICT (id) DO NOTHING;
COMMIT;

-- Tenant A (own TENANT RLS context so the deferred membership trigger resolves).
BEGIN;
SET LOCAL app.context_mode = 'TENANT';
SET LOCAL app.tenant_id = 'a0000001-0001-4001-8001-000000000001';
SET LOCAL app.user_id   = 'b0000001-0001-4001-8001-000000000001';
INSERT INTO tenants (id, display_name, slug, status, timezone, default_locale, created_at, updated_at) VALUES
  ('a0000001-0001-4001-8001-000000000001','AL Proof Tenant A','al09-proof-a','ACTIVE','UTC','en',now(),now())
ON CONFLICT (id) DO UPDATE SET status='ACTIVE';
INSERT INTO tenant_staff_users (id, tenant_id, canonical_email, display_email, display_name, password_hash, status, auth_version, created_at, updated_at) VALUES
  ('b0000001-0001-4001-8001-000000000001','a0000001-0001-4001-8001-000000000001','al09-a@proof.invalid','al09-a@proof.invalid','AL Proof Admin A','$argon2id$v=19$m=65536,t=4,p=1$c2VlZHBsYWNlaG9sZGVy$c2VlZHBsYWNlaG9sZGVycGxhY2Vob2xkZXJzZWVk','ACTIVE',1,now(),now())
ON CONFLICT (id) DO UPDATE SET status='ACTIVE', auth_version=1;
INSERT INTO tenant_staff_memberships (id, tenant_id, staff_user_id, status, authorization_version, joined_at, created_by_provider_operation_id, created_at, updated_at) VALUES
  ('c0000001-0001-4001-8001-000000000001','a0000001-0001-4001-8001-000000000001','b0000001-0001-4001-8001-000000000001','ACTIVE',1,now(),'e0000001-0001-4001-8001-000000000001',now(),now())
ON CONFLICT (id) DO UPDATE SET status='ACTIVE', authorization_version=1;
COMMIT;

-- Tenant B.
BEGIN;
SET LOCAL app.context_mode = 'TENANT';
SET LOCAL app.tenant_id = 'a0000001-0001-4001-8001-000000000002';
SET LOCAL app.user_id   = 'b0000001-0001-4001-8001-000000000002';
INSERT INTO tenants (id, display_name, slug, status, timezone, default_locale, created_at, updated_at) VALUES
  ('a0000001-0001-4001-8001-000000000002','AL Proof Tenant B','al09-proof-b','ACTIVE','UTC','en',now(),now())
ON CONFLICT (id) DO UPDATE SET status='ACTIVE';
INSERT INTO tenant_staff_users (id, tenant_id, canonical_email, display_email, display_name, password_hash, status, auth_version, created_at, updated_at) VALUES
  ('b0000001-0001-4001-8001-000000000002','a0000001-0001-4001-8001-000000000002','al09-b@proof.invalid','al09-b@proof.invalid','AL Proof Admin B','$argon2id$v=19$m=65536,t=4,p=1$c2VlZHBsYWNlaG9sZGVy$c2VlZHBsYWNlaG9sZGVycGxhY2Vob2xkZXJzZWVk','ACTIVE',1,now(),now())
ON CONFLICT (id) DO UPDATE SET status='ACTIVE', auth_version=1;
INSERT INTO tenant_staff_memberships (id, tenant_id, staff_user_id, status, authorization_version, joined_at, created_by_provider_operation_id, created_at, updated_at) VALUES
  ('c0000001-0001-4001-8001-000000000002','a0000001-0001-4001-8001-000000000002','b0000001-0001-4001-8001-000000000002','ACTIVE',1,now(),'e0000001-0001-4001-8001-000000000002',now(),now())
ON CONFLICT (id) DO UPDATE SET status='ACTIVE', authorization_version=1;
COMMIT;
SQL

# 4. Verify the seed landed and report counts (read-only).
echo "[build-g2] verifying seed ..." >&2
g2_guard_psql "$G2_DB" -tAc "SELECT 'tenants='||count(*) FROM tenants WHERE id::text LIKE 'a0000001-%'
  UNION ALL SELECT 'staff='||count(*) FROM tenant_staff_users WHERE id::text LIKE 'b0000001-%'
  UNION ALL SELECT 'memberships='||count(*) FROM tenant_staff_memberships WHERE id::text LIKE 'c0000001-%'
  UNION ALL SELECT 'signing_key_active='||count(*) FROM core01_sql_signing_keys WHERE id=1 AND status='ACTIVE';"

echo "[build-g2] done." >&2
