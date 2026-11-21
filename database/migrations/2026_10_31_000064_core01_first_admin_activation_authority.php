<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/**
 * Actor-bound first-admin activation authority (CORE-01).
 *
 * Reconstructs a signed, single-use, session-bound activation receipt so the
 * PENDING_FIRST_PASSWORD_CHANGE -> ACTIVE rotation can succeed with an
 * independent issuer attestation, closing the documented weakness of the old
 * core01_activate_first_admin (session_user + old-hash knowledge only).
 *
 * Strict reuse, no new standing authority:
 *  - No new login role, no new BYPASSRLS, no direct table privilege grants.
 *    Login roles keep EXECUTE-only access; every table write happens inside a
 *    SECURITY DEFINER function owned by the identity that already holds the
 *    required RLS authority (migration 056 pattern).
 *  - Issuer identity = daleel_tenant_auth_lookup (the only role allowed to read
 *    tenant_staff_users.password_hash, via the migration 026 TENANT_PREAUTH
 *    policy). It attests the founder by reusing core01_lookup_pending_first_admin.
 *  - Consumer identity = daleel_b10b_owner / session_user dl_onboarding, reusing
 *    the migration 047 activation RLS policies for the atomic rotation.
 *  - The receipt table is owned by the issuer; the consumer never touches it
 *    directly. A dedicated redeem function (issuer-owned, EXECUTE granted to the
 *    consumer owner) bridges the two identities without any table grant.
 *
 * The old core01_activate_first_admin, migration 048 REVOKE, and the HTTP 503
 * gate are left intact. This path uses independent signed authority; it does
 * not reopen the old one.
 */
return new class extends Migration
{
    public function up(): void
    {
        // PostgreSQL requires target-owner CREATE privilege for ALTER OWNER and
        // for an issuer-owned object to live in public. The grant exists only
        // inside this transactional migration and is revoked before it ends
        // (mirrors migration 047).
        DB::unprepared('GRANT CREATE ON SCHEMA public TO daleel_tenant_auth_lookup');
        DB::unprepared('GRANT CREATE ON SCHEMA public TO daleel_core01_authority_definer');

        // ---- Signing-key generation accessor (secret stays confined) ----
        // The issuer/redeem functions must read the ACTIVE signing-key generation
        // to bind and later re-validate a receipt, but their owner
        // (daleel_tenant_auth_lookup) must NEVER see core01_sql_signing_keys.secret
        // (the 32-byte HMAC key, migration 049). Following this migration's own
        // "bridge identities via EXECUTE, no table grant" rule, a narrow accessor
        // owned by daleel_core01_authority_definer -- the only non-owner role with
        // SELECT on the signing-key table (migration 059) -- returns ONLY the active
        // generation integer and holds FOR SHARE so the key cannot be rotated out
        // mid-transaction. The issuer gets EXECUTE on this accessor, never a grant
        // on the secret-bearing table.
        DB::unprepared(<<<'SQL'
            CREATE FUNCTION public.core01_active_signing_key_generation()
            RETURNS integer
            LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public
            AS $fn$
            DECLARE v_key integer;
            BEGIN
                SELECT key_generation INTO v_key FROM public.core01_sql_signing_keys
                    WHERE id = 1 AND status = 'ACTIVE' FOR SHARE;
                RETURN v_key;
            END
            $fn$
        SQL);
        DB::unprepared('ALTER FUNCTION public.core01_active_signing_key_generation() OWNER TO daleel_core01_authority_definer');
        DB::unprepared('REVOKE ALL ON FUNCTION public.core01_active_signing_key_generation() FROM PUBLIC');
        DB::unprepared('GRANT EXECUTE ON FUNCTION public.core01_active_signing_key_generation() TO daleel_tenant_auth_lookup');

        DB::unprepared(<<<'SQL'
            CREATE TABLE public.core01_first_admin_activation_receipts (
                id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
                token_hash char(64) NOT NULL UNIQUE CHECK(token_hash ~ '^[a-f0-9]{64}$'),
                tenant_id uuid NOT NULL,
                staff_user_id uuid NOT NULL,
                membership_id uuid NOT NULL,
                request_id uuid NOT NULL,
                action_key text NOT NULL CHECK(action_key = 'first_admin.activate'),
                session_hash char(64) NOT NULL CHECK(session_hash ~ '^[a-f0-9]{64}$'),
                session_generation uuid NOT NULL,
                bound_password_hash text NOT NULL CHECK(bound_password_hash LIKE '$argon2id$%'),
                new_password_hash text NOT NULL CHECK(new_password_hash LIKE '$argon2id$%'),
                key_generation integer NOT NULL,
                issued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
                expires_at timestamptz NOT NULL,
                consumed_at timestamptz NULL,
                CHECK(expires_at > issued_at),
                CHECK(new_password_hash <> bound_password_hash)
            )
        SQL);
        DB::unprepared("CREATE UNIQUE INDEX core01_first_admin_activation_receipts_live
            ON public.core01_first_admin_activation_receipts (tenant_id, staff_user_id)
            WHERE consumed_at IS NULL");
        DB::unprepared('REVOKE ALL ON public.core01_first_admin_activation_receipts FROM PUBLIC');

        // ---- Issuer: attests the PENDING founder and mints a signed receipt ----
        // Runs as daleel_tenant_auth_lookup so it can reuse
        // core01_lookup_pending_first_admin (which reads password_hash under the
        // TENANT_PREAUTH policy). The stored hash the issuer re-reads must match
        // the hash the application bound; a receipt is never minted from
        // client-supplied data alone.
        DB::unprepared(<<<'SQL'
            CREATE FUNCTION public.core01_first_admin_activation_issue_receipt(
                p_hostname text, p_base_domain text, p_env_scope text, p_email text,
                p_bound_hash text, p_new_hash text, p_session_hash text, p_session_generation uuid,
                p_request_id uuid, p_token_hash text
            ) RETURNS uuid
            LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public
            AS $fn$
            DECLARE
                v_tenant uuid; v_user uuid; v_membership uuid; v_hash text; v_auth bigint;
                v_key integer; v_receipt uuid;
            BEGIN
                IF session_user <> 'dl_tauth' OR p_hostname IS NULL OR p_base_domain IS NULL
                   OR p_env_scope IS NULL OR p_email IS NULL OR p_bound_hash NOT LIKE '$argon2id$%'
                   OR p_new_hash NOT LIKE '$argon2id$%' OR p_new_hash = p_bound_hash
                   OR p_session_hash !~ '^[a-f0-9]{64}$' OR p_session_generation IS NULL
                   OR p_request_id IS NULL OR p_token_hash !~ '^[a-f0-9]{64}$' THEN
                    RAISE EXCEPTION 'activation receipt denied' USING ERRCODE = 'PZ403';
                END IF;
                SELECT l.tenant_id, l.staff_user_id, l.membership_id, l.password_hash, l.auth_version
                  INTO v_tenant, v_user, v_membership, v_hash, v_auth
                  FROM public.core01_lookup_pending_first_admin(p_hostname, p_base_domain, p_env_scope, p_email) l;
                IF NOT FOUND OR v_hash IS DISTINCT FROM p_bound_hash OR v_auth <> 1 THEN
                    RAISE EXCEPTION 'activation receipt denied' USING ERRCODE = 'PZ403';
                END IF;
                v_key := public.core01_active_signing_key_generation();
                IF v_key IS NULL THEN
                    RAISE EXCEPTION 'activation key unavailable' USING ERRCODE = 'PZ503';
                END IF;
                -- One live receipt per founder: supersede any prior unconsumed one.
                UPDATE public.core01_first_admin_activation_receipts SET consumed_at = clock_timestamp()
                    WHERE tenant_id = v_tenant AND staff_user_id = v_user AND consumed_at IS NULL;
                INSERT INTO public.core01_first_admin_activation_receipts
                    (token_hash, tenant_id, staff_user_id, membership_id, request_id, action_key,
                     session_hash, session_generation, bound_password_hash, new_password_hash,
                     key_generation, expires_at)
                VALUES (p_token_hash, v_tenant, v_user, v_membership, p_request_id, 'first_admin.activate',
                     p_session_hash, p_session_generation, p_bound_hash, p_new_hash,
                     v_key, clock_timestamp() + interval '90 seconds')
                RETURNING id INTO v_receipt;
                RETURN v_receipt;
            END
            $fn$
        SQL);

        // ---- Redeem: single-use, session-bound consumption of the receipt ----
        // Issuer-owned (owns the receipt table). EXECUTE is granted to the
        // consumer owner so the rotation function can call it; it is guarded to
        // the activation login (session_user dl_onboarding) and runs inside the
        // consumer's transaction, so a failed rotation rolls the consumption back.
        DB::unprepared(<<<'SQL'
            CREATE FUNCTION public.core01_first_admin_activation_redeem_receipt(
                p_token text, p_session_hash text, p_session_generation uuid,
                p_tenant uuid, p_user uuid, p_membership uuid, p_request_id uuid
            ) RETURNS public.core01_first_admin_activation_receipts
            LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public
            AS $fn$
            DECLARE v public.core01_first_admin_activation_receipts%ROWTYPE;
            BEGIN
                IF session_user <> 'dl_onboarding' OR p_token !~ '^[a-f0-9]{64}$'
                   OR p_session_hash !~ '^[a-f0-9]{64}$' OR p_session_generation IS NULL
                   OR p_tenant IS NULL OR p_user IS NULL OR p_membership IS NULL OR p_request_id IS NULL THEN
                    RAISE EXCEPTION 'activation redeem denied' USING ERRCODE = 'PZ403';
                END IF;
                SELECT * INTO v FROM public.core01_first_admin_activation_receipts
                    WHERE token_hash = encode(public.digest(convert_to(p_token, 'UTF8'), 'sha256'), 'hex') FOR UPDATE;
                IF NOT FOUND THEN
                    RAISE EXCEPTION 'activation redeem denied' USING ERRCODE = 'PZ403';
                END IF;
                IF v.consumed_at IS NOT NULL THEN
                    RAISE EXCEPTION 'activation replay conflict' USING ERRCODE = 'PZ409';
                END IF;
                IF v.expires_at <= clock_timestamp() OR v.tenant_id <> p_tenant OR v.staff_user_id <> p_user
                   OR v.membership_id <> p_membership OR v.session_hash <> p_session_hash
                   OR v.session_generation <> p_session_generation OR v.request_id <> p_request_id
                   OR v.action_key <> 'first_admin.activate' THEN
                    RAISE EXCEPTION 'activation redeem denied' USING ERRCODE = 'PZ403';
                END IF;
                IF public.core01_active_signing_key_generation() IS DISTINCT FROM v.key_generation THEN
                    RAISE EXCEPTION 'activation key inactive' USING ERRCODE = 'PZ403';
                END IF;
                UPDATE public.core01_first_admin_activation_receipts SET consumed_at = clock_timestamp() WHERE id = v.id;
                RETURN v;
            END
            $fn$
        SQL);

        DB::unprepared('ALTER TABLE public.core01_first_admin_activation_receipts OWNER TO daleel_tenant_auth_lookup');
        DB::unprepared('ALTER FUNCTION public.core01_first_admin_activation_issue_receipt(text,text,text,text,text,text,text,uuid,uuid,text) OWNER TO daleel_tenant_auth_lookup');
        DB::unprepared('ALTER FUNCTION public.core01_first_admin_activation_redeem_receipt(text,text,uuid,uuid,uuid,uuid,uuid) OWNER TO daleel_tenant_auth_lookup');
        DB::unprepared('REVOKE CREATE ON SCHEMA public FROM daleel_tenant_auth_lookup');
        DB::unprepared('REVOKE CREATE ON SCHEMA public FROM daleel_core01_authority_definer');

        DB::unprepared('REVOKE ALL ON FUNCTION public.core01_first_admin_activation_issue_receipt(text,text,text,text,text,text,text,uuid,uuid,text) FROM PUBLIC');
        DB::unprepared('GRANT EXECUTE ON FUNCTION public.core01_first_admin_activation_issue_receipt(text,text,text,text,text,text,text,uuid,uuid,text) TO daleel_tenant_auth_client');
        DB::unprepared('REVOKE ALL ON FUNCTION public.core01_first_admin_activation_redeem_receipt(text,text,uuid,uuid,uuid,uuid,uuid) FROM PUBLIC');
        DB::unprepared('GRANT EXECUTE ON FUNCTION public.core01_first_admin_activation_redeem_receipt(text,text,uuid,uuid,uuid,uuid,uuid) TO daleel_b10b_owner');

        // ---- Consumer: atomic redeem + the migration 047 rotation ----
        // Owner daleel_b10b_owner (reuses the 047 activation RLS policies).
        // Mirrors the old core01_activate_first_admin verification/rotation body
        // verbatim, but drives it from the redeemed receipt instead of raw
        // caller-supplied hashes. The old function is left untouched.
        DB::unprepared(<<<'SQL'
            CREATE FUNCTION public.core01_activate_first_admin_with_authority(
                p_token text, p_session_hash text, p_session_generation uuid,
                p_tenant uuid, p_user uuid, p_membership uuid, p_hostname text, p_request_id uuid
            ) RETURNS boolean
            LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public
            AS $fn$
            DECLARE
                v_receipt public.core01_first_admin_activation_receipts%ROWTYPE;
                v_operation public.provider_control_operations%ROWTYPE;
                v_staff public.tenant_staff_users%ROWTYPE;
                v_membership public.tenant_staff_memberships%ROWTYPE;
                v_role uuid;
                v_now timestamptz := pg_catalog.clock_timestamp();
            BEGIN
                IF session_user <> 'dl_onboarding' OR p_token !~ '^[a-f0-9]{64}$'
                   OR p_session_hash !~ '^[a-f0-9]{64}$' OR p_session_generation IS NULL
                   OR p_tenant IS NULL OR p_user IS NULL OR p_membership IS NULL
                   OR p_hostname IS NULL OR p_request_id IS NULL THEN
                    RAISE EXCEPTION 'first admin activation denied' USING ERRCODE = 'PZ403';
                END IF;
                v_receipt := public.core01_first_admin_activation_redeem_receipt(
                    p_token, p_session_hash, p_session_generation, p_tenant, p_user, p_membership, p_request_id);
                SELECT * INTO v_operation FROM public.provider_control_operations o
                WHERE o.target_tenant_id = p_tenant AND o.action_key = 'company.provision'
                  AND o.status = 'SUCCEEDED' AND o.ticket_reference = 'CORE01V1'
                  AND o.approval_request_id IS NULL FOR UPDATE;
                IF NOT FOUND OR p_hostname <> v_operation.canonical_slug || '.' || current_setting('app.core01_base_domain', true) THEN
                    RAISE EXCEPTION 'first admin activation denied' USING ERRCODE = 'PZ403';
                END IF;
                PERFORM pg_catalog.set_config('app.context_mode','CORE01_FIRST_ADMIN_ACTIVATION',true);
                PERFORM pg_catalog.set_config('app.core01_v1_operation_id',v_operation.id::text,true);
                SELECT * INTO v_staff FROM public.tenant_staff_users u
                WHERE u.tenant_id = p_tenant AND u.id = p_user FOR UPDATE;
                IF NOT FOUND OR v_staff.status <> 'PENDING_FIRST_PASSWORD_CHANGE'
                   OR v_staff.auth_version <> 1 OR v_staff.canonical_email <> v_operation.founder_email
                   OR v_staff.password_hash <> v_receipt.bound_password_hash THEN
                    RAISE EXCEPTION 'first admin activation denied' USING ERRCODE = 'PZ403';
                END IF;
                SELECT * INTO v_membership FROM public.tenant_staff_memberships m
                WHERE m.tenant_id = p_tenant AND m.id = p_membership AND m.staff_user_id = p_user;
                IF NOT FOUND OR v_membership.status <> 'ACTIVE'
                   OR v_membership.created_by_provider_operation_id <> v_operation.id THEN
                    RAISE EXCEPTION 'first admin activation denied' USING ERRCODE = 'PZ403';
                END IF;
                SELECT r.id INTO v_role FROM public.roles r
                WHERE r.tenant_id = p_tenant AND r.normalized_name = 'company_admin'
                  AND r.status = 'ACTIVE' AND r.version = 1;
                IF v_role IS NULL THEN
                    RAISE EXCEPTION 'first admin role missing' USING ERRCODE = 'PZ503';
                END IF;
                UPDATE public.tenant_staff_users SET password_hash=v_receipt.new_password_hash,
                    status='ACTIVE',auth_version=auth_version+1,updated_at=v_now
                WHERE tenant_id=p_tenant AND id=p_user;
                INSERT INTO public.tenant_staff_membership_roles
                    (id,tenant_id,membership_id,role_id,assigned_by_membership_id,
                     assigned_by_provider_operation_id,assigned_at,revoked_at,
                     revoked_by_membership_id,created_at,updated_at)
                VALUES (pg_catalog.gen_random_uuid(),p_tenant,p_membership,v_role,NULL,
                    v_operation.id,v_now,NULL,NULL,v_now,v_now);
                INSERT INTO public.tenant_staff_security_events
                    (id,occurred_at,tenant_id,event_type,outcome,request_id,actor_membership_id,
                     provider_operation_id,target_staff_user_id,metadata)
                VALUES (pg_catalog.gen_random_uuid(),v_now,p_tenant,'tenant_staff.password_set',
                    'SUCCESS',p_request_id,NULL,v_operation.id,p_user,'{}'::jsonb);
                RETURN true;
            END
            $fn$
        SQL);
        DB::unprepared('REVOKE ALL ON FUNCTION public.core01_activate_first_admin_with_authority(text,text,uuid,uuid,uuid,uuid,text,uuid) FROM PUBLIC');
        DB::unprepared('GRANT EXECUTE ON FUNCTION public.core01_activate_first_admin_with_authority(text,text,uuid,uuid,uuid,uuid,text,uuid) TO dl_onboarding');
    }

    public function down(): void
    {
        throw new RuntimeException('CORE-01 first-admin activation authority is forward-only.');
    }
};
