<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/**
 * Binds a durable tenant authority to one verified logical login attempt.
 * Retries atomically rebind the same row; they never create a second live
 * authority. The raw retry key and raw host-bound client proof never reach SQL.
 */
return new class extends Migration
{
    public function up(): void
    {
        DB::unprepared(<<<'SQL'
            DO $preflight$
            DECLARE v_members integer;
            BEGIN
                IF session_user <> 'daleel_b10b_owner' OR current_user <> 'daleel_b10b_owner' THEN
                    RAISE EXCEPTION 'CORE-01 login attempt migration requires daleel_b10b_owner';
                END IF;
                IF (SELECT pg_get_userbyid(p.proowner) FROM pg_proc p
                    WHERE p.oid='public.core01_tenant_authority_register_session(uuid,uuid,uuid,bigint,bigint,text,uuid,timestamptz)'::regprocedure)
                    <> 'daleel_core01_authority_definer' THEN
                    RAISE EXCEPTION 'CORE-01 authority register owner drifted';
                END IF;
                SELECT count(*) INTO v_members
                  FROM pg_auth_members m
                  JOIN pg_roles role_r ON role_r.oid=m.roleid
                  JOIN pg_roles member_r ON member_r.oid=m.member
                 WHERE role_r.rolname='daleel_core01_authority_definer'
                   AND member_r.rolname='daleel_b10b_owner'
                   AND m.admin_option AND NOT m.inherit_option AND m.set_option;
                IF v_members <> 1
                   OR (SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.roleid
                        WHERE r.rolname='daleel_core01_authority_definer') <> 1 THEN
                    RAISE EXCEPTION 'CORE-01 authority definer requires exact temporary deployment membership';
                END IF;
                IF NOT has_table_privilege('daleel_core01_authority_definer', 'public.core01_tenant_authority_sessions', 'SELECT,INSERT,UPDATE') THEN
                    RAISE EXCEPTION 'CORE-01 authority definer table contract drifted';
                END IF;
            END
            $preflight$
        SQL);

        DB::unprepared('GRANT USAGE, CREATE ON SCHEMA public TO daleel_core01_authority_definer');
        DB::unprepared(<<<'SQL'
            ALTER TABLE public.core01_tenant_authority_sessions
                ADD COLUMN login_attempt_hash char(64) NULL,
                ADD COLUMN login_attempt_client_hash char(64) NULL,
                ADD COLUMN login_attempt_host_hash char(64) NULL,
                ADD COLUMN login_attempt_expires_at timestamptz NULL,
                ADD CONSTRAINT core01_tenant_authority_attempt_shape CHECK (
                    (login_attempt_hash IS NULL AND login_attempt_client_hash IS NULL
                     AND login_attempt_host_hash IS NULL AND login_attempt_expires_at IS NULL)
                    OR
                    (login_attempt_hash ~ '^[a-f0-9]{64}$'
                     AND login_attempt_client_hash ~ '^[a-f0-9]{64}$'
                     AND login_attempt_host_hash ~ '^[a-f0-9]{64}$'
                     AND login_attempt_expires_at > issued_at
                     AND login_attempt_expires_at <= issued_at + interval '15 minutes')
                )
        SQL);
        DB::unprepared('CREATE UNIQUE INDEX core01_tenant_authority_login_attempt_uq ON public.core01_tenant_authority_sessions(login_attempt_hash) WHERE login_attempt_hash IS NOT NULL');

        DB::unprepared(<<<'SQL'
            CREATE FUNCTION public.core01_tenant_authority_register_attempt(
                p_tenant uuid, p_staff uuid, p_membership uuid, p_auth_version bigint,
                p_authorization_version bigint, p_session_hash text, p_session_generation uuid,
                p_expires_at timestamptz, p_attempt_hash text,
                p_attempt_client_hash text, p_attempt_host_hash text
            ) RETURNS TABLE(
                authority_id uuid, authority_issued_at timestamptz,
                authority_expires_at timestamptz, disposition text
            ) LANGUAGE plpgsql VOLATILE SECURITY DEFINER
            SET search_path = pg_catalog, public AS $fn$
            DECLARE
                v_row public.core01_tenant_authority_sessions%ROWTYPE;
                v_key integer;
                v_now timestamptz := clock_timestamp();
                v_existing boolean;
            BEGIN
                IF session_user <> 'dl_tauth' OR p_tenant IS NULL OR p_staff IS NULL OR p_membership IS NULL
                   OR p_auth_version IS NULL OR p_authorization_version IS NULL
                   OR p_session_hash !~ '^[a-f0-9]{64}$' OR p_session_generation IS NULL
                   OR p_attempt_hash !~ '^[a-f0-9]{64}$'
                   OR p_attempt_client_hash !~ '^[a-f0-9]{64}$'
                   OR p_attempt_host_hash !~ '^[a-f0-9]{64}$'
                   OR p_expires_at <= v_now OR p_expires_at > v_now + interval '1 day' THEN
                    RAISE EXCEPTION 'tenant authority attempt registration denied' USING ERRCODE='PZ403';
                END IF;

                PERFORM pg_advisory_xact_lock(hashtextextended(p_attempt_hash, 63005));
                SELECT key_generation INTO v_key FROM public.core01_sql_signing_keys
                    WHERE id=1 AND status='ACTIVE' FOR SHARE;
                IF v_key IS NULL THEN
                    RAISE EXCEPTION 'tenant signing key unavailable' USING ERRCODE='PZ503';
                END IF;

                SELECT * INTO v_row FROM public.core01_tenant_authority_sessions
                    WHERE login_attempt_hash=p_attempt_hash FOR UPDATE;
                v_existing := FOUND;

                PERFORM 1 FROM public.tenants t
                    JOIN public.tenant_staff_users u ON u.tenant_id=t.id
                    JOIN public.tenant_staff_memberships m ON m.tenant_id=t.id AND m.staff_user_id=u.id
                    WHERE t.id=p_tenant AND t.status='ACTIVE' AND u.id=p_staff AND u.status='ACTIVE'
                      AND u.auth_version=p_auth_version AND m.id=p_membership AND m.status='ACTIVE'
                      AND m.authorization_version=p_authorization_version FOR SHARE OF t,u,m;
                IF NOT FOUND THEN
                    RAISE EXCEPTION 'tenant authority subject denied' USING ERRCODE='PZ403';
                END IF;

                IF NOT v_existing THEN
                    INSERT INTO public.core01_tenant_authority_sessions(
                        tenant_id, staff_user_id, membership_id, auth_version, authorization_version,
                        session_hash, session_generation, key_generation, issued_at, expires_at,
                        login_attempt_hash, login_attempt_client_hash, login_attempt_host_hash,
                        login_attempt_expires_at
                    ) VALUES (
                        p_tenant, p_staff, p_membership, p_auth_version, p_authorization_version,
                        p_session_hash, p_session_generation, v_key, v_now, p_expires_at,
                        p_attempt_hash, p_attempt_client_hash, p_attempt_host_hash,
                        v_now + interval '10 minutes'
                    ) RETURNING * INTO v_row;
                    disposition := 'CREATED';
                ELSE
                    IF v_row.tenant_id <> p_tenant OR v_row.staff_user_id <> p_staff
                       OR v_row.membership_id <> p_membership OR v_row.auth_version <> p_auth_version
                       OR v_row.authorization_version <> p_authorization_version
                       OR v_row.login_attempt_client_hash <> p_attempt_client_hash
                       OR v_row.login_attempt_host_hash <> p_attempt_host_hash
                       OR v_row.key_generation <> v_key OR v_row.revoked_at IS NOT NULL
                       OR v_row.login_attempt_expires_at <= v_now OR v_row.expires_at <= v_now THEN
                        RAISE EXCEPTION 'tenant login attempt conflict' USING ERRCODE='PZ409';
                    END IF;
                    UPDATE public.core01_tenant_authority_sessions
                       SET session_hash=p_session_hash, session_generation=p_session_generation
                     WHERE id=v_row.id RETURNING * INTO v_row;
                    disposition := 'REBOUND';
                END IF;

                authority_id := v_row.id;
                authority_issued_at := v_row.issued_at;
                authority_expires_at := v_row.expires_at;
                RETURN NEXT;
            END
            $fn$
        SQL);

        DB::unprepared('REVOKE ALL ON FUNCTION public.core01_tenant_authority_register_attempt(uuid,uuid,uuid,bigint,bigint,text,uuid,timestamptz,text,text,text) FROM PUBLIC');
        DB::unprepared('GRANT EXECUTE ON FUNCTION public.core01_tenant_authority_register_attempt(uuid,uuid,uuid,bigint,bigint,text,uuid,timestamptz,text,text,text) TO dl_tauth');
        DB::unprepared('ALTER FUNCTION public.core01_tenant_authority_register_attempt(uuid,uuid,uuid,bigint,bigint,text,uuid,timestamptz,text,text,text) OWNER TO daleel_core01_authority_definer');
        DB::unprepared('SET LOCAL ROLE daleel_core01_authority_definer');
        DB::unprepared('REVOKE EXECUTE ON FUNCTION public.core01_tenant_authority_register_session(uuid,uuid,uuid,bigint,bigint,text,uuid,timestamptz) FROM dl_tauth');
        DB::unprepared('RESET ROLE');
        DB::unprepared('REVOKE CREATE ON SCHEMA public FROM daleel_core01_authority_definer');

        DB::unprepared(<<<'SQL'
            DO $closeout$
            BEGIN
                IF has_schema_privilege('daleel_core01_authority_definer', 'public', 'CREATE')
                   OR EXISTS (
                       SELECT 1 FROM pg_proc p,
                           LATERAL aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
                        WHERE p.oid='public.core01_tenant_authority_register_attempt(uuid,uuid,uuid,bigint,bigint,text,uuid,timestamptz,text,text,text)'::regprocedure
                          AND a.grantee=0 AND a.privilege_type='EXECUTE'
                   )
                   OR has_function_privilege('dl_tauth', 'public.core01_tenant_authority_register_session(uuid,uuid,uuid,bigint,bigint,text,uuid,timestamptz)', 'EXECUTE')
                   OR NOT has_function_privilege('dl_tauth', 'public.core01_tenant_authority_register_attempt(uuid,uuid,uuid,bigint,bigint,text,uuid,timestamptz,text,text,text)', 'EXECUTE') THEN
                    RAISE EXCEPTION 'CORE-01 login attempt ACL closeout failed';
                END IF;
            END
            $closeout$
        SQL);
    }

    public function down(): void
    {
        throw new RuntimeException('Tenant login attempt idempotency is forward-only.');
    }
};
