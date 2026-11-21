<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/**
 * Replaces the bearer-like signed tenant context with a server-side session
 * authority binding. V1 is retained only for the credential-to-session bridge.
 */
return new class extends Migration
{
    public function up(): void
    {
        DB::unprepared(<<<'SQL'
            DO $roles$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='dl_tauth')
                   OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='dl_core_truntime') THEN
                    RAISE EXCEPTION 'CORE-01 tenant authority roles must exist before migration';
                END IF;
            END
            $roles$
        SQL);
        DB::unprepared("ALTER TABLE public.core01_sql_signing_keys ADD COLUMN key_generation integer NOT NULL DEFAULT 1 CHECK(key_generation >= 1)");
        DB::unprepared("ALTER TABLE public.core01_sql_signing_keys ADD COLUMN status varchar(16) NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE','RETIRED','REVOKED'))");
        DB::unprepared('ALTER TABLE public.core01_sql_signing_keys ADD COLUMN revoked_at timestamptz NULL');
        DB::unprepared("ALTER TABLE public.core01_sql_signing_keys ADD CONSTRAINT core01_sql_signing_keys_active_check CHECK((status='ACTIVE' AND revoked_at IS NULL) OR status <> 'ACTIVE')");
        DB::unprepared(<<<'SQL'
            CREATE TABLE public.core01_tenant_authority_sessions (
                id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
                tenant_id uuid NOT NULL REFERENCES public.tenants(id) ON DELETE RESTRICT,
                staff_user_id uuid NOT NULL REFERENCES public.tenant_staff_users(id) ON DELETE RESTRICT,
                membership_id uuid NOT NULL REFERENCES public.tenant_staff_memberships(id) ON DELETE RESTRICT,
                auth_version bigint NOT NULL CHECK(auth_version >= 1),
                authorization_version bigint NOT NULL CHECK(authorization_version >= 1),
                session_hash char(64) NOT NULL UNIQUE CHECK(session_hash ~ '^[a-f0-9]{64}$'),
                session_generation uuid NOT NULL,
                key_generation integer NOT NULL CHECK(key_generation >= 1),
                issued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
                expires_at timestamptz NOT NULL,
                revoked_at timestamptz NULL,
                CHECK(expires_at > issued_at)
            )
        SQL);
        DB::unprepared('REVOKE ALL ON public.core01_tenant_authority_sessions FROM PUBLIC');
        DB::unprepared(<<<'SQL'
            CREATE FUNCTION public.core01_tenant_authority_register_session(
                p_tenant uuid, p_staff uuid, p_membership uuid, p_auth_version bigint,
                p_authorization_version bigint, p_session_hash text, p_session_generation uuid,
                p_expires_at timestamptz
            ) RETURNS uuid LANGUAGE plpgsql VOLATILE SECURITY DEFINER
            SET search_path = pg_catalog, public AS $fn$
            DECLARE v_id uuid; v_key integer;
            BEGIN
                IF session_user <> 'dl_tauth' OR p_tenant IS NULL OR p_staff IS NULL OR p_membership IS NULL
                   OR p_auth_version IS NULL OR p_authorization_version IS NULL
                   OR p_session_hash !~ '^[a-f0-9]{64}$' OR p_session_generation IS NULL
                   OR p_expires_at <= clock_timestamp() OR p_expires_at > clock_timestamp()+interval '1 day' THEN
                    RAISE EXCEPTION 'tenant authority registration denied' USING ERRCODE='PZ403';
                END IF;
                SELECT key_generation INTO v_key FROM public.core01_sql_signing_keys
                    WHERE id=1 AND status='ACTIVE' FOR SHARE;
                IF v_key IS NULL THEN RAISE EXCEPTION 'tenant signing key unavailable' USING ERRCODE='PZ503'; END IF;
                PERFORM 1 FROM public.tenants t
                    JOIN public.tenant_staff_users u ON u.tenant_id=t.id
                    JOIN public.tenant_staff_memberships m ON m.tenant_id=t.id AND m.staff_user_id=u.id
                    WHERE t.id=p_tenant AND t.status='ACTIVE' AND u.id=p_staff AND u.status='ACTIVE'
                      AND u.auth_version=p_auth_version AND m.id=p_membership AND m.status='ACTIVE'
                      AND m.authorization_version=p_authorization_version FOR SHARE OF t,u,m;
                IF NOT FOUND THEN RAISE EXCEPTION 'tenant authority subject denied' USING ERRCODE='PZ403'; END IF;
                UPDATE public.core01_tenant_authority_sessions SET revoked_at=clock_timestamp()
                    WHERE session_hash=p_session_hash AND revoked_at IS NULL;
                INSERT INTO public.core01_tenant_authority_sessions(tenant_id,staff_user_id,membership_id,auth_version,authorization_version,session_hash,session_generation,key_generation,expires_at)
                    VALUES(p_tenant,p_staff,p_membership,p_auth_version,p_authorization_version,p_session_hash,p_session_generation,v_key,p_expires_at)
                    RETURNING id INTO v_id;
                RETURN v_id;
            END $fn$
        SQL);
        DB::unprepared(<<<'SQL'
            CREATE FUNCTION public.core01_tenant_authority_revoke_session(p_session_hash text, p_session_generation uuid)
            RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER
            SET search_path = pg_catalog, public AS $fn$
            BEGIN
                IF session_user <> 'dl_tauth' OR p_session_hash !~ '^[a-f0-9]{64}$' OR p_session_generation IS NULL THEN
                    RAISE EXCEPTION 'tenant authority revocation denied' USING ERRCODE='PZ403';
                END IF;
                UPDATE public.core01_tenant_authority_sessions SET revoked_at=clock_timestamp()
                    WHERE session_hash=p_session_hash AND session_generation=p_session_generation AND revoked_at IS NULL;
            END $fn$
        SQL);
        DB::unprepared(<<<'SQL'
            CREATE OR REPLACE FUNCTION public.core01_signed_tenant_allowed(p_tenant uuid) RETURNS boolean
            LANGUAGE plpgsql VOLATILE SECURITY DEFINER
            SET search_path = pg_catalog, public AS $fn$
            DECLARE
                v_parts text[]; v_key bytea; v_message text; v_staff uuid; v_membership uuid;
                v_auth bigint; v_authorization bigint; v_expiry bigint; v_tenant uuid;
                v_session_hash text; v_session_generation uuid; v_generation integer; v_backend integer; v_seen boolean;
            BEGIN
                IF session_user <> 'dl_core_truntime' OR current_setting('transaction_isolation') <> 'read committed' THEN
                    RETURN false;
                END IF;
                v_parts := string_to_array(current_setting('app.core01_signed_context',true), '|');
                IF array_length(v_parts,1)=9 THEN
                    -- Credential verification has no durable session yet. It is usable only
                    -- inside the login transaction, never for an authenticated request.
                    IF current_setting('app.context_mode',true)<>'TENANT'
                       OR current_setting('app.core01_login_bridge',true)<>'1'
                       OR NOT pg_input_is_valid(v_parts[1],'uuid') OR NOT pg_input_is_valid(v_parts[2],'uuid')
                       OR NOT pg_input_is_valid(v_parts[3],'uuid') OR NOT pg_input_is_valid(v_parts[4],'bigint')
                       OR NOT pg_input_is_valid(v_parts[5],'bigint') OR NOT pg_input_is_valid(v_parts[6],'bigint')
                       OR v_parts[7]!~'^[a-f0-9]{32}$' OR v_parts[8]<>'v1' OR v_parts[9]!~'^[a-f0-9]{64}$' THEN RETURN false; END IF;
                    v_tenant:=v_parts[1]::uuid; v_staff:=v_parts[2]::uuid; v_membership:=v_parts[3]::uuid;
                    v_auth:=v_parts[4]::bigint; v_authorization:=v_parts[5]::bigint; v_expiry:=v_parts[6]::bigint;
                    SELECT secret INTO v_key FROM public.core01_sql_signing_keys WHERE id=1 AND status='ACTIVE' FOR SHARE;
                    v_message:=array_to_string(v_parts[1:8],'|');
                    IF v_tenant<>p_tenant OR v_expiry<=extract(epoch FROM clock_timestamp())::bigint
                       OR v_expiry>extract(epoch FROM clock_timestamp())::bigint+120 OR current_setting('app.tenant_id',true)<>v_parts[1]
                       OR current_setting('app.user_id',true)<>v_parts[2] OR v_key IS NULL
                       OR encode(public.hmac(convert_to(v_message,'UTF8'),v_key,'sha256'),'hex')<>v_parts[9] THEN RETURN false; END IF;
                ELSIF array_length(v_parts,1)=13 THEN
                    IF current_setting('app.context_mode',true)<>'TENANT'
                       OR NOT pg_input_is_valid(v_parts[1],'uuid') OR NOT pg_input_is_valid(v_parts[2],'uuid')
                       OR NOT pg_input_is_valid(v_parts[3],'uuid') OR NOT pg_input_is_valid(v_parts[4],'bigint')
                       OR NOT pg_input_is_valid(v_parts[5],'bigint') OR v_parts[6]!~'^[a-f0-9]{64}$'
                       OR NOT pg_input_is_valid(v_parts[7],'uuid') OR NOT pg_input_is_valid(v_parts[8],'integer')
                       OR NOT pg_input_is_valid(v_parts[9],'integer') OR NOT pg_input_is_valid(v_parts[10],'bigint') OR v_parts[11]!~'^[a-f0-9]{32}$'
                       OR v_parts[12]<>'v3' OR v_parts[13]!~'^[a-f0-9]{64}$' THEN RETURN false; END IF;
                    v_tenant:=v_parts[1]::uuid; v_staff:=v_parts[2]::uuid; v_membership:=v_parts[3]::uuid;
                    v_auth:=v_parts[4]::bigint; v_authorization:=v_parts[5]::bigint; v_session_hash:=v_parts[6];
                    v_session_generation:=v_parts[7]::uuid; v_generation:=v_parts[8]::integer; v_backend:=v_parts[9]::integer; v_expiry:=v_parts[10]::bigint;
                    SELECT secret INTO v_key FROM public.core01_sql_signing_keys WHERE id=1 AND status='ACTIVE' AND key_generation=v_generation FOR SHARE;
                    v_message:=array_to_string(v_parts[1:12],'|');
                    IF v_tenant<>p_tenant OR v_expiry<=extract(epoch FROM clock_timestamp())::bigint
                       OR v_expiry>extract(epoch FROM clock_timestamp())::bigint+120 OR current_setting('app.tenant_id',true)<>v_parts[1]
                       OR current_setting('app.user_id',true)<>v_parts[2] OR v_backend<>pg_backend_pid() OR v_key IS NULL
                       OR encode(public.hmac(convert_to(v_message,'UTF8'),v_key,'sha256'),'hex')<>v_parts[13] THEN RETURN false; END IF;
                    PERFORM 1 FROM public.core01_tenant_authority_sessions s WHERE s.tenant_id=v_tenant
                      AND s.staff_user_id=v_staff AND s.membership_id=v_membership AND s.auth_version=v_auth
                      AND s.authorization_version=v_authorization AND s.session_hash=v_session_hash
                      AND s.session_generation=v_session_generation AND s.key_generation=v_generation
                      AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() FOR SHARE;
                    IF NOT FOUND THEN RETURN false; END IF;
                ELSE
                    RETURN false;
                END IF;
                SELECT true INTO v_seen FROM public.tenants t JOIN public.tenant_staff_users u ON u.tenant_id=t.id
                    JOIN public.tenant_staff_memberships m ON m.tenant_id=t.id AND m.staff_user_id=u.id
                    WHERE t.id=v_tenant AND t.status='ACTIVE' AND u.id=v_staff AND u.status='ACTIVE'
                      AND u.auth_version=v_auth AND m.id=v_membership AND m.status='ACTIVE'
                      AND m.authorization_version=v_authorization FOR SHARE OF t,u,m;
                RETURN coalesce(v_seen,false);
            END $fn$
        SQL);
        DB::unprepared(<<<'SQL'
            CREATE FUNCTION public.core01_rotate_tenant_signing_key(p_new_secret text) RETURNS integer
            LANGUAGE plpgsql VOLATILE SECURITY DEFINER
            SET search_path = pg_catalog, public AS $fn$
            DECLARE v_generation integer;
            BEGIN
                IF session_user <> 'daleel_b10b_owner' OR current_user <> 'daleel_b10b_owner'
                   OR p_new_secret !~ '^[a-f0-9]{64}$' THEN
                    RAISE EXCEPTION 'tenant signing key rotation denied' USING ERRCODE='PZ403';
                END IF;
                UPDATE public.core01_sql_signing_keys
                    SET secret=decode(p_new_secret,'hex'), key_generation=key_generation+1,
                        created_at=clock_timestamp(), status='ACTIVE', revoked_at=NULL
                    WHERE id=1 RETURNING key_generation INTO v_generation;
                IF v_generation IS NULL THEN RAISE EXCEPTION 'tenant signing key unavailable' USING ERRCODE='PZ503'; END IF;
                RETURN v_generation;
            END $fn$
        SQL);
        DB::unprepared('REVOKE ALL ON FUNCTION public.core01_tenant_authority_register_session(uuid,uuid,uuid,bigint,bigint,text,uuid,timestamptz), public.core01_tenant_authority_revoke_session(text,uuid), public.core01_signed_tenant_allowed(uuid), public.core01_rotate_tenant_signing_key(text) FROM PUBLIC');
        DB::unprepared('GRANT EXECUTE ON FUNCTION public.core01_tenant_authority_register_session(uuid,uuid,uuid,bigint,bigint,text,uuid,timestamptz), public.core01_tenant_authority_revoke_session(text,uuid) TO dl_tauth');
        DB::unprepared('GRANT EXECUTE ON FUNCTION public.core01_signed_tenant_allowed(uuid) TO daleel_tenant_runtime');
        DB::unprepared('ALTER TABLE public.core01_tenant_authority_sessions OWNER TO daleel_b10b_owner');
        DB::unprepared('ALTER FUNCTION public.core01_tenant_authority_register_session(uuid,uuid,uuid,bigint,bigint,text,uuid,timestamptz) OWNER TO daleel_b10b_owner');
        DB::unprepared('ALTER FUNCTION public.core01_tenant_authority_revoke_session(text,uuid) OWNER TO daleel_b10b_owner');
        DB::unprepared('ALTER FUNCTION public.core01_signed_tenant_allowed(uuid) OWNER TO daleel_b10b_owner');
        DB::unprepared('ALTER FUNCTION public.core01_rotate_tenant_signing_key(text) OWNER TO daleel_b10b_owner');
    }

    public function down(): void
    {
        throw new RuntimeException('CORE-01 tenant authority is forward-only.');
    }
};
