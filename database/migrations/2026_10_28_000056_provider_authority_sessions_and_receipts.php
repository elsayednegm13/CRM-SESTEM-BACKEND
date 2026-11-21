<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/** Durable Provider authority; issuer and SQL control consumer stay separate. */
return new class extends Migration
{
    public function up(): void
    {
        DB::unprepared(<<<'SQL'
            DO $roles$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_roles r WHERE r.rolname='dl_provider_issuer'
                      AND r.rolcanlogin AND NOT r.rolinherit AND NOT r.rolsuper
                      AND NOT r.rolbypassrls AND NOT r.rolcreatedb AND NOT r.rolcreaterole
                      AND NOT r.rolreplication
                ) THEN
                    RAISE EXCEPTION 'dl_provider_issuer must be a constrained NOINHERIT issuer login';
                END IF;
                IF EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.member=(SELECT oid FROM pg_roles WHERE rolname='dl_provider_issuer'))
                   OR has_schema_privilege('dl_provider_issuer','public','CREATE')
                   OR EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                       WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','S')
                         AND (has_table_privilege('dl_provider_issuer',c.oid,'SELECT')
                           OR has_table_privilege('dl_provider_issuer',c.oid,'INSERT')
                           OR has_table_privilege('dl_provider_issuer',c.oid,'UPDATE')
                           OR has_table_privilege('dl_provider_issuer',c.oid,'DELETE'))) THEN
                    RAISE EXCEPTION 'dl_provider_issuer has unsafe inherited or direct database authority';
                END IF;
            END
            $roles$
        SQL);
        DB::unprepared(<<<'SQL'
            CREATE TABLE public.core01_provider_authority_key_generations (
                generation integer PRIMARY KEY CHECK (generation >= 1),
                status varchar(16) NOT NULL CHECK (status IN ('ACTIVE','RETIRED','REVOKED')),
                created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
                revoked_at timestamptz NULL,
                CHECK ((status = 'ACTIVE' AND revoked_at IS NULL) OR status <> 'ACTIVE')
            )
        SQL);
        DB::unprepared("INSERT INTO public.core01_provider_authority_key_generations(generation,status) VALUES(1,'ACTIVE')");
        DB::unprepared(<<<'SQL'
            CREATE TABLE public.core01_provider_authority_sessions (
                id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
                provider_user_id uuid NOT NULL REFERENCES public.provider_users(id) ON DELETE RESTRICT,
                auth_version bigint NOT NULL CHECK(auth_version >= 1),
                authorization_version bigint NOT NULL CHECK(authorization_version >= 1),
                session_hash char(64) NOT NULL UNIQUE CHECK(session_hash ~ '^[a-f0-9]{64}$'),
                session_generation uuid NOT NULL,
                key_generation integer NOT NULL REFERENCES public.core01_provider_authority_key_generations(generation),
                issued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
                expires_at timestamptz NOT NULL,
                revoked_at timestamptz NULL,
                CHECK(expires_at > issued_at)
            )
        SQL);
        DB::unprepared(<<<'SQL'
            CREATE TABLE public.core01_provider_stepup_grants_v2 (
                id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
                authority_session_id uuid NOT NULL REFERENCES public.core01_provider_authority_sessions(id) ON DELETE RESTRICT,
                provider_user_id uuid NOT NULL REFERENCES public.provider_users(id) ON DELETE RESTRICT,
                auth_version bigint NOT NULL CHECK(auth_version >= 1),
                authorization_version bigint NOT NULL CHECK(authorization_version >= 1),
                key_generation integer NOT NULL REFERENCES public.core01_provider_authority_key_generations(generation),
                verified_at timestamptz NOT NULL DEFAULT clock_timestamp(),
                expires_at timestamptz NOT NULL,
                issued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
                consumed_at timestamptz NULL,
                CHECK(expires_at > verified_at)
            )
        SQL);
        DB::unprepared(<<<'SQL'
            CREATE TABLE public.core01_provider_authority_receipts (
                id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
                token_hash char(64) NOT NULL UNIQUE CHECK(token_hash ~ '^[a-f0-9]{64}$'),
                authority_session_id uuid NOT NULL REFERENCES public.core01_provider_authority_sessions(id) ON DELETE RESTRICT,
                stepup_grant_id uuid NOT NULL REFERENCES public.core01_provider_stepup_grants_v2(id) ON DELETE RESTRICT,
                provider_user_id uuid NOT NULL REFERENCES public.provider_users(id) ON DELETE RESTRICT,
                auth_version bigint NOT NULL CHECK(auth_version >= 1),
                authorization_version bigint NOT NULL CHECK(authorization_version >= 1),
                key_generation integer NOT NULL REFERENCES public.core01_provider_authority_key_generations(generation),
                action_key text NOT NULL CHECK(action_key='company.provision'),
                request_id uuid NOT NULL,
                idempotency_key_hash char(64) NOT NULL CHECK(idempotency_key_hash ~ '^[a-f0-9]{64}$'),
                intent_digest char(64) NOT NULL CHECK(intent_digest ~ '^[a-f0-9]{64}$'),
                payload_hash char(64) NOT NULL CHECK(payload_hash ~ '^[a-f0-9]{64}$'),
                initial_password_hash text NOT NULL CHECK(initial_password_hash LIKE '$argon2id$%'),
                issued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
                expires_at timestamptz NOT NULL,
                consumed_at timestamptz NULL,
                CHECK(expires_at > issued_at)
            )
        SQL);
        DB::unprepared('REVOKE ALL ON public.core01_provider_authority_key_generations, public.core01_provider_authority_sessions, public.core01_provider_stepup_grants_v2, public.core01_provider_authority_receipts FROM PUBLIC');
        DB::unprepared(<<<'SQL'
            CREATE FUNCTION public.core01_provider_authority_register_session(
                p_actor uuid, p_auth_version bigint, p_authorization_version bigint,
                p_session_hash text, p_session_generation uuid, p_expires_at timestamptz
            ) RETURNS uuid LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
            DECLARE v_session uuid; v_key integer;
            BEGIN
                IF session_user <> 'dl_provider_issuer' OR p_actor IS NULL OR p_auth_version IS NULL
                   OR p_authorization_version IS NULL OR p_session_hash !~ '^[a-f0-9]{64}$'
                   OR p_session_generation IS NULL OR p_expires_at <= clock_timestamp()
                   OR p_expires_at > clock_timestamp() + interval '1 day' THEN
                    RAISE EXCEPTION 'issuer session denied' USING ERRCODE='PZ403';
                END IF;
                SELECT generation INTO v_key FROM public.core01_provider_authority_key_generations
                    WHERE status='ACTIVE' FOR SHARE;
                IF v_key IS NULL OR EXISTS(SELECT 1 FROM public.core01_provider_authority_key_generations WHERE status='ACTIVE' AND generation<>v_key) THEN
                    RAISE EXCEPTION 'issuer key unavailable' USING ERRCODE='PZ503';
                END IF;
                PERFORM 1 FROM public.provider_users WHERE id=p_actor AND status='ACTIVE'
                    AND email_verified_at IS NOT NULL AND mfa_enrolled_at IS NOT NULL
                    AND auth_version=p_auth_version AND authorization_version=p_authorization_version FOR SHARE;
                IF NOT FOUND THEN RAISE EXCEPTION 'issuer actor denied' USING ERRCODE='PZ403'; END IF;
                UPDATE public.core01_provider_authority_sessions SET revoked_at=clock_timestamp()
                    WHERE session_hash=p_session_hash AND revoked_at IS NULL;
                INSERT INTO public.core01_provider_authority_sessions(provider_user_id,auth_version,authorization_version,session_hash,session_generation,key_generation,expires_at)
                    VALUES(p_actor,p_auth_version,p_authorization_version,p_session_hash,p_session_generation,v_key,p_expires_at) RETURNING id INTO v_session;
                RETURN v_session;
            END $fn$
        SQL);
        DB::unprepared(<<<'SQL'
            CREATE FUNCTION public.core01_provider_authority_record_stepup(
                p_actor uuid, p_auth_version bigint, p_authorization_version bigint,
                p_session_hash text, p_session_generation uuid
            ) RETURNS uuid LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
            DECLARE v_session public.core01_provider_authority_sessions%ROWTYPE; v_grant uuid;
            BEGIN
                IF session_user <> 'dl_provider_issuer' OR p_session_hash !~ '^[a-f0-9]{64}$' OR p_session_generation IS NULL THEN
                    RAISE EXCEPTION 'issuer step-up denied' USING ERRCODE='PZ403';
                END IF;
                SELECT * INTO v_session FROM public.core01_provider_authority_sessions
                    WHERE session_hash=p_session_hash AND session_generation=p_session_generation FOR UPDATE;
                IF NOT FOUND OR v_session.revoked_at IS NOT NULL OR v_session.expires_at <= clock_timestamp()
                   OR v_session.provider_user_id<>p_actor OR v_session.auth_version<>p_auth_version
                   OR v_session.authorization_version<>p_authorization_version THEN
                    RAISE EXCEPTION 'issuer session inactive' USING ERRCODE='PZ403';
                END IF;
                PERFORM 1 FROM public.core01_provider_authority_key_generations WHERE generation=v_session.key_generation AND status='ACTIVE' FOR SHARE;
                IF NOT FOUND THEN RAISE EXCEPTION 'issuer key inactive' USING ERRCODE='PZ403'; END IF;
                PERFORM 1 FROM public.provider_users WHERE id=p_actor AND status='ACTIVE' AND auth_version=p_auth_version AND authorization_version=p_authorization_version FOR SHARE;
                IF NOT FOUND THEN RAISE EXCEPTION 'issuer actor denied' USING ERRCODE='PZ403'; END IF;
                INSERT INTO public.core01_provider_stepup_grants_v2(authority_session_id,provider_user_id,auth_version,authorization_version,key_generation,expires_at)
                    VALUES(v_session.id,p_actor,p_auth_version,p_authorization_version,v_session.key_generation,clock_timestamp()+interval '10 minutes') RETURNING id INTO v_grant;
                RETURN v_grant;
            END $fn$
        SQL);
        DB::unprepared(<<<'SQL'
            CREATE FUNCTION public.core01_provider_authority_issue_receipt(
                p_actor uuid, p_auth_version bigint, p_authorization_version bigint, p_session_hash text,
                p_session_generation uuid, p_action text, p_request_id uuid, p_key_hash text,
                p_digest text, p_payload_hash text, p_password_hash text, p_token_hash text
            ) RETURNS uuid LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
            DECLARE v_session public.core01_provider_authority_sessions%ROWTYPE; v_grant public.core01_provider_stepup_grants_v2%ROWTYPE; v_receipt uuid;
            BEGIN
                IF session_user <> 'dl_provider_issuer' OR p_actor IS NULL OR p_auth_version IS NULL OR p_authorization_version IS NULL
                   OR p_session_hash !~ '^[a-f0-9]{64}$' OR p_session_generation IS NULL OR p_action<>'company.provision'
                   OR p_request_id IS NULL OR p_key_hash !~ '^[a-f0-9]{64}$' OR p_digest !~ '^[a-f0-9]{64}$'
                   OR p_payload_hash !~ '^[a-f0-9]{64}$' OR p_password_hash NOT LIKE '$argon2id$%'
                   OR p_token_hash !~ '^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'issuer receipt denied' USING ERRCODE='PZ403'; END IF;
                SELECT * INTO v_session FROM public.core01_provider_authority_sessions WHERE session_hash=p_session_hash AND session_generation=p_session_generation FOR UPDATE;
                IF NOT FOUND OR v_session.revoked_at IS NOT NULL OR v_session.expires_at<=clock_timestamp()
                   OR v_session.provider_user_id<>p_actor OR v_session.auth_version<>p_auth_version OR v_session.authorization_version<>p_authorization_version THEN
                    RAISE EXCEPTION 'issuer session inactive' USING ERRCODE='PZ403';
                END IF;
                SELECT * INTO v_grant FROM public.core01_provider_stepup_grants_v2 WHERE authority_session_id=v_session.id
                    AND provider_user_id=p_actor AND auth_version=p_auth_version AND authorization_version=p_authorization_version
                    AND key_generation=v_session.key_generation AND consumed_at IS NULL ORDER BY issued_at DESC LIMIT 1 FOR UPDATE;
                IF NOT FOUND OR v_grant.expires_at<=clock_timestamp() THEN RAISE EXCEPTION 'issuer step-up required' USING ERRCODE='PZ403'; END IF;
                PERFORM 1 FROM public.core01_provider_authority_key_generations WHERE generation=v_session.key_generation AND status='ACTIVE' FOR SHARE;
                IF NOT FOUND THEN RAISE EXCEPTION 'issuer key inactive' USING ERRCODE='PZ403'; END IF;
                PERFORM 1 FROM public.provider_users u JOIN public.provider_user_capabilities a ON a.provider_user_id=u.id JOIN public.provider_capabilities c ON c.key=a.capability_key
                    WHERE u.id=p_actor AND u.status='ACTIVE' AND u.auth_version=p_auth_version AND u.authorization_version=p_authorization_version
                      AND u.email_verified_at IS NOT NULL AND u.mfa_enrolled_at IS NOT NULL AND a.capability_key='company.provision' AND c.status='ACTIVE'
                      AND (a.expires_at IS NULL OR a.expires_at>clock_timestamp()) FOR SHARE OF u,a,c;
                IF NOT FOUND THEN RAISE EXCEPTION 'issuer capability denied' USING ERRCODE='PZ403'; END IF;
                UPDATE public.core01_provider_stepup_grants_v2 SET consumed_at=clock_timestamp() WHERE id=v_grant.id;
                INSERT INTO public.core01_provider_authority_receipts(token_hash,authority_session_id,stepup_grant_id,provider_user_id,auth_version,authorization_version,key_generation,action_key,request_id,idempotency_key_hash,intent_digest,payload_hash,initial_password_hash,expires_at)
                    VALUES(p_token_hash,v_session.id,v_grant.id,p_actor,p_auth_version,p_authorization_version,v_session.key_generation,p_action,p_request_id,p_key_hash,p_digest,p_payload_hash,p_password_hash,least(v_grant.expires_at,clock_timestamp()+interval '90 seconds')) RETURNING id INTO v_receipt;
                RETURN v_receipt;
            END $fn$
        SQL);
        DB::unprepared(<<<'SQL'
            CREATE FUNCTION public.core01_provider_authority_revoke_session(p_session_hash text, p_session_generation uuid)
            RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
            BEGIN
                IF session_user <> 'dl_provider_issuer' OR p_session_hash !~ '^[a-f0-9]{64}$' OR p_session_generation IS NULL THEN
                    RAISE EXCEPTION 'issuer revoke denied' USING ERRCODE='PZ403';
                END IF;
                UPDATE public.core01_provider_authority_sessions SET revoked_at=clock_timestamp()
                    WHERE session_hash=p_session_hash AND session_generation=p_session_generation AND revoked_at IS NULL;
            END $fn$
        SQL);
        DB::unprepared(<<<'SQL'
            CREATE FUNCTION public.core01_provision_company_with_authority(
                p_token text, p_session_hash text, p_actor uuid, p_auth_version bigint, p_authorization_version bigint,
                p_key_hash text, p_digest text, p_display text, p_slug text, p_timezone text, p_email text,
                p_admin_name text, p_base_domain text, p_payload_hash text
            ) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
            DECLARE v_receipt public.core01_provider_authority_receipts%ROWTYPE; v_session public.core01_provider_authority_sessions%ROWTYPE; v_old public.provider_control_operations%ROWTYPE; v_payload text; v_hash text;
            BEGIN
                IF session_user<>'dl_provider_ctl' OR p_token !~ '^[a-f0-9]{64}$' OR p_session_hash !~ '^[a-f0-9]{64}$'
                   OR p_actor IS NULL OR p_auth_version IS NULL OR p_authorization_version IS NULL OR p_key_hash !~ '^[a-f0-9]{64}$'
                   OR p_digest !~ '^[a-f0-9]{64}$' OR p_display IS NULL OR p_slug IS NULL OR p_timezone IS NULL OR p_email IS NULL
                   OR p_admin_name IS NULL OR p_base_domain IS NULL OR p_payload_hash !~ '^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'authority receipt denied' USING ERRCODE='PZ403'; END IF;
                SELECT * INTO v_receipt FROM public.core01_provider_authority_receipts WHERE token_hash=encode(public.digest(convert_to(p_token,'UTF8'),'sha256'),'hex') FOR UPDATE;
                IF NOT FOUND OR v_receipt.provider_user_id<>p_actor OR v_receipt.auth_version<>p_auth_version OR v_receipt.authorization_version<>p_authorization_version
                   OR v_receipt.action_key<>'company.provision' OR v_receipt.idempotency_key_hash<>p_key_hash OR v_receipt.intent_digest<>p_digest OR v_receipt.payload_hash<>p_payload_hash OR v_receipt.expires_at<=clock_timestamp() THEN RAISE EXCEPTION 'authority receipt invalid' USING ERRCODE='PZ403'; END IF;
                v_payload:=octet_length(p_display)::text||':'||p_display||octet_length(p_slug)::text||':'||p_slug||octet_length(p_timezone)::text||':'||p_timezone||octet_length(p_email)::text||':'||p_email||octet_length(p_admin_name)::text||':'||p_admin_name||octet_length(p_base_domain)::text||':'||p_base_domain;
                v_hash:=encode(public.digest(convert_to(v_payload,'UTF8'),'sha256'),'hex');
                IF v_hash IS DISTINCT FROM v_receipt.payload_hash THEN RAISE EXCEPTION 'authority payload mismatch' USING ERRCODE='PZ403'; END IF;
                SELECT * INTO v_session FROM public.core01_provider_authority_sessions WHERE id=v_receipt.authority_session_id AND session_hash=p_session_hash FOR SHARE;
                IF NOT FOUND OR v_session.revoked_at IS NOT NULL OR v_session.expires_at<=clock_timestamp() OR v_session.auth_version<>p_auth_version OR v_session.authorization_version<>p_authorization_version THEN RAISE EXCEPTION 'authority session invalid' USING ERRCODE='PZ403'; END IF;
                PERFORM 1 FROM public.core01_provider_authority_key_generations WHERE generation=v_receipt.key_generation AND status='ACTIVE' FOR SHARE;
                IF NOT FOUND THEN RAISE EXCEPTION 'authority key inactive' USING ERRCODE='PZ403'; END IF;
                PERFORM 1 FROM public.provider_users u JOIN public.provider_user_capabilities a ON a.provider_user_id=u.id JOIN public.provider_capabilities c ON c.key=a.capability_key WHERE u.id=p_actor AND u.status='ACTIVE' AND u.auth_version=p_auth_version AND u.authorization_version=p_authorization_version AND u.email_verified_at IS NOT NULL AND u.mfa_enrolled_at IS NOT NULL AND a.capability_key='company.provision' AND c.status='ACTIVE' AND (a.expires_at IS NULL OR a.expires_at>clock_timestamp()) FOR SHARE OF u,a,c;
                IF NOT FOUND THEN RAISE EXCEPTION 'authority revoked' USING ERRCODE='PZ403'; END IF;
                IF v_receipt.consumed_at IS NOT NULL THEN
                    SELECT * INTO v_old FROM public.provider_control_operations WHERE requester_provider_user_id=p_actor AND action_key='company.provision' AND idempotency_key_hash=p_key_hash AND intent_digest=p_digest FOR SHARE;
                    IF NOT FOUND OR v_old.status<>'SUCCEEDED' THEN RAISE EXCEPTION 'authority replay conflict' USING ERRCODE='PZ409'; END IF;
                    RETURN jsonb_build_object('operation_id',v_old.id,'tenant_id',v_old.target_tenant_id,'slug',v_old.canonical_slug,'hostname',v_old.canonical_slug||'.'||p_base_domain,'first_admin_state','PENDING_FIRST_PASSWORD_CHANGE','replay',true);
                END IF;
                UPDATE public.core01_provider_authority_receipts SET consumed_at=clock_timestamp() WHERE id=v_receipt.id;
                -- The legacy routine compares this to transaction_timestamp(); use
                -- the same transaction clock after validating the durable receipt.
                RETURN public.core01_provision_company_v1(p_actor,p_auth_version,transaction_timestamp(),v_receipt.request_id,p_key_hash,p_digest,p_display,p_slug,p_timezone,p_email,p_admin_name,v_receipt.initial_password_hash,p_base_domain);
            END $fn$
        SQL);
        DB::unprepared('REVOKE ALL ON FUNCTION public.core01_provider_authority_register_session(uuid,bigint,bigint,text,uuid,timestamptz), public.core01_provider_authority_record_stepup(uuid,bigint,bigint,text,uuid), public.core01_provider_authority_issue_receipt(uuid,bigint,bigint,text,uuid,text,uuid,text,text,text,text,text), public.core01_provider_authority_revoke_session(text,uuid), public.core01_provision_company_with_authority(text,text,uuid,bigint,bigint,text,text,text,text,text,text,text,text,text) FROM PUBLIC');
        DB::unprepared('GRANT EXECUTE ON FUNCTION public.core01_provider_authority_register_session(uuid,bigint,bigint,text,uuid,timestamptz), public.core01_provider_authority_record_stepup(uuid,bigint,bigint,text,uuid), public.core01_provider_authority_issue_receipt(uuid,bigint,bigint,text,uuid,text,uuid,text,text,text,text,text), public.core01_provider_authority_revoke_session(text,uuid) TO dl_provider_issuer');
        DB::unprepared('GRANT EXECUTE ON FUNCTION public.core01_provision_company_with_authority(text,text,uuid,bigint,bigint,text,text,text,text,text,text,text,text,text) TO dl_provider_ctl');
        DB::unprepared('REVOKE EXECUTE ON FUNCTION public.core01_provision_company_with_proof(text,uuid,bigint,uuid,text,text,text,text,text,text,text,text,text) FROM dl_provider_ctl');
        DB::unprepared('ALTER TABLE public.core01_provider_authority_key_generations OWNER TO daleel_b10b_owner');
        DB::unprepared('ALTER TABLE public.core01_provider_authority_sessions OWNER TO daleel_b10b_owner');
        DB::unprepared('ALTER TABLE public.core01_provider_stepup_grants_v2 OWNER TO daleel_b10b_owner');
        DB::unprepared('ALTER TABLE public.core01_provider_authority_receipts OWNER TO daleel_b10b_owner');
        DB::unprepared('ALTER FUNCTION public.core01_provider_authority_register_session(uuid,bigint,bigint,text,uuid,timestamptz) OWNER TO daleel_b10b_owner');
        DB::unprepared('ALTER FUNCTION public.core01_provider_authority_record_stepup(uuid,bigint,bigint,text,uuid) OWNER TO daleel_b10b_owner');
        DB::unprepared('ALTER FUNCTION public.core01_provider_authority_issue_receipt(uuid,bigint,bigint,text,uuid,text,uuid,text,text,text,text,text) OWNER TO daleel_b10b_owner');
        DB::unprepared('ALTER FUNCTION public.core01_provider_authority_revoke_session(text,uuid) OWNER TO daleel_b10b_owner');
        DB::unprepared('ALTER FUNCTION public.core01_provision_company_with_authority(text,text,uuid,bigint,bigint,text,text,text,text,text,text,text,text,text) OWNER TO daleel_b10b_owner');
    }

    public function down(): void
    {
        throw new RuntimeException('CORE-01 Provider authority is forward-only.');
    }
};
