<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/** Forward-only, transactionally issued and consumed Provider V1 proof. */
return new class extends Migration
{
    public function up(): void
    {
        DB::unprepared(<<<'SQL'
            CREATE TABLE public.core01_provider_stepup_receipts (
                id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
                provider_user_id uuid NOT NULL REFERENCES public.provider_users(id),
                auth_version bigint NOT NULL,
                action_key text NOT NULL CHECK (action_key = 'company.provision'),
                issued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
                expires_at timestamptz NOT NULL,
                consumed_at timestamptz NULL
            )
        SQL);
        DB::unprepared('REVOKE ALL ON public.core01_provider_stepup_receipts FROM PUBLIC');
        DB::unprepared(<<<'SQL'
            CREATE FUNCTION public.core01_issue_provider_stepup_receipt(p_actor uuid, p_auth_version bigint)
            RETURNS uuid LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public
            AS $fn$
            DECLARE v_id uuid;
            BEGIN
                IF session_user <> 'dl_provider' OR NOT EXISTS (
                    SELECT 1 FROM public.provider_users u WHERE u.id = p_actor
                    AND u.auth_version = p_auth_version AND u.status = 'ACTIVE'
                    AND u.email_verified_at IS NOT NULL AND u.mfa_enrolled_at IS NOT NULL
                ) THEN
                    RAISE EXCEPTION 'receipt issuer denied' USING ERRCODE = 'PZ403';
                END IF;
                INSERT INTO public.core01_provider_stepup_receipts
                    (provider_user_id, auth_version, action_key, expires_at)
                    VALUES (p_actor, p_auth_version, 'company.provision', clock_timestamp() + interval '10 minutes')
                    RETURNING id INTO v_id;
                RETURN v_id;
            END
            $fn$
        SQL);
        DB::unprepared(<<<'SQL'
            CREATE FUNCTION public.core01_provision_company_with_receipt(
                p_receipt uuid, p_actor uuid, p_auth_version bigint,
                p_request_id uuid, p_key_hash text, p_digest text,
                p_display text, p_slug text, p_timezone text, p_email text,
                p_admin_name text, p_password_hash text, p_base_domain text
            ) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
            SET search_path = pg_catalog, public
            AS $fn$
            DECLARE v_receipt public.core01_provider_stepup_receipts%ROWTYPE;
            BEGIN
                IF session_user <> 'dl_provider_ctl' THEN
                    RAISE EXCEPTION 'receipt consumer denied' USING ERRCODE = 'PZ403';
                END IF;
                SELECT * INTO v_receipt FROM public.core01_provider_stepup_receipts
                    WHERE id = p_receipt FOR UPDATE;
                IF NOT FOUND OR v_receipt.provider_user_id <> p_actor
                    OR v_receipt.auth_version <> p_auth_version
                    OR v_receipt.action_key <> 'company.provision'
                    OR v_receipt.consumed_at IS NOT NULL
                    OR v_receipt.expires_at <= clock_timestamp() THEN
                    RAISE EXCEPTION 'receipt invalid' USING ERRCODE = 'PZ403';
                END IF;
                UPDATE public.core01_provider_stepup_receipts SET consumed_at = clock_timestamp()
                    WHERE id = p_receipt;
                RETURN public.core01_provision_company_v1(
                    p_actor, p_auth_version, v_receipt.issued_at, p_request_id, p_key_hash,
                    p_digest, p_display, p_slug, p_timezone, p_email, p_admin_name,
                    p_password_hash, p_base_domain);
            END
            $fn$
        SQL);
        DB::unprepared('REVOKE ALL ON FUNCTION public.core01_issue_provider_stepup_receipt(uuid,bigint) FROM PUBLIC');
        DB::unprepared('REVOKE ALL ON FUNCTION public.core01_provision_company_with_receipt(uuid,uuid,bigint,uuid,text,text,text,text,text,text,text,text,text) FROM PUBLIC');
        DB::unprepared('GRANT EXECUTE ON FUNCTION public.core01_issue_provider_stepup_receipt(uuid,bigint) TO dl_provider');
        DB::unprepared('GRANT EXECUTE ON FUNCTION public.core01_provision_company_with_receipt(uuid,uuid,bigint,uuid,text,text,text,text,text,text,text,text,text) TO dl_provider_ctl');
        DB::unprepared('REVOKE EXECUTE ON FUNCTION public.core01_provision_company_v1(uuid,bigint,timestamptz,uuid,text,text,text,text,text,text,text,text,text) FROM dl_provider_ctl');
    }

    public function down(): void
    {
        throw new RuntimeException('Provider receipt authority is forward-only.');
    }
};
