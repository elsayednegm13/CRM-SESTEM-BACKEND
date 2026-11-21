<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/** Supersedes the unbound receipt path from 050; SQL control cannot mint a proof. */
return new class extends Migration
{
    public function up(): void
    {
        $key = env('CORE01_PROVIDER_PROOF_KEY');
        if (! is_string($key) || ! preg_match('/^[a-f0-9]{64}$/D', $key)) {
            throw new RuntimeException('CORE01_PROVIDER_PROOF_KEY must be 32-byte hex.');
        }
        DB::unprepared('REVOKE EXECUTE ON FUNCTION public.core01_issue_provider_stepup_receipt(uuid,bigint) FROM dl_provider');
        DB::unprepared('REVOKE EXECUTE ON FUNCTION public.core01_provision_company_with_receipt(uuid,uuid,bigint,uuid,text,text,text,text,text,text,text,text,text) FROM dl_provider_ctl');
        DB::unprepared('CREATE TABLE public.core01_provider_proof_keys(id smallint PRIMARY KEY CHECK(id=1), secret bytea NOT NULL)');
        DB::unprepared('REVOKE ALL ON public.core01_provider_proof_keys FROM PUBLIC');
        DB::insert('INSERT INTO public.core01_provider_proof_keys(id,secret) VALUES (1,decode(?, ?))', [$key, 'hex']);
        DB::unprepared(<<<'SQL'
            CREATE TABLE public.core01_provider_proof_nonces(
                nonce text PRIMARY KEY CHECK(nonce ~ '^[a-f0-9]{32}$'),
                actor uuid NOT NULL, consumed_at timestamptz NOT NULL DEFAULT clock_timestamp()
            )
        SQL);
        DB::unprepared('REVOKE ALL ON public.core01_provider_proof_nonces FROM PUBLIC');
        DB::unprepared(<<<'SQL'
            CREATE FUNCTION public.core01_provision_company_with_proof(
                p_proof text, p_actor uuid, p_auth_version bigint,
                p_request_id uuid, p_key_hash text, p_digest text,
                p_display text, p_slug text, p_timezone text, p_email text,
                p_admin_name text, p_password_hash text, p_base_domain text
            ) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
            SET search_path = pg_catalog, public
            AS $fn$
            DECLARE
                v_parts text[];
                v_message text;
                v_secret bytea;
                v_expiry bigint;
            BEGIN
                IF session_user <> 'dl_provider_ctl' OR p_proof IS NULL THEN
                    RAISE EXCEPTION 'provider proof denied' USING ERRCODE = 'PZ403';
                END IF;
                v_parts := string_to_array(p_proof, '|');
                IF array_length(v_parts,1) <> 9 OR v_parts[1] <> p_actor::text
                    OR v_parts[2] <> p_auth_version::text OR v_parts[3] <> 'company.provision'
                    OR v_parts[4] <> p_key_hash OR v_parts[5] <> p_digest
                    OR v_parts[6] !~ '^[0-9]{10}$' OR v_parts[7] !~ '^[a-f0-9]{32}$'
                    OR v_parts[8] <> 'v1' OR v_parts[9] !~ '^[a-f0-9]{64}$' THEN
                    RAISE EXCEPTION 'provider proof invalid' USING ERRCODE = 'PZ403';
                END IF;
                v_expiry := v_parts[6]::bigint;
                IF v_expiry <= extract(epoch from clock_timestamp())::bigint
                    OR v_expiry > extract(epoch from clock_timestamp())::bigint + 90 THEN
                    RAISE EXCEPTION 'provider proof expired' USING ERRCODE = 'PZ403';
                END IF;
                SELECT secret INTO v_secret FROM public.core01_provider_proof_keys WHERE id=1;
                v_message := array_to_string(v_parts[1:8], '|');
                IF v_secret IS NULL OR NOT (encode(public.hmac(convert_to(v_message,'UTF8'),v_secret,'sha256'),'hex') = v_parts[9]) THEN
                    RAISE EXCEPTION 'provider proof invalid' USING ERRCODE = 'PZ403';
                END IF;
                INSERT INTO public.core01_provider_proof_nonces(nonce,actor)
                    VALUES(v_parts[7],p_actor);
                RETURN public.core01_provision_company_v1(
                    p_actor,p_auth_version,clock_timestamp(),p_request_id,p_key_hash,p_digest,
                    p_display,p_slug,p_timezone,p_email,p_admin_name,p_password_hash,p_base_domain);
            EXCEPTION WHEN unique_violation THEN
                RAISE EXCEPTION 'provider proof replayed' USING ERRCODE = 'PZ403';
            END
            $fn$
        SQL);
        DB::unprepared('REVOKE ALL ON FUNCTION public.core01_provision_company_with_proof(text,uuid,bigint,uuid,text,text,text,text,text,text,text,text,text) FROM PUBLIC');
        DB::unprepared('GRANT EXECUTE ON FUNCTION public.core01_provision_company_with_proof(text,uuid,bigint,uuid,text,text,text,text,text,text,text,text,text) TO dl_provider_ctl');
    }

    public function down(): void
    {
        throw new RuntimeException('Provider proof authority is forward-only.');
    }
};
