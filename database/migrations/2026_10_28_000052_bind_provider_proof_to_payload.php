<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/** Binds the signed proof to every SQL argument that can affect provisioning. */
return new class extends Migration
{
    public function up(): void
    {
        DB::unprepared(<<<'SQL'
            CREATE OR REPLACE FUNCTION public.core01_provision_company_with_proof(
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
                v_payload text;
                v_payload_hash text;
            BEGIN
                IF session_user <> 'dl_provider_ctl' OR p_proof IS NULL THEN
                    RAISE EXCEPTION 'provider proof denied' USING ERRCODE = 'PZ403';
                END IF;
                v_parts := string_to_array(p_proof, '|');
                IF array_length(v_parts,1) <> 10 OR v_parts[1] <> p_actor::text
                    OR v_parts[2] <> p_auth_version::text OR v_parts[3] <> 'company.provision'
                    OR v_parts[4] <> p_key_hash OR v_parts[5] <> p_digest
                    OR v_parts[6] !~ '^[a-f0-9]{64}$'
                    OR v_parts[7] !~ '^[0-9]{10}$' OR v_parts[8] !~ '^[a-f0-9]{32}$'
                    OR v_parts[9] <> 'v2' OR v_parts[10] !~ '^[a-f0-9]{64}$' THEN
                    RAISE EXCEPTION 'provider proof invalid' USING ERRCODE = 'PZ403';
                END IF;
                v_payload := octet_length(p_display)::text || ':' || p_display
                    || octet_length(p_slug)::text || ':' || p_slug
                    || octet_length(p_timezone)::text || ':' || p_timezone
                    || octet_length(p_email)::text || ':' || p_email
                    || octet_length(p_admin_name)::text || ':' || p_admin_name
                    || octet_length(p_password_hash)::text || ':' || p_password_hash
                    || octet_length(p_base_domain)::text || ':' || p_base_domain;
                v_payload_hash := encode(public.digest(convert_to(v_payload,'UTF8'),'sha256'),'hex');
                IF v_payload_hash <> v_parts[6] THEN
                    RAISE EXCEPTION 'provider payload mismatch' USING ERRCODE = 'PZ403';
                END IF;
                v_expiry := v_parts[7]::bigint;
                IF v_expiry <= extract(epoch from clock_timestamp())::bigint
                    OR v_expiry > extract(epoch from clock_timestamp())::bigint + 90 THEN
                    RAISE EXCEPTION 'provider proof expired' USING ERRCODE = 'PZ403';
                END IF;
                SELECT secret INTO v_secret FROM public.core01_provider_proof_keys WHERE id=1;
                v_message := array_to_string(v_parts[1:9], '|');
                IF v_secret IS NULL OR NOT (encode(public.hmac(convert_to(v_message,'UTF8'),v_secret,'sha256'),'hex') = v_parts[10]) THEN
                    RAISE EXCEPTION 'provider proof invalid' USING ERRCODE = 'PZ403';
                END IF;
                INSERT INTO public.core01_provider_proof_nonces(nonce,actor)
                    VALUES(v_parts[8],p_actor);
                RETURN public.core01_provision_company_v1(
                    p_actor,p_auth_version,clock_timestamp(),p_request_id,p_key_hash,p_digest,
                    p_display,p_slug,p_timezone,p_email,p_admin_name,p_password_hash,p_base_domain);
            END
            $fn$
        SQL);
    }

    public function down(): void
    {
        throw new RuntimeException('Provider proof payload binding is forward-only.');
    }
};
