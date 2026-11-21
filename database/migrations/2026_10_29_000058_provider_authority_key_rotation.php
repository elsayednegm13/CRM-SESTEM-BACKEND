<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/** Owner-only key lifecycle: rotation atomically invalidates old authority. */
return new class extends Migration
{
    public function up(): void
    {
        DB::unprepared(<<<'SQL'
            CREATE FUNCTION public.core01_rotate_provider_authority_key() RETURNS integer
            LANGUAGE plpgsql VOLATILE SECURITY DEFINER
            SET search_path = pg_catalog, public AS $fn$
            DECLARE v_old integer; v_new integer;
            BEGIN
                IF session_user <> 'daleel_b10b_owner' OR current_user <> 'daleel_b10b_owner' THEN
                    RAISE EXCEPTION 'provider authority key rotation denied' USING ERRCODE='PZ403';
                END IF;
                SELECT generation INTO v_old FROM public.core01_provider_authority_key_generations
                    WHERE status='ACTIVE' FOR UPDATE;
                IF v_old IS NULL OR EXISTS(SELECT 1 FROM public.core01_provider_authority_key_generations WHERE status='ACTIVE' AND generation<>v_old) THEN
                    RAISE EXCEPTION 'provider authority key state unavailable' USING ERRCODE='PZ503';
                END IF;
                UPDATE public.core01_provider_authority_key_generations
                    SET status='REVOKED', revoked_at=clock_timestamp() WHERE generation=v_old;
                v_new:=v_old+1;
                INSERT INTO public.core01_provider_authority_key_generations(generation,status) VALUES(v_new,'ACTIVE');
                RETURN v_new;
            END $fn$
        SQL);
        DB::unprepared('REVOKE ALL ON FUNCTION public.core01_rotate_provider_authority_key() FROM PUBLIC');
        DB::unprepared('ALTER FUNCTION public.core01_rotate_provider_authority_key() OWNER TO daleel_b10b_owner');
    }

    public function down(): void
    {
        throw new RuntimeException('Provider authority key lifecycle is forward-only.');
    }
};
