<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/** Additional restrictive boundary for the existing trusted SQL login. */
return new class extends Migration
{
    public function up(): void
    {
        $key = env('CORE01_SQL_SIGNING_KEY');
        if (! is_string($key) || ! preg_match('/^[a-f0-9]{64}$/D', $key)) {
            throw new RuntimeException('CORE01_SQL_SIGNING_KEY must be a 32-byte hex secret.');
        }
        DB::unprepared('CREATE EXTENSION IF NOT EXISTS pgcrypto');
        DB::unprepared('CREATE TABLE public.core01_sql_signing_keys (id smallint PRIMARY KEY CHECK(id = 1), secret bytea NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp())');
        DB::unprepared('REVOKE ALL ON public.core01_sql_signing_keys FROM PUBLIC');
        DB::insert('INSERT INTO public.core01_sql_signing_keys(id,secret) VALUES (1,decode(?, ?))', [$key, 'hex']);
        DB::unprepared(<<<'SQL'
            CREATE FUNCTION public.core01_signed_tenant_allowed(p_tenant uuid) RETURNS boolean
            LANGUAGE plpgsql VOLATILE SECURITY DEFINER
            SET search_path = pg_catalog, public
            AS $fn$
            DECLARE
                v_parts text[];
                v_key bytea;
                v_message text;
                v_staff uuid;
                v_membership uuid;
                v_auth bigint;
                v_authorization bigint;
                v_expiry bigint;
                v_tenant uuid;
                v_seen boolean;
            BEGIN
                IF session_user <> 'dl_core_truntime'
                   OR current_setting('transaction_isolation') <> 'read committed' THEN
                    RETURN false;
                END IF;
                v_parts := string_to_array(current_setting('app.core01_signed_context',true), '|');
                IF array_length(v_parts,1) <> 9
                   OR NOT pg_input_is_valid(v_parts[1],'uuid')
                   OR NOT pg_input_is_valid(v_parts[2],'uuid')
                   OR NOT pg_input_is_valid(v_parts[3],'uuid')
                   OR NOT pg_input_is_valid(v_parts[4],'bigint')
                   OR NOT pg_input_is_valid(v_parts[5],'bigint')
                   OR NOT pg_input_is_valid(v_parts[6],'bigint')
                   OR v_parts[7] !~ '^[a-f0-9]{32}$'
                   OR v_parts[8] <> 'v1'
                   OR v_parts[9] !~ '^[a-f0-9]{64}$' THEN
                    RETURN false;
                END IF;
                v_tenant := v_parts[1]::uuid;
                v_staff := v_parts[2]::uuid;
                v_membership := v_parts[3]::uuid;
                v_auth := v_parts[4]::bigint;
                v_authorization := v_parts[5]::bigint;
                v_expiry := v_parts[6]::bigint;
                IF v_tenant <> p_tenant OR v_expiry <= extract(epoch FROM clock_timestamp())::bigint
                   OR v_expiry > extract(epoch FROM clock_timestamp())::bigint + 120
                   OR current_setting('app.tenant_id',true) <> v_parts[1]
                   OR current_setting('app.user_id',true) <> v_parts[2] THEN
                    RETURN false;
                END IF;
                SELECT secret INTO v_key FROM public.core01_sql_signing_keys WHERE id=1;
                v_message := array_to_string(v_parts[1:8],'|');
                IF v_key IS NULL OR encode(public.hmac(convert_to(v_message,'UTF8'),v_key,'sha256'),'hex') <> v_parts[9] THEN
                    RETURN false;
                END IF;
                SELECT true INTO v_seen FROM public.tenants t
                JOIN public.tenant_staff_users u ON u.tenant_id=t.id
                JOIN public.tenant_staff_memberships m ON m.tenant_id=t.id AND m.staff_user_id=u.id
                WHERE t.id=v_tenant AND t.status='ACTIVE'
                  AND u.id=v_staff AND u.status='ACTIVE' AND u.auth_version=v_auth
                  AND m.id=v_membership AND m.status='ACTIVE'
                  AND m.authorization_version=v_authorization
                FOR SHARE OF t,u,m;
                RETURN coalesce(v_seen,false);
            END
            $fn$
        SQL);
        DB::unprepared('REVOKE ALL ON FUNCTION public.core01_signed_tenant_allowed(uuid) FROM PUBLIC');
        DB::unprepared('GRANT EXECUTE ON FUNCTION public.core01_signed_tenant_allowed(uuid) TO daleel_tenant_runtime');
        $tables = DB::select(<<<'SQL'
            SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='public' AND c.relkind IN ('r','p') AND c.relrowsecurity AND c.relforcerowsecurity
              AND EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attname='tenant_id' AND NOT a.attisdropped)
            ORDER BY c.relname
        SQL);
        if (count($tables) !== 15) {
            throw new RuntimeException('Tenant RLS inventory unexpectedly small.');
        }
        foreach ($tables as $table) {
            if (! preg_match('/^[a-z_]+$/D', $table->relname)) {
                throw new RuntimeException('Unexpected tenant table name.');
            }
            DB::unprepared("CREATE POLICY core01_signed_runtime_boundary ON public.{$table->relname} AS RESTRICTIVE FOR ALL TO daleel_tenant_runtime USING (public.core01_signed_tenant_allowed(tenant_id)) WITH CHECK (public.core01_signed_tenant_allowed(tenant_id))");
        }
        DB::unprepared('CREATE POLICY core01_signed_runtime_boundary ON public.tenants AS RESTRICTIVE FOR ALL TO daleel_tenant_runtime USING (public.core01_signed_tenant_allowed(id)) WITH CHECK (public.core01_signed_tenant_allowed(id))');
    }

    public function down(): void
    {
        throw new RuntimeException('Signed tenant boundary is forward-only.');
    }
};
