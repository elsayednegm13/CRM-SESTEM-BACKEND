<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/**
 * Makes the signed tenant boundary usable by an environment-owned restricted
 * LOGIN without turning the shared dl_core_truntime group into a LOGIN role.
 *
 * The direct membership check is only the outer identity gate. The signed v3
 * context, backend PID, active authority session, expiry, key generation and
 * live tenant/user/membership versions remain mandatory below it.
 */
return new class extends Migration
{
    public function up(): void
    {
        DB::unprepared(<<<'SQL'
            DO $contract$
            DECLARE
                v_owner name;
                v_security_definer boolean;
                v_config text[];
            BEGIN
                SELECT p.proowner::regrole::text::name, p.prosecdef, p.proconfig
                  INTO v_owner, v_security_definer, v_config
                  FROM pg_proc p
                 WHERE p.oid = 'public.core01_signed_tenant_allowed(uuid)'::regprocedure;

                IF v_owner IS DISTINCT FROM 'daleel_core01_authority_definer'::name
                   OR v_security_definer IS DISTINCT FROM true
                   OR NOT coalesce(v_config, ARRAY[]::text[]) @> ARRAY['search_path=pg_catalog, public']::text[] THEN
                    RAISE EXCEPTION 'CORE-01 signed tenant function contract drifted';
                END IF;

                IF NOT EXISTS (
                    SELECT 1
                      FROM pg_roles runtime_role
                     WHERE runtime_role.rolname = 'dl_core_truntime'
                       AND NOT runtime_role.rolcanlogin
                       AND NOT runtime_role.rolsuper
                       AND NOT runtime_role.rolcreaterole
                       AND NOT runtime_role.rolbypassrls
                ) THEN
                    RAISE EXCEPTION 'CORE-01 runtime group role contract drifted';
                END IF;

                IF EXISTS (
                    SELECT 1
                      FROM pg_proc function_row
                      CROSS JOIN LATERAL aclexplode(coalesce(function_row.proacl, acldefault('f', function_row.proowner))) privilege
                     WHERE function_row.oid = 'public.core01_signed_tenant_allowed(uuid)'::regprocedure
                       AND privilege.grantee = 0
                       AND privilege.privilege_type = 'EXECUTE'
                ) OR NOT has_function_privilege('daleel_tenant_runtime', 'public.core01_signed_tenant_allowed(uuid)', 'EXECUTE') THEN
                    RAISE EXCEPTION 'CORE-01 signed tenant function ACL drifted';
                END IF;
            END
            $contract$
        SQL);

        // The registry contains only deployment-selected role names and a fixed purpose;
        // it contains no credential material. The isolated definer needs this single
        // read in order to enforce the same trusted-login boundary on every signed table.
        DB::unprepared('GRANT SELECT ON public.core_sql_tenant_logins TO daleel_core01_authority_definer');

        DB::unprepared(<<<'SQL'
            CREATE OR REPLACE FUNCTION public.core01_signed_tenant_allowed(p_tenant uuid) RETURNS boolean
            LANGUAGE plpgsql VOLATILE SECURITY DEFINER
            SET search_path = pg_catalog, public AS $fn$
            DECLARE
                v_parts text[]; v_key bytea; v_message text; v_staff uuid; v_membership uuid;
                v_auth bigint; v_authorization bigint; v_expiry bigint; v_tenant uuid;
                v_session_hash text; v_session_generation uuid; v_generation integer; v_backend integer; v_seen boolean;
            BEGIN
                IF current_setting('transaction_isolation') <> 'read committed'
                   OR NOT EXISTS (
                        SELECT 1
                          FROM pg_roles login_role
                          JOIN pg_auth_members membership ON membership.member = login_role.oid
                          JOIN pg_roles runtime_role ON runtime_role.oid = membership.roleid
                         WHERE login_role.rolname = session_user
                           AND login_role.rolcanlogin
                           AND NOT login_role.rolinherit
                           AND NOT login_role.rolsuper
                           AND NOT login_role.rolcreatedb
                           AND NOT login_role.rolcreaterole
                           AND NOT login_role.rolreplication
                           AND NOT login_role.rolbypassrls
                           AND runtime_role.rolname = 'dl_core_truntime'
                           AND NOT runtime_role.rolcanlogin
                           AND NOT runtime_role.rolsuper
                           AND NOT runtime_role.rolcreaterole
                           AND NOT runtime_role.rolbypassrls
                           AND NOT membership.admin_option
                           AND membership.inherit_option
                           AND NOT membership.set_option
                           AND EXISTS (
                                SELECT 1
                                  FROM public.core_sql_tenant_logins trusted_login
                                 WHERE trusted_login.role_name = session_user
                                   AND trusted_login.purpose = 'TRUSTED_TENANT'
                           )
                   ) THEN
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

        DB::unprepared('ALTER FUNCTION public.core01_signed_tenant_allowed(uuid) OWNER TO daleel_core01_authority_definer');
        DB::unprepared('REVOKE ALL ON FUNCTION public.core01_signed_tenant_allowed(uuid) FROM PUBLIC');
        DB::unprepared('GRANT EXECUTE ON FUNCTION public.core01_signed_tenant_allowed(uuid) TO daleel_tenant_runtime');
    }

    public function down(): void
    {
        throw new RuntimeException('CORE-01 secure runtime identity binding is forward-only.');
    }
};
