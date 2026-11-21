<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/**
 * Forward-only repair for 064: its function owner is the isolated definer,
 * so the ACL must be changed while current_user is that owner.  The temporary
 * SET membership is already required by 059's documented deployment contract.
 */
return new class extends Migration
{
    public function up(): void
    {
        DB::transaction(function (): void {
            DB::unprepared(<<<'SQL'
                DO $guard$
                BEGIN
                    IF session_user <> 'daleel_b10b_owner' OR current_user <> 'daleel_b10b_owner' THEN
                        RAISE EXCEPTION 'CORE-01 ACL repair must start as daleel_b10b_owner';
                    END IF;
                    IF NOT EXISTS (
                        SELECT 1
                        FROM pg_auth_members m
                        JOIN pg_roles role_r ON role_r.oid = m.roleid
                        JOIN pg_roles member_r ON member_r.oid = m.member
                        WHERE role_r.rolname = 'daleel_core01_authority_definer'
                          AND member_r.rolname = 'daleel_b10b_owner'
                          AND m.admin_option AND NOT m.inherit_option AND m.set_option
                    ) THEN
                        RAISE EXCEPTION 'CORE-01 ACL repair requires the exact temporary definer SET membership';
                    END IF;
                    IF NOT EXISTS (
                        SELECT 1
                        FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                        JOIN pg_roles owner_r ON owner_r.oid = p.proowner
                        WHERE n.nspname = 'public'
                          AND p.oid = 'public.core01_active_signing_key_generation()'::regprocedure
                          AND owner_r.rolname = 'daleel_core01_authority_definer'
                          AND p.prosecdef
                    ) THEN
                        RAISE EXCEPTION 'CORE-01 active signing generation function has unexpected owner or security mode';
                    END IF;
                END
                $guard$
            SQL);

            DB::unprepared('SET LOCAL ROLE daleel_core01_authority_definer');
            DB::unprepared('REVOKE ALL ON FUNCTION public.core01_active_signing_key_generation() FROM PUBLIC');
            DB::unprepared('GRANT EXECUTE ON FUNCTION public.core01_active_signing_key_generation() TO daleel_tenant_auth_lookup');
            DB::unprepared('RESET ROLE');

            DB::unprepared(<<<'SQL'
                DO $assert$
                DECLARE v_function oid := 'public.core01_active_signing_key_generation()'::regprocedure;
                BEGIN
                    IF has_function_privilege('public', v_function, 'EXECUTE') THEN
                        RAISE EXCEPTION 'CORE-01 ACL repair left PUBLIC EXECUTE enabled';
                    END IF;
                    IF NOT has_function_privilege('daleel_tenant_auth_lookup', v_function, 'EXECUTE') THEN
                        RAISE EXCEPTION 'CORE-01 ACL repair did not grant tenant auth lookup';
                    END IF;
                    IF EXISTS (
                        SELECT 1
                        FROM pg_proc p
                        CROSS JOIN LATERAL aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) acl
                        LEFT JOIN pg_roles grantee_r ON grantee_r.oid = acl.grantee
                        WHERE p.oid = v_function
                          AND acl.privilege_type = 'EXECUTE'
                          AND (acl.grantee = 0 OR coalesce(grantee_r.rolname, '') NOT IN (
                              'daleel_core01_authority_definer', 'daleel_tenant_auth_lookup'
                          ))
                    ) THEN
                        RAISE EXCEPTION 'CORE-01 ACL repair found an unexpected EXECUTE grantee';
                    END IF;
                END
                $assert$
            SQL);
        });
    }

    public function down(): void
    {
        throw new RuntimeException('CORE-01 ACL repair is forward-only; restore a reviewed backup to roll back.');
    }
};
