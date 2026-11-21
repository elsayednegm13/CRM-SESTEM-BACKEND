<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/** The deferred integrity check runs at COMMIT, after the V1 definer has returned. */
return new class extends Migration
{
    public function up(): void
    {
        $row = DB::selectOne("SELECT pg_get_functiondef('public.tenant_staff_user_requires_membership()'::regprocedure) AS definition");
        if (! is_string($row?->definition)
            || ! str_contains($row->definition, 'FROM tenant_staff_memberships membership')
            || ! str_contains($row->definition, 'membership.staff_user_id = NEW.id')) {
            throw new RuntimeException('Unexpected deferred membership check.');
        }
        DB::unprepared(<<<'SQL'
            CREATE OR REPLACE FUNCTION public.tenant_staff_user_requires_membership()
            RETURNS trigger
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, public
            AS $function$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM public.tenant_staff_memberships membership
                    WHERE membership.tenant_id = NEW.tenant_id
                      AND membership.staff_user_id = NEW.id
                ) THEN
                    RAISE EXCEPTION USING ERRCODE = '23514',
                        MESSAGE = 'tenant staff identity requires exactly one tenant membership';
                END IF;
                RETURN NULL;
            END
            $function$
        SQL);
        DB::unprepared('ALTER FUNCTION public.tenant_staff_user_requires_membership() OWNER TO daleel_b10b_owner');
        DB::unprepared('REVOKE ALL ON FUNCTION public.tenant_staff_user_requires_membership() FROM PUBLIC');
    }

    public function down(): void
    {
        throw new RuntimeException('Restoring the invoker check would break V1 commits.');
    }
};
