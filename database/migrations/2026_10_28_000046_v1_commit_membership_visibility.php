<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/** Permit only the V1 commit integrity trigger to see its own just-written membership. */
return new class extends Migration
{
    public function up(): void
    {
        $signature = 'public.core01_v1_allowed(uuid)';
        $row = DB::selectOne('SELECT pg_get_functiondef(?::regprocedure) AS definition', [$signature]);
        if (! is_string($row?->definition)
            || substr_count($row->definition, "o.status = 'READY'") !== 1
            || ! str_contains($row->definition, "session_user <> 'dl_provider_ctl'")) {
            throw new RuntimeException('Unexpected V1 authority predicate.');
        }
        DB::unprepared(str_replace("o.status = 'READY'", "o.status IN ('READY', 'SUCCEEDED')", $row->definition));
        DB::unprepared(<<<'SQL'
            CREATE POLICY tenant_staff_memberships_core01_v1_commit_select
            ON public.tenant_staff_memberships
            FOR SELECT TO daleel_b10b_owner
            USING (
                session_user = 'dl_provider_ctl'
                AND current_user = 'daleel_b10b_owner'
                AND status = 'ACTIVE'
                AND created_by_provider_operation_id = nullif(current_setting('app.core01_v1_operation_id', true), '')::uuid
                AND public.core01_v1_allowed(tenant_id)
            )
        SQL);
    }

    public function down(): void
    {
        throw new RuntimeException('The V1 commit integrity visibility cannot be removed safely.');
    }
};
