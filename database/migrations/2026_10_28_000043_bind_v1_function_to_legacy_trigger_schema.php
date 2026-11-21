<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/** Existing trigger bodies use unqualified public tables; keep a fixed trusted path. */
return new class extends Migration
{
    public function up(): void
    {
        foreach (['dl_provider_ctl', 'dl_provider', 'dl_truntime', 'dl_core_truntime', 'dl_onboarding', 'dl_host', 'dl_tauth'] as $role) {
            if (DB::selectOne("SELECT has_schema_privilege(?, 'public', 'CREATE') AS allowed", [$role])->allowed) {
                throw new RuntimeException('An HTTP runtime can create objects in public.');
            }
        }
        DB::statement('ALTER FUNCTION public.core01_provision_company_v1(uuid,bigint,timestamptz,uuid,text,text,text,text,text,text,text,text,text) SET search_path = pg_catalog, public');
    }

    public function down(): void
    {
        throw new RuntimeException('V1 trigger compatibility change requires reviewed rollback.');
    }
};
