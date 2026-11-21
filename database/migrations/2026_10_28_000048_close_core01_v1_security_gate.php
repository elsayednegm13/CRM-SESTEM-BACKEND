<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/** Fail closed after the G2 A/B and forged step-up counterexamples. */
return new class extends Migration
{
    public function up(): void
    {
        DB::unprepared('REVOKE EXECUTE ON FUNCTION public.core01_provision_company_v1(uuid,bigint,timestamptz,uuid,text,text,text,text,text,text,text,text,text) FROM dl_provider_ctl');
        DB::unprepared('REVOKE EXECUTE ON FUNCTION public.core01_activate_first_admin(uuid,uuid,uuid,text,text,text,uuid) FROM dl_onboarding');
    }

    public function down(): void
    {
        throw new RuntimeException('The CORE-01 security gate cannot be reopened by rollback.');
    }
};
