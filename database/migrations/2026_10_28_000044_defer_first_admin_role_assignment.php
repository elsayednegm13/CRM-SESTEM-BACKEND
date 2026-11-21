<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/** Pending founder has no role assignment; activation must assign it atomically. */
return new class extends Migration
{
    public function up(): void
    {
        $signature = 'public.core01_provision_company_v1(uuid,bigint,timestamptz,uuid,text,text,text,text,text,text,text,text,text)';
        $row = DB::selectOne('SELECT pg_get_functiondef(?::regprocedure) AS definition', [$signature]);
        $definition = $row?->definition;
        if (! is_string($definition)) {
            throw new RuntimeException('V1 direct function is missing.');
        }
        $startMarker = 'INSERT INTO public.tenant_staff_membership_roles';
        $endMarker = 'INSERT INTO public.tenant_staff_security_events';
        $start = strpos($definition, $startMarker);
        $end = strpos($definition, $endMarker, $start === false ? 0 : $start);
        if ($start === false || $end === false || $end <= $start
            || substr_count($definition, $startMarker) !== 1
            || ! str_contains(substr($definition, $start, $end - $start), 'v_operation,v_now,NULL,NULL,v_now,v_now)')) {
            throw new RuntimeException('Unexpected V1 assignment function body.');
        }
        $replacement = substr($definition, 0, $start)
            ."-- First administrator role assignment is deferred until password activation.\n                "
            .substr($definition, $end);
        DB::unprepared($replacement);
    }

    public function down(): void
    {
        throw new RuntimeException('Reactivating pending role assignment is unsafe.');
    }
};
