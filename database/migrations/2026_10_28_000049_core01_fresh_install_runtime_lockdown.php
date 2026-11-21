<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/**
 * Fresh-install staging: 050 historically created an unsafe transient grant.
 * Runtime logins stay disabled until the later replacement boundary is installed.
 */
return new class extends Migration
{
    public function up(): void
    {
        DB::unprepared(<<<'SQL'
            DO $guard$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dl_provider')
                   OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dl_provider_ctl')
                   OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dl_core_truntime') THEN
                    RAISE EXCEPTION 'CORE-01 runtime roles must exist before migration staging';
                END IF;
                EXECUTE 'ALTER ROLE dl_provider NOLOGIN';
                EXECUTE 'ALTER ROLE dl_provider_ctl NOLOGIN';
                EXECUTE 'ALTER ROLE dl_core_truntime NOLOGIN';
            END
            $guard$
        SQL);
    }

    public function down(): void
    {
        throw new RuntimeException('Fresh-install runtime lockdown is forward-only.');
    }
};
