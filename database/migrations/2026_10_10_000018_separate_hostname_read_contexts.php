<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    public function up(): void
    {
        DB::statement('DROP POLICY tenant_hostnames_host_lookup ON tenant_hostnames');
        DB::statement('DROP POLICY tenant_hostnames_provider_select ON tenant_hostnames');
        // Fail closed while role-bound read policies are installed by migration 19.
        DB::statement(<<<'SQL'
            CREATE POLICY tenant_hostnames_scoped_select ON tenant_hostnames
            AS RESTRICTIVE FOR SELECT TO PUBLIC
            USING (FALSE)
        SQL);
    }

    public function down(): void
    {
        throw new RuntimeException('Hostname read contexts must remain isolated; use a reviewed forward correction.');
    }
};
