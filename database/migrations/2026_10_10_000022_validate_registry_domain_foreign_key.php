<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    public function up(): void
    {
        DB::statement('ALTER TABLE tenant_hostnames VALIDATE CONSTRAINT tenant_hostnames_active_domain_fk');
    }

    public function down(): void
    {
        throw new RuntimeException('The registry domain foreign key remains required; use a reviewed forward correction.');
    }
};
