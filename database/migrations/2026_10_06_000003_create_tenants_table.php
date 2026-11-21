<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('tenants', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->string('display_name', 160);
            $table->string('legal_name', 200)->nullable();
            $table->string('slug', 100)->unique();
            $table->string('status', 16)->default('PROVISIONING');
            $table->string('timezone', 64);
            $table->string('default_locale', 16);
            $table->timestampTz('archived_at')->nullable();
            $table->timestampsTz();
        });

        DB::statement("ALTER TABLE tenants ADD CONSTRAINT tenants_status_check CHECK (status IN ('PROVISIONING', 'ACTIVE', 'SUSPENDED', 'ARCHIVED'))");
        DB::statement("ALTER TABLE tenants ADD CONSTRAINT tenants_slug_check CHECK (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$')");
    }

    public function down(): void
    {
        Schema::dropIfExists('tenants');
    }
};
