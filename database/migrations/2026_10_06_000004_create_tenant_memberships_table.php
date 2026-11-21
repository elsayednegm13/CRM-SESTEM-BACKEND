<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('tenant_memberships', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->uuid('tenant_id');
            $table->uuid('user_id');
            $table->string('status', 12)->default('SUSPENDED');
            $table->unsignedBigInteger('authorization_version')->default(1);
            $table->timestampTz('joined_at');
            $table->timestampsTz();

            $table->foreign('tenant_id')->references('id')->on('tenants')->restrictOnDelete();
            $table->foreign('user_id')->references('id')->on('users')->restrictOnDelete();
            $table->unique(['tenant_id', 'user_id']);
            $table->unique(['tenant_id', 'id']);
            $table->index(['user_id', 'status', 'tenant_id']);
            $table->index(['tenant_id', 'status', 'user_id']);
        });

        DB::statement("ALTER TABLE tenant_memberships ADD CONSTRAINT tenant_memberships_status_check CHECK (status IN ('ACTIVE', 'SUSPENDED'))");
        DB::statement('ALTER TABLE tenant_memberships ADD CONSTRAINT tenant_memberships_authorization_version_check CHECK (authorization_version >= 1)');
        DB::statement("CREATE UNIQUE INDEX tenant_memberships_one_active_company_per_user ON tenant_memberships (user_id) WHERE status = 'ACTIVE'");
    }

    public function down(): void
    {
        Schema::dropIfExists('tenant_memberships');
    }
};
