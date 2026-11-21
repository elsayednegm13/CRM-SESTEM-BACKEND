<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('roles', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->uuid('tenant_id');
            $table->string('display_name', 160);
            $table->string('normalized_name', 100);
            $table->string('status', 8)->default('ACTIVE');
            $table->uuid('source_template_id')->nullable();
            $table->unsignedBigInteger('version')->default(1);
            $table->timestampTz('archived_at')->nullable();
            $table->timestampsTz();
            $table->foreign('tenant_id')->references('id')->on('tenants')->restrictOnDelete();
            $table->foreign('source_template_id')->references('id')->on('role_templates')->restrictOnDelete();
            $table->unique(['tenant_id', 'id']);
            $table->unique(['tenant_id', 'normalized_name']);
            $table->index(['tenant_id', 'status']);
        });
        DB::statement("ALTER TABLE roles ADD CONSTRAINT roles_status_check CHECK (status IN ('ACTIVE', 'ARCHIVED'))");
        DB::statement("ALTER TABLE roles ADD CONSTRAINT roles_normalized_name_check CHECK (normalized_name ~ '^[a-z][a-z0-9_]*$')");
        DB::statement('ALTER TABLE roles ADD CONSTRAINT roles_version_check CHECK (version >= 1)');

        Schema::create('role_permissions', function (Blueprint $table): void {
            $table->uuid('tenant_id');
            $table->uuid('role_id');
            $table->string('permission_key', 100);
            $table->string('scope', 16)->nullable();
            $table->primary(['tenant_id', 'role_id', 'permission_key']);
            $table->foreign(['tenant_id', 'role_id'])->references(['tenant_id', 'id'])->on('roles')->restrictOnDelete();
            $table->foreign('permission_key')->references('key')->on('permissions')->restrictOnDelete();
        });
        DB::statement("ALTER TABLE role_permissions ADD CONSTRAINT role_permissions_scope_check CHECK (scope IS NULL OR scope IN ('ALL_TENANT', 'TEAM', 'ASSIGNED', 'SELF', 'NONE'))");

        Schema::create('membership_roles', function (Blueprint $table): void {
            $table->uuid('tenant_id');
            $table->uuid('membership_id');
            $table->uuid('role_id');
            $table->uuid('assigned_by_user_id')->nullable();
            $table->timestampTz('assigned_at');
            $table->primary(['tenant_id', 'membership_id', 'role_id']);
            $table->foreign(['tenant_id', 'membership_id'])->references(['tenant_id', 'id'])->on('tenant_memberships')->restrictOnDelete();
            $table->foreign(['tenant_id', 'role_id'])->references(['tenant_id', 'id'])->on('roles')->restrictOnDelete();
            $table->foreign('assigned_by_user_id')->references('id')->on('users')->restrictOnDelete();
            $table->index(['tenant_id', 'role_id', 'membership_id']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('membership_roles');
        Schema::dropIfExists('role_permissions');
        Schema::dropIfExists('roles');
    }
};
