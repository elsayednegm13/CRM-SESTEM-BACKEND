<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('permissions', function (Blueprint $table): void {
            $table->string('key', 100)->primary();
            $table->boolean('scopeable');
            $table->jsonb('allowed_scopes');
            $table->boolean('delegable');
            $table->string('status', 8)->default('ACTIVE');
            $table->unsignedInteger('version')->default(1);
            $table->string('description', 200);
            $table->timestampsTz();
        });
        DB::statement("ALTER TABLE permissions ADD CONSTRAINT permissions_key_check CHECK (key ~ '^[a-z][a-z0-9_]*[.][a-z][a-z0-9_]*$')");
        DB::statement("ALTER TABLE permissions ADD CONSTRAINT permissions_status_check CHECK (status IN ('ACTIVE', 'RETIRED'))");
        DB::statement('ALTER TABLE permissions ADD CONSTRAINT permissions_version_check CHECK (version >= 1)');
        DB::statement("ALTER TABLE permissions ADD CONSTRAINT permissions_scopes_check CHECK (jsonb_typeof(allowed_scopes) = 'array' AND allowed_scopes <@ '[\"ALL_TENANT\",\"TEAM\",\"ASSIGNED\",\"SELF\",\"NONE\"]'::jsonb AND ((scopeable = false AND allowed_scopes = '[]'::jsonb) OR (scopeable = true AND jsonb_array_length(allowed_scopes) > 0)))");

        Schema::create('role_templates', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->string('code', 80);
            $table->unsignedInteger('version');
            $table->string('display_name', 160);
            $table->string('status', 8)->default('ACTIVE');
            $table->timestampsTz();
            $table->unique(['code', 'version']);
        });
        DB::statement("ALTER TABLE role_templates ADD CONSTRAINT role_templates_code_check CHECK (code ~ '^[a-z][a-z0-9_]*$')");
        DB::statement("ALTER TABLE role_templates ADD CONSTRAINT role_templates_status_check CHECK (status IN ('ACTIVE', 'RETIRED'))");
        DB::statement('ALTER TABLE role_templates ADD CONSTRAINT role_templates_version_check CHECK (version >= 1)');

        Schema::create('role_template_permissions', function (Blueprint $table): void {
            $table->uuid('template_id');
            $table->string('permission_key', 100);
            $table->string('scope', 16)->nullable();
            $table->primary(['template_id', 'permission_key']);
            $table->foreign('template_id')->references('id')->on('role_templates')->restrictOnDelete();
            $table->foreign('permission_key')->references('key')->on('permissions')->restrictOnDelete();
        });
        DB::statement("ALTER TABLE role_template_permissions ADD CONSTRAINT role_template_permissions_scope_check CHECK (scope IS NULL OR scope IN ('ALL_TENANT', 'TEAM', 'ASSIGNED', 'SELF', 'NONE'))");
    }

    public function down(): void
    {
        Schema::dropIfExists('role_template_permissions');
        Schema::dropIfExists('role_templates');
        Schema::dropIfExists('permissions');
    }
};
