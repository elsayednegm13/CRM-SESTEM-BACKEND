<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('users', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->string('email', 254)->unique();
            $table->string('password');
            $table->timestampTz('email_verified_at')->nullable();
            $table->string('status', 8)->default('ACTIVE');
            $table->unsignedInteger('auth_version')->default(0);
            $table->timestampTz('last_login_at')->nullable();
            $table->timestampsTz();
        });

        DB::statement("ALTER TABLE users ADD CONSTRAINT users_status_check CHECK (status IN ('ACTIVE', 'DISABLED'))");
        DB::statement('ALTER TABLE users ADD CONSTRAINT users_auth_version_nonnegative_check CHECK (auth_version >= 0)');
    }

    public function down(): void
    {
        Schema::dropIfExists('users');
    }
};
