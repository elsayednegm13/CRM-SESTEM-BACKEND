<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/** FOR UPDATE in MFA consumption needs a scoped UPDATE privilege on its target row. */
return new class extends Migration
{
    public function up(): void
    {
        $role = DB::selectOne("SELECT rolsuper, rolbypassrls, rolcanlogin FROM pg_roles WHERE rolname = 'dl_provider'");
        if (! $role || $role->rolsuper || $role->rolbypassrls || ! $role->rolcanlogin) {
            throw new RuntimeException('Provider runtime role is absent or unsafe.');
        }
        DB::statement('GRANT UPDATE (last_used_counter, updated_at) ON public.provider_mfa_totp TO dl_provider');
        DB::statement('GRANT UPDATE (used_at, updated_at) ON public.provider_mfa_recovery_codes TO dl_provider');
    }

    public function down(): void
    {
        throw new RuntimeException('MFA consumption grant change requires reviewed rollback.');
    }
};
