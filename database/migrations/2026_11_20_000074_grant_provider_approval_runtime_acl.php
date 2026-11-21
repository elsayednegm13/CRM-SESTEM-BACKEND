<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    public function up(): void
    {
        $missing = DB::selectOne(<<<'SQL'
            SELECT count(*) AS count
            FROM (VALUES ('dl_provider'), ('daleel_b10b_owner')) AS required(name)
            WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = required.name)
        SQL);
        if ((int) $missing->count !== 0) {
            throw new RuntimeException('Provider approval ACL roles are unavailable.');
        }

        DB::statement('GRANT SELECT, INSERT, UPDATE ON public.provider_approval_requests TO dl_provider');
        DB::statement('GRANT SELECT, INSERT ON public.provider_approval_decisions TO dl_provider');
        DB::statement('GRANT SELECT (id, action_key, status, current_revision, intent_digest, display_name, canonical_slug, timezone, founder_email, first_admin_display_name, lifecycle_action) ON public.provider_control_operations TO dl_provider');
    }

    public function down(): void
    {
        DB::statement('REVOKE SELECT, INSERT, UPDATE ON public.provider_approval_requests FROM dl_provider');
        DB::statement('REVOKE SELECT, INSERT ON public.provider_approval_decisions FROM dl_provider');
        DB::statement('REVOKE SELECT (id, action_key, status, current_revision, intent_digest, display_name, canonical_slug, timezone, founder_email, first_admin_display_name, lifecycle_action) ON public.provider_control_operations FROM dl_provider');
    }
};
