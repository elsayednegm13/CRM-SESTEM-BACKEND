<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

return new class extends Migration
{
    public function up(): void
    {
        $now = now();
        DB::table('permissions')->insert([
            ['key' => 'company.administer', 'scopeable' => true, 'allowed_scopes' => json_encode(['ALL_TENANT']), 'delegable' => false, 'status' => 'ACTIVE', 'version' => 1, 'description' => 'Company administration invariant', 'created_at' => $now, 'updated_at' => $now],
            ['key' => 'role.view', 'scopeable' => false, 'allowed_scopes' => '[]', 'delegable' => true, 'status' => 'ACTIVE', 'version' => 1, 'description' => 'View company roles', 'created_at' => $now, 'updated_at' => $now],
            ['key' => 'role.manage', 'scopeable' => false, 'allowed_scopes' => '[]', 'delegable' => true, 'status' => 'ACTIVE', 'version' => 1, 'description' => 'Manage company roles', 'created_at' => $now, 'updated_at' => $now],
            ['key' => 'member.view', 'scopeable' => false, 'allowed_scopes' => '[]', 'delegable' => true, 'status' => 'ACTIVE', 'version' => 1, 'description' => 'View company members', 'created_at' => $now, 'updated_at' => $now],
            ['key' => 'member.manage', 'scopeable' => false, 'allowed_scopes' => '[]', 'delegable' => true, 'status' => 'ACTIVE', 'version' => 1, 'description' => 'Manage company memberships', 'created_at' => $now, 'updated_at' => $now],
        ]);

        $templateId = (string) Str::uuid7();
        DB::table('role_templates')->insert([
            'id' => $templateId, 'code' => 'company_admin', 'version' => 1,
            'display_name' => 'Company Admin', 'status' => 'ACTIVE',
            'created_at' => $now, 'updated_at' => $now,
        ]);
        foreach (['company.administer', 'role.view', 'role.manage', 'member.view', 'member.manage'] as $key) {
            DB::table('role_template_permissions')->insert([
                'template_id' => $templateId, 'permission_key' => $key,
                'scope' => $key === 'company.administer' ? 'ALL_TENANT' : null,
            ]);
        }
    }

    public function down(): void
    {
        $template = DB::table('role_templates')->where('code', 'company_admin')->where('version', 1)->value('id');
        if ($template) {
            DB::table('role_template_permissions')->where('template_id', $template)->delete();
            DB::table('role_templates')->where('id', $template)->delete();
        }
        DB::table('permissions')->whereIn('key', ['company.administer', 'role.view', 'role.manage', 'member.view', 'member.manage'])->delete();
    }
};
