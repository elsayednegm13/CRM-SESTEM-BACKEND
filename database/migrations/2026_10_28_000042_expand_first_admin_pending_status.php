<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/** The V1 pending state cannot fit the original varchar(8) staff status column. */
return new class extends Migration
{
    public function up(): void
    {
        $column = DB::selectOne("SELECT character_maximum_length AS n FROM information_schema.columns WHERE table_schema='public' AND table_name='tenant_staff_users' AND column_name='status'");
        if (! $column || (int) $column->n !== 8) {
            throw new RuntimeException('Unexpected staff status width before V1 upgrade.');
        }
        // PostgreSQL refuses a type change while ANY policy on ANY table refers
        // to this column. Discover exact dependencies rather than guessing from
        // policy names. All changes stay inside this migration transaction.
        $dependencies = DB::select(<<<'SQL'
            SELECT c.relname AS table_name, p.polname AS policy_name
            FROM pg_depend d
            JOIN pg_policy p ON p.oid=d.objid
            JOIN pg_class c ON c.oid=p.polrelid
            WHERE d.classid='pg_policy'::regclass
              AND d.refobjid='public.tenant_staff_users'::regclass
              AND d.refobjsubid=(SELECT attnum FROM pg_attribute
                    WHERE attrelid=d.refobjid AND attname='status')
            ORDER BY c.relname,p.polname
        SQL);
        $expected = [
            'tenant_staff_memberships/tenant_staff_memberships_provider_first_admin_insert',
            'tenant_staff_security_events/tenant_staff_security_events_provider_first_admin_insert',
            'tenant_staff_users/tenant_staff_users_core01_v1_insert',
            'tenant_staff_users/tenant_staff_users_provider_first_admin_insert',
            'tenants/tenants_provider_first_admin_activate',
            'tenants/tenants_provider_first_admin_activation_guard',
        ];
        if (array_map(static fn ($row) => $row->table_name.'/'.$row->policy_name, $dependencies) !== $expected) {
            throw new RuntimeException('Unexpected RLS dependencies on staff status.');
        }
        $saved = [];
        foreach ($dependencies as $dependency) {
            $table = $dependency->table_name;
            $name = $dependency->policy_name;
            $policy = DB::selectOne("SELECT permissive, roles, cmd, qual, with_check FROM pg_policies WHERE schemaname='public' AND tablename=? AND policyname=?", [$table, $name]);
            if (! $policy || ! in_array($policy->roles, ['{public}', '{daleel_provider_first_admin_writer}'], true)
                || ! in_array($policy->permissive, ['PERMISSIVE', 'RESTRICTIVE'], true)
                || ! in_array($policy->cmd, ['INSERT', 'UPDATE'], true)) {
                throw new RuntimeException('Unexpected staff status policy shape: '.$name);
            }
            $saved[] = [$table, $name, $policy];
            DB::statement('DROP POLICY '.$name.' ON public.'.$table);
        }
        DB::statement('ALTER TABLE public.tenant_staff_users ALTER COLUMN status TYPE varchar(32)');
        foreach ($saved as [$table, $name, $policy]) {
            $role = $policy->roles === '{public}' ? 'PUBLIC' : 'daleel_provider_first_admin_writer';
            $definition = 'CREATE POLICY '.$name.' ON public.'.$table.' AS '.$policy->permissive.' FOR '.$policy->cmd.' TO '.$role;
            if ($policy->qual !== null) {
                $definition .= ' USING ('.$policy->qual.')';
            }
            if ($policy->with_check !== null) {
                $definition .= ' WITH CHECK ('.$policy->with_check.')';
            }
            DB::statement($definition);
        }
    }

    public function down(): void
    {
        throw new RuntimeException('Narrowing the staff status would destroy V1 pending values.');
    }
};
