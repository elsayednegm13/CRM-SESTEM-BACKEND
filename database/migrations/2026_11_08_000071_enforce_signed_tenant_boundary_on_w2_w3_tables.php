<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/**
 * Forward-only repair for W2/W3 tables created after 049's signed-boundary
 * inventory. Existing permissive tenant-GUC policies remain necessary for
 * application filtering; this migration adds the independent restrictive
 * signed/session-user gate required for access.
 */
return new class extends Migration
{
    private const TABLES = [
        'customers', 'customer_contacts', 'customer_addresses', 'lead_conversions',
        'sales_pipelines', 'sales_pipeline_stages', 'deals', 'deal_stage_transitions',
        'sales_tasks', 'sales_activities',
    ];

    public function up(): void
    {
        DB::transaction(function (): void {
            DB::unprepared(<<<'SQL'
                DO $guard$
                DECLARE
                    v_table name;
                    v_function oid := 'public.core01_signed_tenant_allowed(uuid)'::regprocedure;
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1
                        FROM pg_proc p
                        JOIN pg_roles owner_r ON owner_r.oid = p.proowner
                        WHERE p.oid = v_function
                          AND p.prosecdef
                          AND owner_r.rolname = 'daleel_core01_authority_definer'
                    ) THEN
                        RAISE EXCEPTION 'W2/W3 signed tenant guard is missing, has an unexpected owner, or is not SECURITY DEFINER';
                    END IF;
                    IF has_function_privilege('public', v_function, 'EXECUTE')
                       OR NOT has_function_privilege('daleel_tenant_runtime', v_function, 'EXECUTE') THEN
                        RAISE EXCEPTION 'W2/W3 signed tenant guard has an unexpected EXECUTE ACL';
                    END IF;
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_roles
                        WHERE rolname = 'daleel_tenant_runtime'
                          AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcanlogin
                    ) THEN
                        RAISE EXCEPTION 'W2/W3 tenant runtime role contract is unsafe';
                    END IF;
                    FOREACH v_table IN ARRAY ARRAY[
                        'customers', 'customer_contacts', 'customer_addresses', 'lead_conversions',
                        'sales_pipelines', 'sales_pipeline_stages', 'deals', 'deal_stage_transitions',
                        'sales_tasks', 'sales_activities'
                    ]
                    LOOP
                        IF NOT EXISTS (
                            SELECT 1
                            FROM pg_class c
                            JOIN pg_namespace n ON n.oid = c.relnamespace
                            JOIN pg_attribute a ON a.attrelid = c.oid
                            WHERE n.nspname = 'public' AND c.relname = v_table
                              AND c.relkind IN ('r', 'p') AND c.relrowsecurity AND c.relforcerowsecurity
                              AND a.attname = 'tenant_id' AND NOT a.attisdropped
                              AND a.atttypid = 'uuid'::regtype
                        ) THEN
                            RAISE EXCEPTION 'W2/W3 table % does not satisfy FORCE RLS tenant-table prerequisites', v_table;
                        END IF;
                        IF EXISTS (
                            SELECT 1 FROM pg_policies
                            WHERE schemaname = 'public' AND tablename = v_table
                              AND policyname = 'core01_signed_runtime_boundary_w2w3'
                        ) THEN
                            RAISE EXCEPTION 'W2/W3 table % already has a conflicting signed-boundary policy', v_table;
                        END IF;
                    END LOOP;
                END
                $guard$
            SQL);

            foreach (self::TABLES as $table) {
                DB::unprepared("CREATE POLICY core01_signed_runtime_boundary_w2w3 ON public.{$table} AS RESTRICTIVE FOR ALL TO daleel_tenant_runtime USING (public.core01_signed_tenant_allowed(tenant_id)) WITH CHECK (public.core01_signed_tenant_allowed(tenant_id))");
            }
        });
    }

    public function down(): void
    {
        throw new RuntimeException('W2/W3 signed tenant boundary is forward-only; restore a reviewed backup to roll back.');
    }
};
