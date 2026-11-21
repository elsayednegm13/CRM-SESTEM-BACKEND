<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    public function up(): void
    {
        if (DB::connection()->getDriverName() !== 'pgsql' || DB::connection()->transactionLevel() < 1) {
            throw new RuntimeException('Provider installation attestation requires a PostgreSQL migration transaction.');
        }

        // Block writes during attestation. Missing tables/permissions/RLS visibility abort,
        // rather than treating a filtered or partial view of an upgrade as a fresh install.
        DB::statement('SET LOCAL row_security = off');
        $tables = ['provider_users', 'users', 'tenant_staff_users', 'tenants', 'security_audit_events',
            'provider_control_operations', 'provider_approval_requests'];
        foreach ($tables as $table) {
            DB::statement('LOCK TABLE public.'.$table.' IN SHARE ROW EXCLUSIVE MODE');
        }
        $sealed = false;
        foreach ($tables as $table) {
            $row = DB::selectOne('SELECT EXISTS (SELECT 1 FROM public.'.$table.') AS populated');
            if (! in_array($row->populated, [false, 0, '0', 'f'], true)) {
                $sealed = true;
            }
        }

        DB::statement(<<<'SQL'
            CREATE TABLE public.provider_installation_setup (
                id smallint PRIMARY KEY CHECK (id = 1),
                sealed boolean NOT NULL,
                completed_at timestamptz NULL,
                CHECK (sealed OR completed_at IS NULL)
            )
        SQL);
        DB::table('public.provider_installation_setup')->insert(['id' => 1, 'sealed' => $sealed, 'completed_at' => null]);
        DB::unprepared(<<<'SQL'
            CREATE FUNCTION public.provider_installation_setup_guard() RETURNS trigger
            LANGUAGE plpgsql SET search_path = pg_catalog AS $guard$
            BEGIN
                IF TG_OP <> 'UPDATE' THEN
                    RAISE EXCEPTION 'Provider installation seal is permanent';
                END IF;
                IF OLD.sealed OR NEW.id <> OLD.id OR NOT NEW.sealed OR NEW.completed_at IS NULL THEN
                    RAISE EXCEPTION 'Provider installation seal is permanent';
                END IF;
                RETURN NEW;
            END;
            $guard$;
            REVOKE ALL ON FUNCTION public.provider_installation_setup_guard() FROM PUBLIC;
            -- Owned by the migration principal. This definer can only remove setup authority.
            CREATE FUNCTION public.provider_installation_setup_seal_on_population() RETURNS trigger
            LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $seal$
            BEGIN
                UPDATE public.provider_installation_setup
                SET sealed = true, completed_at = clock_timestamp()
                WHERE id = 1 AND NOT sealed;
                RETURN NEW;
            END;
            $seal$;
            REVOKE ALL ON FUNCTION public.provider_installation_setup_seal_on_population() FROM PUBLIC;
            CREATE TRIGGER provider_installation_setup_update_delete
                BEFORE UPDATE OR DELETE ON public.provider_installation_setup
                FOR EACH ROW EXECUTE FUNCTION public.provider_installation_setup_guard();
            CREATE TRIGGER provider_installation_setup_truncate
                BEFORE TRUNCATE ON public.provider_installation_setup
                FOR EACH STATEMENT EXECUTE FUNCTION public.provider_installation_setup_guard();
            DO $acl$
            DECLARE recipient name;
            BEGIN
                IF pg_has_role('dl_provider', current_user, 'MEMBER') THEN
                    RAISE EXCEPTION 'Provider runtime must not inherit installation marker ownership';
                END IF;
                -- Remove any default-ACL grants on this NEW table only.
                FOR recipient IN
                    SELECT DISTINCT r.rolname
                    FROM pg_roles r
                    JOIN aclexplode((SELECT relacl FROM pg_class
                        WHERE oid = 'public.provider_installation_setup'::regclass)) a ON a.grantee = r.oid
                    WHERE r.oid <> (SELECT relowner FROM pg_class
                        WHERE oid = 'public.provider_installation_setup'::regclass)
                LOOP
                    EXECUTE format('REVOKE ALL ON TABLE public.provider_installation_setup FROM %I', recipient);
                END LOOP;
            END;
            $acl$;
            REVOKE ALL ON TABLE public.provider_installation_setup FROM PUBLIC, dl_provider;
            GRANT SELECT ON TABLE public.provider_installation_setup TO dl_provider;
            GRANT UPDATE (sealed, completed_at) ON TABLE public.provider_installation_setup TO dl_provider;
        SQL);

        // Keep all attestation locks until these hooks are installed and committed.
        // Row triggers ignore zero-row inserts and share the setup transaction's marker lock.
        foreach ($tables as $table) {
            DB::statement('CREATE TRIGGER provider_installation_setup_population AFTER INSERT ON public.'.$table.
                ' FOR EACH ROW EXECUTE FUNCTION public.provider_installation_setup_seal_on_population()');
        }
    }

    public function down(): void
    {
        throw new RuntimeException('Forward-only: preserve the permanent Provider installation seal.');
    }
};
