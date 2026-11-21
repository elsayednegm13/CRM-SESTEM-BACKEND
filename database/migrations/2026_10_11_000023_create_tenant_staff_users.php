<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('tenant_staff_users', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->uuid('tenant_id');
            $table->string('canonical_email', 254);
            $table->string('display_email', 254);
            $table->string('display_name', 160);
            $table->string('password_hash', 255);
            $table->string('status', 8)->default('ACTIVE');
            $table->unsignedBigInteger('auth_version')->default(1);
            $table->timestampsTz();

            $table->foreign('tenant_id')->references('id')->on('tenants')->restrictOnDelete();
            $table->unique(['tenant_id', 'canonical_email'], 'tenant_staff_email_per_tenant_unique');
            $table->unique(['tenant_id', 'id'], 'tenant_staff_tenant_id_id_unique');
            $table->index(['tenant_id', 'status', 'id'], 'tenant_staff_tenant_status_idx');
        });

        DB::statement("ALTER TABLE tenant_staff_users ADD CONSTRAINT tenant_staff_status_check CHECK (status IN ('ACTIVE', 'DISABLED'))");
        DB::statement('ALTER TABLE tenant_staff_users ADD CONSTRAINT tenant_staff_auth_version_check CHECK (auth_version >= 1)');
        DB::statement("ALTER TABLE tenant_staff_users ADD CONSTRAINT tenant_staff_email_canonical_check CHECK (canonical_email = lower(canonical_email) AND canonical_email = btrim(canonical_email) AND canonical_email ~ '^[^[:space:]@]+@[^[:space:]@]+$')");
        DB::statement(<<<'SQL'
            ALTER TABLE tenant_staff_users
            ADD CONSTRAINT tenant_staff_password_argon2id_check
            CHECK (password_hash LIKE '$argon2id$%')
        SQL);

        Schema::create('tenant_staff_memberships', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->uuid('tenant_id');
            $table->uuid('staff_user_id');
            $table->string('status', 9)->default('ACTIVE');
            $table->unsignedBigInteger('authorization_version')->default(1);
            $table->timestampTz('joined_at')->useCurrent();
            $table->uuid('created_by_membership_id')->nullable();
            $table->uuid('created_by_provider_operation_id')->nullable();
            $table->timestampsTz();

            $table->foreign('tenant_id')->references('id')->on('tenants')->restrictOnDelete();
            $table->foreign(['tenant_id', 'staff_user_id'])
                ->references(['tenant_id', 'id'])->on('tenant_staff_users')->restrictOnDelete();
            $table->foreign('created_by_provider_operation_id')
                ->references('id')->on('provider_control_operations')->restrictOnDelete();
            $table->unique('staff_user_id', 'tenant_staff_one_membership_per_user_unique');
            $table->unique(['tenant_id', 'staff_user_id'], 'tenant_staff_membership_per_tenant_user_unique');
            $table->unique(['tenant_id', 'id'], 'tenant_staff_membership_tenant_id_id_unique');
            $table->index(['tenant_id', 'status', 'staff_user_id'], 'tenant_staff_membership_tenant_status_idx');
        });

        Schema::table('tenant_staff_memberships', function (Blueprint $table): void {
            $table->foreign(['tenant_id', 'created_by_membership_id'])
                ->references(['tenant_id', 'id'])->on('tenant_staff_memberships')->restrictOnDelete();
        });

        DB::statement("ALTER TABLE tenant_staff_memberships ADD CONSTRAINT tenant_staff_membership_status_check CHECK (status IN ('ACTIVE', 'SUSPENDED'))");
        DB::statement('ALTER TABLE tenant_staff_memberships ADD CONSTRAINT tenant_staff_membership_version_check CHECK (authorization_version >= 1)');
        DB::statement("ALTER TABLE tenant_staff_memberships ADD CONSTRAINT tenant_staff_membership_creator_check CHECK (num_nonnulls(created_by_membership_id, created_by_provider_operation_id) = 1)");

        DB::statement(<<<'SQL'
            CREATE OR REPLACE FUNCTION tenant_staff_user_owner_immutable() RETURNS trigger
            LANGUAGE plpgsql
            AS $$
            BEGIN
                IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id THEN
                    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'tenant staff owner is immutable';
                END IF;
                RETURN NEW;
            END
            $$
        SQL);
        DB::statement(<<<'SQL'
            CREATE TRIGGER tenant_staff_user_owner_immutable_trigger
            BEFORE UPDATE OF tenant_id ON tenant_staff_users
            FOR EACH ROW EXECUTE FUNCTION tenant_staff_user_owner_immutable()
        SQL);

        DB::statement(<<<'SQL'
            CREATE OR REPLACE FUNCTION tenant_staff_membership_owner_immutable() RETURNS trigger
            LANGUAGE plpgsql
            AS $$
            BEGIN
                IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
                    OR NEW.staff_user_id IS DISTINCT FROM OLD.staff_user_id
                    OR NEW.created_by_membership_id IS DISTINCT FROM OLD.created_by_membership_id
                    OR NEW.created_by_provider_operation_id IS DISTINCT FROM OLD.created_by_provider_operation_id THEN
                    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'tenant staff membership identity and provenance are immutable';
                END IF;
                RETURN NEW;
            END
            $$
        SQL);
        DB::statement(<<<'SQL'
            CREATE TRIGGER tenant_staff_membership_owner_immutable_trigger
            BEFORE UPDATE OF tenant_id, staff_user_id, created_by_membership_id, created_by_provider_operation_id
            ON tenant_staff_memberships
            FOR EACH ROW EXECUTE FUNCTION tenant_staff_membership_owner_immutable()
        SQL);

        DB::statement(<<<'SQL'
            CREATE OR REPLACE FUNCTION tenant_staff_membership_creator_valid() RETURNS trigger
            LANGUAGE plpgsql
            AS $$
            BEGIN
                IF NEW.created_by_provider_operation_id IS NOT NULL AND NOT EXISTS (
                    SELECT 1 FROM provider_control_operations operation
                    WHERE operation.id = NEW.created_by_provider_operation_id
                      AND operation.action_key = 'company.provision'
                      AND operation.target_tenant_id = NEW.tenant_id
                ) THEN
                    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'provider operation does not provision this tenant';
                END IF;
                IF NEW.created_by_membership_id IS NOT NULL AND NOT EXISTS (
                    SELECT 1 FROM tenant_staff_memberships creator
                    WHERE creator.id = NEW.created_by_membership_id
                      AND creator.tenant_id = NEW.tenant_id
                      AND creator.staff_user_id = app_rls_current_user_id()
                      AND creator.status = 'ACTIVE'
                ) THEN
                    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'staff creator must be the active same-tenant actor';
                END IF;
                RETURN NEW;
            END
            $$
        SQL);
        DB::statement(<<<'SQL'
            CREATE TRIGGER tenant_staff_membership_creator_valid_trigger
            BEFORE INSERT ON tenant_staff_memberships
            FOR EACH ROW EXECUTE FUNCTION tenant_staff_membership_creator_valid()
        SQL);

        DB::statement(<<<'SQL'
            CREATE OR REPLACE FUNCTION tenant_staff_user_requires_membership() RETURNS trigger
            LANGUAGE plpgsql
            AS $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM tenant_staff_memberships membership
                    WHERE membership.tenant_id = NEW.tenant_id
                      AND membership.staff_user_id = NEW.id
                ) THEN
                    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'tenant staff identity requires exactly one tenant membership';
                END IF;
                RETURN NULL;
            END
            $$
        SQL);
        DB::statement(<<<'SQL'
            CREATE CONSTRAINT TRIGGER tenant_staff_user_requires_membership_trigger
            AFTER INSERT ON tenant_staff_users
            DEFERRABLE INITIALLY DEFERRED
            FOR EACH ROW EXECUTE FUNCTION tenant_staff_user_requires_membership()
        SQL);
        DB::statement(<<<'SQL'
            CREATE OR REPLACE FUNCTION tenant_staff_membership_delete_deny() RETURNS trigger
            LANGUAGE plpgsql
            AS $$
            BEGIN
                RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'tenant staff membership is retained; suspend instead';
            END
            $$
        SQL);
        DB::statement(<<<'SQL'
            CREATE TRIGGER tenant_staff_membership_delete_deny_trigger
            BEFORE DELETE ON tenant_staff_memberships
            FOR EACH ROW EXECUTE FUNCTION tenant_staff_membership_delete_deny()
        SQL);

        foreach (['tenant_staff_users', 'tenant_staff_memberships'] as $table) {
            DB::statement("ALTER TABLE {$table} ENABLE ROW LEVEL SECURITY");
            DB::statement("ALTER TABLE {$table} FORCE ROW LEVEL SECURITY");
            DB::statement("CREATE POLICY {$table}_tenant_scope ON {$table} FOR ALL "
                .'USING (app_rls_context_mode() = \'TENANT\' AND tenant_id = app_rls_current_tenant_id() AND app_rls_current_user_id() IS NOT NULL) '
                .'WITH CHECK (app_rls_context_mode() = \'TENANT\' AND tenant_id = app_rls_current_tenant_id() AND app_rls_current_user_id() IS NOT NULL)');
            DB::statement("REVOKE ALL ON TABLE {$table} FROM PUBLIC");
        }
    }

    public function down(): void
    {
        throw new LogicException('FND-ID-01 migrations are forward-only; restore from an approved snapshot instead.');
    }
};
