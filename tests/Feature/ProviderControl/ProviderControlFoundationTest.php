<?php

namespace Tests\Feature\ProviderControl;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

final class ProviderControlFoundationTest extends TestCase
{
    use RefreshDatabase;

    public function test_control_operation_and_invitation_constraints_are_installed(): void
    {
        $columns = DB::select("select column_name from information_schema.columns where table_schema = current_schema() and table_name = 'provider_control_operations'");
        $names = array_map(static fn (object $row): string => $row->column_name, $columns);
        foreach (['idempotency_key_hash','intent_digest','target_tenant_id','approval_request_id',
            'successor_user_id','compromised_membership_id','recovery_mode','status'] as $column) {
            $this->assertContains($column, $names);
        }
        $this->assertDatabaseHas('provider_capabilities', ['key' => 'company.provision']);
        $this->assertDatabaseHas('provider_capabilities', ['key' => 'company.recover']);
    }

    public function test_provider_control_does_not_change_tenant_rls_policies_or_force_flags(): void
    {
        $rows = DB::select("select c.relname, c.relrowsecurity, c.relforcerowsecurity from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname=current_schema() and c.relname in ('tenants','tenant_memberships','roles','role_permissions','membership_roles','security_audit_events','outbox_messages')");
        $this->assertCount(7, $rows);
        foreach ($rows as $row) {
            $this->assertTrue($row->relrowsecurity);
            $this->assertTrue($row->relforcerowsecurity);
        }
        $policies = DB::select("select policyname from pg_policies where schemaname=current_schema()");
        $names = array_map(static fn (object $row): string => $row->policyname, $policies);
        foreach (['tenants_tenant_select','tenant_memberships_context_select',
            'security_audit_provider_insert','security_audit_provider_control_insert',
            'security_audit_founder_activation_insert','outbox_provider_control_insert'] as $policy) {
            $this->assertContains($policy, $names);
        }
    }

    public function test_audit_and_outbox_are_limited_to_typed_foundation_events(): void
    {
        $checks = DB::select("select conname from pg_constraint where conrelid in ('security_audit_events'::regclass, 'outbox_messages'::regclass)");
        $names = array_map(static fn (object $row): string => $row->conname, $checks);
        $this->assertContains('outbox_founder_delivery_shape_check', $names);
        $this->assertContains('security_audit_metadata_check', $names);
        $this->assertContains('security_audit_current_event_target_check', $names);
    }

    public function test_provider_rls_helpers_short_circuit_outside_their_context_and_remain_invoker_functions(): void
    {
        $helpers = DB::select("select p.proname, l.lanname, p.prosecdef from pg_proc p join pg_language l on l.oid=p.prolang where p.proname in ('app_provider_control_actor_allowed','app_provider_control_tenant_allowed','app_provider_control_request_tenant_allowed','app_founder_activation_tenant_allowed')");
        $this->assertCount(4, $helpers);
        foreach ($helpers as $helper) {
            $this->assertSame('plpgsql', $helper->lanname);
            $this->assertFalse($helper->prosecdef, $helper->proname.' must remain SECURITY INVOKER');
        }

        DB::select("select set_config('app.context_mode', '', true)");
        $allowed = DB::selectOne("select app_provider_control_tenant_allowed(?::uuid) as allowed", ['00000000-0000-4000-8000-000000000001']);
        $this->assertFalse($allowed->allowed);
    }
}
