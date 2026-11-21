<?php

namespace Tests\Feature\ProviderControl;

use App\Modules\Shared\Audit\AuditEventType;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Database\QueryException;
use LogicException;
use Illuminate\Support\Str;
use Tests\TestCase;

final class ProviderControlVocabularyTest extends TestCase
{
    use RefreshDatabase;

    public function test_10c_event_vocabulary_matches_enum_database_constraints_and_rls(): void
    {
        $expected = [
            'provider.control_operation.created' => ['PROVIDER_SECURITY', 'provider_control_operation'],
            'provider.control_operation.cancelled' => ['PROVIDER_SECURITY', 'provider_control_operation'],
            'provider.approval.requested' => ['PROVIDER_SECURITY', 'approval_request'],
            'provider.approval.approved' => ['PROVIDER_SECURITY', 'approval_request'],
            'provider.approval.rejected' => ['PROVIDER_SECURITY', 'approval_request'],
            'provider.approval.revoked' => ['PROVIDER_SECURITY', 'approval_request'],
            'tenant.provisioning.executed' => ['TENANT_SECURITY', 'tenant'],
            'tenant.recovery.executed' => ['TENANT_SECURITY', 'tenant'],
            'tenant.founder_invitation.accepted' => ['IDENTITY_SECURITY', 'tenant_founder_invitation'],
            'tenant.activated' => ['TENANT_SECURITY', 'tenant'],
        ];

        foreach ($expected as $token => [$category, $target]) {
            $event = AuditEventType::tryFrom($token);
            $this->assertNotNull($event, "Missing enum event: {$token}");
            $this->assertSame($category, $event->category());
            $this->assertSame($target, $event->targetType());
        }

        $this->assertNull(AuditEventType::tryFrom('provider.approval.approve'));
        $this->assertSame('provider.approval.approved', AuditEventType::PROVIDER_APPROVAL_APPROVED->value);

        $invalidId = (string) Str::uuid();
        try {
            DB::transaction(fn () => DB::table('security_audit_events')->insert(
                $this->providerApprovalAuditRow($invalidId, 'provider.approval.approve')));
            $this->fail('The obsolete approval alias unexpectedly passed PostgreSQL CHECK constraints.');
        } catch (QueryException $exception) {
            $this->assertSame('23514', $exception->errorInfo[0] ?? null);
        }
        $canonicalId = (string) Str::uuid();
        DB::table('security_audit_events')->insert($this->providerApprovalAuditRow($canonicalId,
            AuditEventType::PROVIDER_APPROVAL_APPROVED->value));
        $this->assertDatabaseHas('security_audit_events', [
            'id' => $canonicalId,
            'event_type' => AuditEventType::PROVIDER_APPROVAL_APPROVED->value,
        ]);

        $constraints = DB::select("select conname, pg_get_constraintdef(oid) as definition from pg_constraint where conrelid = 'security_audit_events'::regclass");
        $definitions = [];
        foreach ($constraints as $constraint) {
            $definitions[$constraint->conname] = $constraint->definition;
        }
        foreach (['security_audit_provider_event_shape_check', 'security_audit_current_event_target_check',
            'security_audit_metadata_check'] as $name) {
            $this->assertArrayHasKey($name, $definitions);
        }
        foreach (array_keys($expected) as $token) {
            $this->assertStringContainsString($token, implode("\n", $definitions), "DB CHECK missing {$token}");
        }
        $this->assertStringNotContainsString('provider.approval.approve\'', implode("\n", $definitions));

        $policies = DB::select("select policyname, coalesce(qual, '') || ' ' || coalesce(with_check, '') as definition from pg_policies where schemaname = current_schema() and tablename = 'security_audit_events'");
        $policyText = implode("\n", array_map(static fn (object $policy): string => $policy->definition, $policies));
        foreach (array_keys($expected) as $token) {
            $this->assertStringContainsString($token, $policyText, "RLS policy missing {$token}");
        }

        $service = file_get_contents(app_path('Modules/Provider/Application/ProviderControlOperationService.php'));
        foreach (array_keys($expected) as $token) {
            $this->assertStringNotContainsString("'{$token}'", $service, "Service contains raw audit token {$token}");
        }
    }

    public function test_canonical_approved_event_metadata_rejects_unknown_alias_and_shape(): void
    {
        $this->assertSame([], AuditEventType::PROVIDER_APPROVAL_APPROVED->metadata());
        $this->assertSame('provider.approval.approved', AuditEventType::PROVIDER_APPROVAL_APPROVED->value);

        $this->expectException(LogicException::class);
        AuditEventType::TENANT_PROVISIONING_EXECUTED->metadata(['invitation_id' => 'obsolete']);
    }

    private function providerApprovalAuditRow(string $id, string $event): array
    {
        return [
            'id' => $id,
            'category' => 'PROVIDER_SECURITY',
            'event_type' => $event,
            'outcome' => 'SUCCESS',
            'request_id' => (string) Str::uuid(),
            'actor_type' => 'PROVIDER_USER',
            'actor_id' => (string) Str::uuid(),
            'tenant_id' => null,
            'target_type' => 'approval_request',
            'target_id' => (string) Str::uuid(),
            'source_channel' => 'PROVIDER',
            'metadata' => '{}',
        ];
    }
}
