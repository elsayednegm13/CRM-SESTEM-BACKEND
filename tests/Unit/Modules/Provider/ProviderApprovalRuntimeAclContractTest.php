<?php

namespace Tests\Unit\Modules\Provider;

use PHPUnit\Framework\TestCase;

final class ProviderApprovalRuntimeAclContractTest extends TestCase
{
    public function test_forward_acl_is_narrow_and_does_not_grant_ddl_or_delete(): void
    {
        $source = file_get_contents(dirname(__DIR__, 4).'/database/migrations/2026_11_20_000074_grant_provider_approval_runtime_acl.php');
        self::assertIsString($source);
        self::assertStringContainsString(
            'GRANT SELECT, INSERT, UPDATE ON public.provider_approval_requests TO dl_provider', $source);
        self::assertStringContainsString(
            'GRANT SELECT, INSERT ON public.provider_approval_decisions TO dl_provider', $source);
        self::assertStringContainsString(
            'GRANT SELECT (id, action_key, status, current_revision, intent_digest, display_name, canonical_slug, timezone, founder_email, first_admin_display_name, lifecycle_action) ON public.provider_control_operations TO dl_provider', $source);
        self::assertStringNotContainsString('GRANT SELECT ON public.provider_control_operations', $source);
        self::assertStringNotContainsString('GRANT ALL', $source);
        self::assertStringNotContainsString('DELETE ON public.provider_approval', $source);
        self::assertStringNotContainsString(' TO PUBLIC', $source);
    }
}
