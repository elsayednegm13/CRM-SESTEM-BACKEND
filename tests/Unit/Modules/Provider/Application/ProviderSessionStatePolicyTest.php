<?php

declare(strict_types=1);

namespace Tests\Unit\Modules\Provider\Application;

use App\Modules\Provider\Application\ProviderSessionStatePolicy;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ProviderSessionStatePolicyTest extends TestCase
{
    private ProviderSessionStatePolicy $policy;

    protected function setUp(): void
    {
        $this->policy = new ProviderSessionStatePolicy;
    }

    public function test_mfa_01_fresh_unenrolled_password_session_is_valid_for_ordinary_authorization(): void
    {
        $user = $this->user(false);
        self::assertTrue($this->policy->valid($user, 900, 1, 1000, 3600, false));
        self::assertFalse($this->policy->valid($user, 900, 1, 1000, 3600, true));
    }

    public function test_m03_enrolled_session_is_valid_for_high_risk_boundary_but_policy_never_creates_step_up(): void
    {
        $user = $this->user(true);
        self::assertTrue($this->policy->valid($user, 900, 1, 1000, 3600, true));
        self::assertObjectNotHasProperty('step_up_verified_at', $user);
    }

    public function test_mfa_01_ordinary_provider_session_is_not_coupled_to_enrollment(): void
    {
        $source = file_get_contents(dirname(__DIR__, 5).'/app/Modules/Provider/Application/ProviderAuthorizationService.php');
        self::assertIsString($source);
        self::assertStringContainsString('return $this->currentSession($request, false);', $source);
        self::assertGreaterThanOrEqual(2, substr_count($source, 'currentSession($request, false)'));
    }

    #[DataProvider('invalidSessions')]
    public function test_m05_m06_wrong_expired_revoked_or_cross_account_state_is_denied(object $user, mixed $started, mixed $version): void
    {
        self::assertFalse($this->policy->valid($user, $started, $version, 1000, 100, false));
    }

    public static function invalidSessions(): array
    {
        $base = static fn (): object => (object) [
            'status' => 'ACTIVE', 'email_verified_at' => 'verified',
            'mfa_enrolled_at' => null, 'auth_version' => 3,
        ];
        $revoked = $base(); $revoked->status = 'DISABLED';
        $unverified = $base(); $unverified->email_verified_at = null;

        return [
            'revoked account' => [$revoked, 950, 3],
            'unverified account' => [$unverified, 950, 3],
            'expired session' => [$base(), 899, 3],
            'future session' => [$base(), 1001, 3],
            'rotated auth version' => [$base(), 950, 2],
            'missing session version' => [$base(), 950, null],
        ];
    }

    private function user(bool $enrolled): object
    {
        return (object) [
            'status' => 'ACTIVE', 'email_verified_at' => 'verified',
            'mfa_enrolled_at' => $enrolled ? 'enrolled' : null,
            'auth_version' => 1,
        ];
    }
}
