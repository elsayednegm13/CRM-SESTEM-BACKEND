<?php

namespace App\Modules\Provider\Application;

use App\Modules\Provider\Domain\ProviderAccessException;
use App\Modules\Provider\Domain\ProviderContext;
use App\Modules\Provider\Infrastructure\Persistence\ProviderUser;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Throwable;

final class ProviderAuthorizationService
{
    public function __construct(private readonly ProviderSessionStatePolicy $sessions) {}

    public function current(Request $request): ProviderContext
    {
        // MFA enrollment is opt-in. A verified password-authenticated Provider
        // may use ordinary RBAC-protected features before enrollment; sensitive
        // callers still enforce their own verified step-up/receipt boundary.
        return $this->currentSession($request, false);
    }

    /**
     * Account-security-only context. An MFA-unenrolled password-authenticated
     * Provider may use it solely on routes guarded by the dedicated middleware.
     * It never creates a step-up and is not used by provisioning routes.
     */
    public function currentForSecuritySettings(Request $request): ProviderContext
    {
        return $this->currentSession($request, false);
    }

    private function currentSession(Request $request, bool $requireEnrolledMfa): ProviderContext
    {
        $session = $request->session();
        $guardUser = Auth::guard('provider')->user();
        if (! $guardUser instanceof ProviderUser) {
            throw ProviderAccessException::authRequired();
        }
        $user = ProviderUser::query()->whereKey($guardUser->getKey())->first([
            'id', 'status', 'email_verified_at', 'mfa_enrolled_at', 'auth_version', 'authorization_version',
        ]);
        $started = $session->get('provider.authenticated_at');
        $version = $session->get('provider.auth_version');
        if (! $user || ! $this->sessions->valid($user, $started, $version, now('UTC')->timestamp,
            (int) config('provider.absolute_session_seconds'), $requireEnrolledMfa)) {
            // The authoritative consumer also rechecks these versions, so a failed
            // issuer revocation cannot preserve authority. Best-effort revocation
            // shortens the invalidation window without masking the local logout.
            try {
                app(ProviderAuthorityService::class)->revokeCurrentSession($request);
            } catch (Throwable) {
                // No credential or session details are emitted from this boundary.
            }
            Auth::guard('provider')->logout();
            $session->forget(['provider.authenticated_at', 'provider.auth_version', 'provider.step_up', 'provider.pending', 'provider.authority_generation', 'provider.authority_receipts']);
            $session->regenerate();
            throw ProviderAccessException::authRequired();
        }
        $step = $session->get('provider.step_up');
        $stepAt = is_array($step) && ($step['provider_id'] ?? null) === $user->getKey()
            && ($step['auth_version'] ?? null) === $user->auth_version
            && is_numeric($step['verified_at'] ?? null)
            && is_numeric($step['expires_at'] ?? null)
            && now('UTC')->timestamp < (int) $step['expires_at']
            ? (int) $step['verified_at'] : null;

        return new ProviderContext($user->getKey(), $user->auth_version,
            $user->authorization_version, (string) $request->attributes->get('request_id'),
            (int) $started, $stepAt);
    }

    public function assertStepUp(ProviderContext $context): void
    {
        if ($context->stepUpVerifiedAt === null
            || now('UTC')->timestamp - $context->stepUpVerifiedAt >= (int) config('provider.step_up_seconds')) {
            throw ProviderAccessException::stepUpRequired();
        }
    }

    /** @return list<string> */
    public function capabilities(ProviderContext $context): array
    {
        if ($context->mode !== ProviderContext::MODE) {
            throw ProviderAccessException::denied();
        }
        return DB::connection('pgsql_provider')->table('provider_user_capabilities as assignment')
            ->join('provider_capabilities as catalog', 'catalog.key', '=', 'assignment.capability_key')
            ->where('assignment.provider_user_id', $context->providerUserId)
            ->where('catalog.status', 'ACTIVE')
            ->where(static function ($query): void {
                $query->whereNull('assignment.expires_at')->orWhere('assignment.expires_at', '>', now('UTC'));
            })->orderBy('assignment.capability_key')->pluck('assignment.capability_key')->all();
    }

    public function assertCapability(ProviderContext $context, string $key): void
    {
        if (! in_array($key, $this->capabilities($context), true)) {
            throw ProviderAccessException::denied();
        }
    }
}
