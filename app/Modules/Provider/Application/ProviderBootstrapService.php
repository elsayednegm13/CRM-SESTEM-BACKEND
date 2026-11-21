<?php

namespace App\Modules\Provider\Application;

use App\Modules\Identity\Domain\EmailAddressNormalizer;
use App\Modules\Provider\Domain\ProviderAccessException;
use App\Modules\Provider\Domain\ProviderBootstrapPolicy;
use App\Modules\Provider\Infrastructure\Persistence\ProviderDatabaseContext;
use App\Modules\Shared\Audit\AuditEventType;
use App\Modules\Shared\Audit\SecurityAuditWriter;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Str;
use SensitiveParameter;
use Throwable;

final class ProviderBootstrapService
{
    public function __construct(
        private readonly ProviderBootstrapPolicy $policy,
        private readonly EmailAddressNormalizer $emails,
        private readonly ProviderDatabaseContext $context,
        private readonly SecurityAuditWriter $audit,
    ) {}

    /** Status is advisory; creation always repeats all checks under the marker lock. */
    public function status(): array
    {
        $this->policy->assertConfigured(config('provider.bootstrap', []), time());
        try {
            return $this->context->run((string) Str::uuid7(), function ($db): array {
                $this->assertAvailable($db);
                return ['state' => 'AVAILABLE'];
            });
        } catch (Throwable) {
            // Query exceptions may contain bindings. Never propagate them to reporting.
            throw new ProviderAccessException('PROVIDER_SETUP_UNAVAILABLE', 409);
        }
    }

    public function create(#[SensitiveParameter] array $input, string $requestId): array
    {
        // An invalid proof must not cause even a database connection.
        $this->policy->assertSecret(config('provider.bootstrap', []), $input['bootstrap_secret'] ?? null, time());
        if (RateLimiter::hit('provider:installation-setup:global', 3600) > 20) {
            throw ProviderAccessException::rateLimited();
        }
        $identity = $this->policy->identity($input, $this->emails);
        if (! Str::isUuid($requestId)) {
            throw new ProviderAccessException('PROVIDER_SETUP_INPUT_INVALID', 422);
        }
        $id = (string) Str::uuid7();
        try {
            return $this->context->run($id, function ($db) use ($id, $identity, $input, $requestId): array {
                $this->assertAvailable($db);
                $this->policy->assertSecret(config('provider.bootstrap', []), $input['bootstrap_secret'] ?? null, time());
                $capabilities = $db->table('provider_capabilities')->where('status', 'ACTIVE')->pluck('key')->all();
                if (! in_array('provider.team.manage', $capabilities, true)) {
                    throw new ProviderAccessException('PROVIDER_SETUP_UNAVAILABLE', 409);
                }
                $now = now('UTC');
                // Seal under the lock before inserts: population triggers then no-op.
                // A failed insert/audit still rolls back this seal in the same transaction.
                if ($db->table('provider_installation_setup')->where('id', 1)->where('sealed', false)
                    ->update(['sealed' => true, 'completed_at' => $now]) !== 1) {
                    throw new ProviderAccessException('PROVIDER_SETUP_UNAVAILABLE', 409);
                }
                $db->table('provider_users')->insert([
                    'id' => $id, 'email' => $identity['email'], 'password' => Hash::make($identity['password']),
                    'status' => 'ACTIVE', 'email_verified_at' => $now, 'mfa_enrolled_at' => null,
                    'auth_version' => 1, 'authorization_version' => 1, 'created_at' => $now, 'updated_at' => $now,
                ]);
                foreach ($capabilities as $key) {
                    $db->table('provider_user_capabilities')->insert([
                        'provider_user_id' => $id, 'capability_key' => $key, 'granted_at' => $now, 'expires_at' => null,
                    ]);
                }
                $this->audit->appendProviderMutation($id, $requestId, AuditEventType::PROVIDER_TEAM_MEMBER_CREATED, $id);
                // P2 makes routine MFA account-optional. High-risk action
                // authority remains independently guarded by its existing
                // issuer/step-up contract.
                return ['status' => 'created', 'next' => 'LOGIN_AVAILABLE'];
            });
        } catch (ProviderAccessException $exception) {
            throw new ProviderAccessException($exception->safeCode, $exception->status);
        } catch (Throwable) {
            throw new ProviderAccessException('PROVIDER_SETUP_UNAVAILABLE', 409);
        }
    }

    private function assertAvailable($db): void
    {
        $marker = $db->table('provider_installation_setup')->where('id', 1)->lockForUpdate()->first(['sealed', 'completed_at']);
        if (! $marker || ! in_array($marker->sealed, [false, 0, '0', 'f'], true) || $marker->completed_at !== null
            || $db->table('provider_users')->exists()) {
            throw new ProviderAccessException('PROVIDER_SETUP_UNAVAILABLE', 409);
        }
    }
}
