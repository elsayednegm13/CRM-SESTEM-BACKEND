<?php

namespace App\Modules\Provider\Application;

use App\Modules\Provider\Domain\ProviderAccessException;
use App\Modules\Provider\Domain\ProviderContext;
use App\Modules\Provider\Infrastructure\Persistence\ProviderDatabaseContext;
use App\Modules\Shared\Audit\AuditEventType;
use App\Modules\Shared\Audit\SecurityAuditWriter;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;

/**
 * Provider team & capability administration.
 * provider_users / provider_user_capabilities carry no RLS (see docs/PROVIDER_SECURITY.md); the
 * capability + step-up checks below are the real enforcement, not a defense-in-depth layer on
 * top of a database policy. Every mutation still runs inside ProviderDatabaseContext so the
 * audit row and the data change share one PostgreSQL transaction.
 */
final class ProviderTeamService
{
    public function __construct(
        private readonly ProviderAuthorizationService $authorization,
        private readonly ProviderDatabaseContext $context,
        private readonly SecurityAuditWriter $audit,
    ) {}

    public function listTeam(ProviderContext $actor): array
    {
        $this->authorization->assertCapability($actor, 'provider.team.manage');
        $users = DB::connection('pgsql_provider')->table('provider_users')
            ->orderBy('created_at')
            ->get(['id', 'email', 'status', 'email_verified_at', 'mfa_enrolled_at', 'created_at']);
        $grants = DB::connection('pgsql_provider')->table('provider_user_capabilities')
            ->whereIn('provider_user_id', $users->pluck('id'))
            ->get(['provider_user_id', 'capability_key', 'granted_at', 'expires_at'])
            ->groupBy('provider_user_id');

        return $users->map(fn ($user) => [
            'id' => $user->id, 'email' => $user->email, 'status' => $user->status,
            'email_verified' => $user->email_verified_at !== null,
            'mfa_enrolled' => $user->mfa_enrolled_at !== null,
            'capabilities' => ($grants->get($user->id) ?? collect())
                ->map(fn ($grant) => ['key' => $grant->capability_key, 'granted_at' => $grant->granted_at,
                    'expires_at' => $grant->expires_at])->values()->all(),
        ])->all();
    }

    /** @return array{id:string,email:string,temporary_password:string} */
    public function createMember(ProviderContext $actor, string $email): array
    {
        $this->authorization->assertStepUp($actor);
        $this->authorization->assertCapability($actor, 'provider.team.manage');
        $email = mb_strtolower(trim($email));
        if (! filter_var($email, FILTER_VALIDATE_EMAIL) || mb_strlen($email) > 254) {
            throw ValidationException::withMessages(['email' => ['The email address is invalid.']]);
        }
        $password = Str::password(32);
        return $this->context->run($actor->providerUserId, function ($db) use ($actor, $email, $password): array {
            if (DB::connection('pgsql_provider')->table('provider_users')->where('email', $email)->exists()) {
                throw ValidationException::withMessages(['email' => ['A provider account with this email already exists.']]);
            }
            $id = (string) Str::uuid7();
            $now = now('UTC');
            $db->table('provider_users')->insert([
                'id' => $id, 'email' => $email, 'password' => Hash::make($password),
                'status' => 'ACTIVE', 'email_verified_at' => $now, 'mfa_enrolled_at' => null,
                'auth_version' => 1, 'authorization_version' => 1, 'created_at' => $now, 'updated_at' => $now,
            ]);
            $this->audit->appendProviderMutation($actor->providerUserId, $actor->requestId,
                AuditEventType::PROVIDER_TEAM_MEMBER_CREATED, $id);
            return ['id' => $id, 'email' => $email, 'temporary_password' => $password];
        });
    }

    public function grantCapability(ProviderContext $actor, string $targetProviderUserId, string $capabilityKey): void
    {
        $this->authorization->assertStepUp($actor);
        $this->authorization->assertCapability($actor, 'provider.team.manage');
        if (! Str::isUuid($targetProviderUserId)) {
            throw ProviderAccessException::approvalUnusable();
        }
        if ($targetProviderUserId === $actor->providerUserId) {
            // No self-grant: a team-manage holder must not be able to escalate their own account.
            throw ProviderAccessException::denied();
        }
        $this->context->run($actor->providerUserId, function ($db) use ($actor, $targetProviderUserId, $capabilityKey): void {
            $catalog = DB::connection('pgsql_provider')->table('provider_capabilities')
                ->where('key', $capabilityKey)->where('status', 'ACTIVE')->exists();
            $target = DB::connection('pgsql_provider')->table('provider_users')
                ->where('id', $targetProviderUserId)->exists();
            if (! $catalog || ! $target) {
                throw ValidationException::withMessages(['capability_key' => ['The capability or provider account is invalid.']]);
            }
            $db->table('provider_user_capabilities')->insertOrIgnore([
                'provider_user_id' => $targetProviderUserId, 'capability_key' => $capabilityKey,
                'granted_at' => now('UTC'), 'expires_at' => null,
            ]);
            $db->table('provider_users')->where('id', $targetProviderUserId)->increment('authorization_version');
            $this->audit->appendProviderMutation($actor->providerUserId, $actor->requestId,
                AuditEventType::PROVIDER_CAPABILITY_GRANTED, $targetProviderUserId, ['capability_key' => $capabilityKey]);
        });
    }

    public function revokeCapability(ProviderContext $actor, string $targetProviderUserId, string $capabilityKey): void
    {
        $this->authorization->assertStepUp($actor);
        $this->authorization->assertCapability($actor, 'provider.team.manage');
        if (! Str::isUuid($targetProviderUserId)) {
            throw ProviderAccessException::approvalUnusable();
        }
        if ($targetProviderUserId === $actor->providerUserId && $capabilityKey === 'provider.team.manage') {
            // Never let the last-standing enforcement path remove its own ability to grant/revoke.
            $otherHolders = DB::connection('pgsql_provider')->table('provider_user_capabilities')
                ->where('capability_key', 'provider.team.manage')
                ->where('provider_user_id', '<>', $actor->providerUserId)->exists();
            if (! $otherHolders) {
                throw ProviderAccessException::denied();
            }
        }
        $this->context->run($actor->providerUserId, function ($db) use ($actor, $targetProviderUserId, $capabilityKey): void {
            $deleted = $db->table('provider_user_capabilities')
                ->where('provider_user_id', $targetProviderUserId)->where('capability_key', $capabilityKey)->delete();
            if ($deleted === 0) {
                throw ValidationException::withMessages(['capability_key' => ['That grant does not exist.']]);
            }
            $db->table('provider_users')->where('id', $targetProviderUserId)->increment('authorization_version');
            $this->audit->appendProviderMutation($actor->providerUserId, $actor->requestId,
                AuditEventType::PROVIDER_CAPABILITY_REVOKED, $targetProviderUserId, ['capability_key' => $capabilityKey]);
        });
    }

    public function setStatus(ProviderContext $actor, string $targetProviderUserId, string $status): void
    {
        $this->authorization->assertStepUp($actor);
        $this->authorization->assertCapability($actor, 'provider.team.manage');
        if (! Str::isUuid($targetProviderUserId) || ! in_array($status, ['ACTIVE', 'DISABLED'], true)) {
            throw ProviderAccessException::approvalUnusable();
        }
        if ($targetProviderUserId === $actor->providerUserId) {
            throw ProviderAccessException::denied();
        }
        $this->context->run($actor->providerUserId, function ($db) use ($actor, $targetProviderUserId, $status): void {
            $target = DB::connection('pgsql_provider')->table('provider_users')
                ->where('id', $targetProviderUserId)->first(['status']);
            if (! $target) {
                throw ProviderAccessException::approvalUnusable();
            }
            if ($target->status === $status) {
                return;
            }
            if ($status === 'DISABLED') {
                $holdsTeamManage = DB::connection('pgsql_provider')->table('provider_user_capabilities')
                    ->where('provider_user_id', $targetProviderUserId)->where('capability_key', 'provider.team.manage')->exists();
                $otherActiveHolders = DB::connection('pgsql_provider')->table('provider_users as u')
                    ->join('provider_user_capabilities as c', 'c.provider_user_id', '=', 'u.id')
                    ->where('c.capability_key', 'provider.team.manage')->where('u.status', 'ACTIVE')
                    ->where('u.id', '<>', $targetProviderUserId)->exists();
                if ($holdsTeamManage && ! $otherActiveHolders) {
                    throw ProviderAccessException::denied();
                }
            }
            $db->table('provider_users')->where('id', $targetProviderUserId)
                ->update(['status' => $status, 'auth_version' => DB::raw('auth_version + 1'),
                    'authorization_version' => DB::raw('authorization_version + 1'), 'updated_at' => now('UTC')]);
            $this->audit->appendProviderMutation($actor->providerUserId, $actor->requestId,
                AuditEventType::PROVIDER_USER_STATUS_CHANGED, $targetProviderUserId,
                ['before_status' => $target->status, 'after_status' => $status]);
        });
    }
}
