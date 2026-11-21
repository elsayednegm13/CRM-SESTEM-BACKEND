<?php

declare(strict_types=1);

namespace App\Modules\Provider\Application;

/**
 * Pure session-state policy shared by normal Provider authorization and the
 * narrowly scoped account-security enrollment boundary.
 */
final class ProviderSessionStatePolicy
{
    public function valid(
        object $user,
        mixed $authenticatedAt,
        mixed $sessionAuthVersion,
        int $now,
        int $absoluteSeconds,
        bool $requireEnrolledMfa,
    ): bool {
        return ($user->status ?? null) === 'ACTIVE'
            && ($user->email_verified_at ?? null) !== null
            && (! $requireEnrolledMfa || ($user->mfa_enrolled_at ?? null) !== null)
            && is_numeric($authenticatedAt)
            && is_numeric($sessionAuthVersion)
            && (int) $sessionAuthVersion === (int) ($user->auth_version ?? -1)
            && $now >= (int) $authenticatedAt
            && $now - (int) $authenticatedAt < $absoluteSeconds;
    }
}
