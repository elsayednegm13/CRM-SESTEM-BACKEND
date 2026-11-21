<?php

namespace App\Modules\Identity\Application;

use App\Modules\Identity\Domain\EmailAddressNormalizer;
use InvalidArgumentException;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

/** Builds a safe direct-account persistence payload; it does not persist or authenticate it. */
final class TenantStaffAccountFactory
{
    public function __construct(private readonly EmailAddressNormalizer $emails)
    {
    }

    /**
     * @return array{id:string,tenant_id:string,canonical_email:string,display_email:string,display_name:string,password_hash:string,status:string,auth_version:int,created_at:mixed,updated_at:mixed}
     */
    public function build(string $tenantId, string $email, string $displayName, string $initialPassword): array
    {
        if (! Str::isUuid($tenantId)) {
            throw new InvalidArgumentException('A valid tenant identity is required.');
        }

        $canonicalEmail = $this->emails->normalize($email);
        $displayEmail = preg_replace('/^\s+|\s+$/u', '', $email);
        if (! is_string($displayEmail) || $displayEmail === '' || mb_strlen($displayEmail, 'UTF-8') > 254) {
            throw new InvalidArgumentException('A valid email address is required.');
        }

        $displayName = trim($displayName);
        if ($displayName === '' || mb_strlen($displayName, 'UTF-8') > 160
            || preg_match('/[\x00-\x1F\x7F]/u', $displayName) === 1) {
            throw new InvalidArgumentException('A valid display name is required.');
        }

        if (! mb_check_encoding($initialPassword, 'UTF-8')
            || mb_strlen($initialPassword, 'UTF-8') < 12
            || strlen($initialPassword) > 1024) {
            throw new InvalidArgumentException('The initial password does not meet the configured password requirements.');
        }

        $now = now();

        return [
            'id' => (string) Str::uuid(),
            'tenant_id' => $tenantId,
            'canonical_email' => $canonicalEmail,
            'display_email' => $displayEmail,
            'display_name' => $displayName,
            'password_hash' => Hash::driver('argon2id')->make($initialPassword),
            'status' => 'ACTIVE',
            'auth_version' => 1,
            'created_at' => $now,
            'updated_at' => $now,
        ];
    }
}
