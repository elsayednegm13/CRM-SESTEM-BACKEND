<?php

namespace App\Modules\Provider\Domain;

use RuntimeException;

final class ProviderAccessException extends RuntimeException
{
    public function __construct(public readonly string $safeCode, public readonly int $status = 403)
    {
        parent::__construct($safeCode);
    }

    public static function invalidCredentials(): self { return new self('PROVIDER_INVALID_CREDENTIALS', 401); }
    public static function authRequired(): self { return new self('PROVIDER_AUTH_REQUIRED', 401); }
    public static function unavailable(): self { return new self('PROVIDER_ACCOUNT_UNAVAILABLE', 401); }
    public static function mfaRequired(): self { return new self('PROVIDER_MFA_REQUIRED', 401); }
    public static function mfaInvalid(): self { return new self('PROVIDER_MFA_INVALID', 401); }
    public static function mfaReplayed(): self { return new self('PROVIDER_MFA_REPLAYED', 401); }
    public static function stepUpRequired(): self { return new self('PROVIDER_STEP_UP_REQUIRED', 403); }
    public static function denied(): self { return new self('PROVIDER_AUTHORIZATION_DENIED', 403); }
    public static function approvalUnusable(): self { return new self('PROVIDER_APPROVAL_NOT_USABLE', 403); }
    public static function rateLimited(): self { return new self('PROVIDER_RATE_LIMITED', 429); }
}
