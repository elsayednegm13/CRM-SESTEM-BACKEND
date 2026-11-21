<?php

namespace App\Modules\Provider\Domain;

final readonly class ProviderContext
{
    public const MODE = 'PROVIDER';

    public function __construct(
        public string $providerUserId,
        public int $authVersion,
        public int $authorizationVersion,
        public string $requestId,
        public int $authenticatedAt,
        public ?int $stepUpVerifiedAt,
        public string $mode = self::MODE,
    ) {
    }
}
