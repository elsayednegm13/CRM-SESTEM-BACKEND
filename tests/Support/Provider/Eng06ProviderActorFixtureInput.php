<?php

declare(strict_types=1);

namespace Tests\Support\Provider;

use LogicException;

/** Immutable, runtime-injected target and actor credentials for the ENG-06 test fixture. */
final readonly class Eng06ProviderActorFixtureInput
{
    public function __construct(
        private string $tag,
        private string $runPrefix,
        private string $databaseName,
        private string $databaseOid,
        /** Runner-side attestation; this initializer checks only its decimal form. */
        private string $clusterSystemIdentifier,
        private string $requesterPassword,
        private string $requesterTotpSecret,
        private string $reviewerPassword,
        private string $reviewerTotpSecret,
    ) {}

    public function tag(): string
    {
        return $this->tag;
    }

    public function runPrefix(): string
    {
        return $this->runPrefix;
    }

    public function databaseName(): string
    {
        return $this->databaseName;
    }

    public function databaseOid(): string
    {
        return $this->databaseOid;
    }

    public function clusterSystemIdentifier(): string
    {
        return $this->clusterSystemIdentifier;
    }

    public function requesterPassword(): string
    {
        return $this->requesterPassword;
    }

    public function requesterTotpSecret(): string
    {
        return $this->requesterTotpSecret;
    }

    public function reviewerPassword(): string
    {
        return $this->reviewerPassword;
    }

    public function reviewerTotpSecret(): string
    {
        return $this->reviewerTotpSecret;
    }

    /** Prevent accidental object dumps from displaying runtime credentials. */
    public function __debugInfo(): array
    {
        return [
            'tag' => $this->tag,
            'run_prefix' => $this->runPrefix,
            'target' => '[attestation omitted]',
            'actor_credentials' => '[redacted]',
        ];
    }

    /** @throws LogicException */
    public function __serialize(): array
    {
        throw new LogicException('Provider fixture input cannot be serialized.');
    }

    /** @param array<string, mixed> $data */
    public function __unserialize(array $data): void
    {
        throw new LogicException('Provider fixture input cannot be unserialized.');
    }
}
