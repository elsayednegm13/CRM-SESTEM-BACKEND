<?php

namespace App\Modules\Shared\Audit;

use App\Modules\Tenancy\Domain\TenantContext;
use App\Modules\Provider\Domain\ProviderContext;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use LogicException;

/** One authoritative append path; no update, delete, public read, or audit bypass. */
final class SecurityAuditWriter
{
    public function appendTenantMutation(TenantContext $actor, AuditEventType $event, string $targetId): string
    {
        if (! $event->isTenantMutation()) {
            throw new LogicException('Invalid tenant audit event.');
        }
        $this->assertTransaction();
        $this->assertUuid($actor->userId);
        $this->assertUuid($actor->tenantId);
        $this->assertUuid($actor->requestId);

        return $this->insert($event, $targetId, $actor->requestId, 'TENANT_USER', $actor->userId, $actor->tenantId);
    }

    /** Internal global-disable service has no caller identity or public route in this batch. */
    public function appendInternalUserDisabled(string $targetUserId, ?string $tenantId): string
    {
        $this->assertTransaction();
        $this->assertUuid($targetUserId);
        if ($tenantId !== null) {
            $this->assertUuid($tenantId);
        }

        return $this->insert(AuditEventType::USER_DISABLED, $targetUserId, null, 'SYSTEM', null, $tenantId);
    }

    /** Only the already-restricted local/testing disposable bootstrap may call this. */
    public function appendDisposableBootstrap(TenantContext $founder): string
    {
        if (! app()->environment(['local', 'testing']) || ! config('tenancy.disposable_bootstrap_enabled')) {
            throw new LogicException('Disposable audit bootstrap is unavailable.');
        }
        $this->assertTransaction();
        $this->assertUuid($founder->tenantId);
        $this->assertUuid($founder->requestId);

        return $this->insert(AuditEventType::COMPANY_ADMIN_BOOTSTRAPPED, $founder->tenantId,
            $founder->requestId, 'SYSTEM', null, $founder->tenantId);
    }

    /** Provider service supplies the authenticated or password-pending server principal. */
    public function appendProviderMutation(string $serverProviderId, string $requestId,
        AuditEventType $event, string $targetId, array $metadata = [], ?string $tenantId = null): string
    {
        if (! $event->isProviderMutation()) {
            throw new LogicException('Invalid provider audit event.');
        }
        $this->assertUuid($serverProviderId);
        $this->assertUuid($requestId);
        $this->assertUuid($targetId);
        $tenantScoped = $event->isProviderTenantScopedMutation();
        if ($tenantScoped !== ($tenantId !== null) || ($tenantScoped && $targetId !== $tenantId)) {
            throw new LogicException('Invalid provider-mutation tenant scope.');
        }
        if ($tenantId !== null) {
            $this->assertUuid($tenantId);
        }
        $connection = DB::connection('pgsql_provider');
        if ($connection->getDriverName() !== 'pgsql' || $connection->transactionLevel() < 1) {
            throw new LogicException('Provider audit requires the provider PostgreSQL transaction.');
        }
        $id = (string) Str::uuid7();
        $connection->table('security_audit_events')->insert([
            'id' => $id,
            'category' => $event->category(),
            'event_type' => $event->value,
            'outcome' => 'SUCCESS',
            'request_id' => $requestId,
            'actor_type' => 'PROVIDER_USER',
            'actor_id' => $serverProviderId,
            'tenant_id' => $tenantId,
            'target_type' => $event->targetType(),
            'target_id' => $targetId,
            'source_channel' => 'PROVIDER',
            'metadata' => json_encode((object) $event->metadata($metadata), JSON_THROW_ON_ERROR),
        ]);

        return $id;
    }

    /** 10C provider-control facts are written on the caller's guarded transaction/connection. */
    public function appendProviderControlMutation(ConnectionInterface $connection, ProviderContext $actor,
        AuditEventType $event, string $targetId, ?string $tenantId = null, array $metadata = []): string
    {
        if (! $event->isProviderControlMutation()) {
            throw new LogicException('Invalid provider-control audit event.');
        }
        $this->assertConnectionTransaction($connection);
        $this->assertUuid($actor->providerUserId);
        $this->assertUuid($actor->requestId);
        $this->assertUuid($targetId);
        if ($tenantId !== null) {
            $this->assertUuid($tenantId);
        }
        $eventMetadata = $event->metadata($metadata);
        $tenantEvent = in_array($event, [AuditEventType::TENANT_PROVISIONING_EXECUTED,
            AuditEventType::TENANT_RECOVERY_EXECUTED, AuditEventType::TENANT_LIFECYCLE_CHANGED], true);
        if ($tenantEvent !== ($tenantId !== null) || ($tenantEvent && $targetId !== $tenantId)) {
            throw new LogicException('Invalid provider-control audit target.');
        }

        return $this->insertOn($connection, $event, $targetId, $actor->requestId,
            'PROVIDER_USER', $actor->providerUserId, $tenantId, 'PROVIDER', $eventMetadata);
    }

    /** Founder activation facts are written on the invite's activation transaction. */
    public function appendFounderActivation(ConnectionInterface $connection, string $userId, string $tenantId,
        AuditEventType $event, string $targetId, string $membershipId): string
    {
        if (! $event->isFounderActivation()) {
            throw new LogicException('Invalid founder activation audit event.');
        }
        $this->assertConnectionTransaction($connection);
        $this->assertUuid($userId);
        $this->assertUuid($tenantId);
        $this->assertUuid($targetId);
        $this->assertUuid($membershipId);
        if (($event === AuditEventType::TENANT_ACTIVATED && $targetId !== $tenantId)
            || ($event === AuditEventType::TENANT_FOUNDER_INVITATION_ACCEPTED && $targetId === $tenantId)) {
            throw new LogicException('Invalid founder activation audit target.');
        }

        return $this->insertOn($connection, $event, $targetId, null,
            'TENANT_USER', $userId, $tenantId, 'API', ['membership_id' => $membershipId]);
    }

    private function insert(AuditEventType $event, string $targetId, ?string $requestId,
        string $actorType, ?string $actorId, ?string $tenantId): string
    {
        $this->assertUuid($targetId);
        $id = (string) Str::uuid7();
        return $this->insertOn(DB::connection(), $event, $targetId, $requestId,
            $actorType, $actorId, $tenantId, 'INTERNAL', $event->metadata());
    }

    private function insertOn(ConnectionInterface $connection, AuditEventType $event, string $targetId,
        ?string $requestId, string $actorType, ?string $actorId, ?string $tenantId, string $sourceChannel,
        array $metadata): string
    {
        $event->metadata($metadata);
        $id = (string) Str::uuid7();
        $connection->table('security_audit_events')->insert([
            'id' => $id,
            'category' => $event->category(),
            'event_type' => $event->value,
            'outcome' => 'SUCCESS',
            'request_id' => $requestId,
            'actor_type' => $actorType,
            'actor_id' => $actorId,
            'tenant_id' => $tenantId,
            'target_type' => $event->targetType(),
            'target_id' => $targetId,
            'source_channel' => $sourceChannel,
            'metadata' => json_encode((object) $metadata, JSON_THROW_ON_ERROR),
        ]);

        return $id;
    }

    private function assertConnectionTransaction(ConnectionInterface $connection): void
    {
        if ($connection->getDriverName() !== 'pgsql' || $connection->transactionLevel() < 1) {
            throw new LogicException('Security audit requires an active PostgreSQL transaction.');
        }
    }

    private function assertTransaction(): void
    {
        if (DB::transactionLevel() < 1 || DB::connection()->getDriverName() !== 'pgsql') {
            throw new LogicException('Security audit requires an active PostgreSQL transaction.');
        }
    }

    private function assertUuid(string $value): void
    {
        if (! Str::isUuid($value)) {
            throw new LogicException('Security audit identifier is invalid.');
        }
    }
}
