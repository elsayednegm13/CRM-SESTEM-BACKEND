<?php

namespace App\Modules\Tenancy\Infrastructure\Persistence;

use App\Modules\Tenancy\Domain\TenantAccessException;
use App\Modules\Tenancy\Domain\TenantContext;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use InvalidArgumentException;
use stdClass;

/** Fixed-table base for future tenant-owned repositories. Subclasses define their table. */
abstract class TenantScopedRepository
{
    public function __construct(protected readonly TenantContextGuard $guard)
    {
    }

    abstract protected function table(): string;

    private function scoped(TenantContext $context): Builder
    {
        return DB::table($this->table())->where('tenant_id', $context->tenantId);
    }

    public function find(?TenantContext $context, string $id): ?stdClass
    {
        return $this->guard->run($context, fn () => $this->scoped($context)->where('id', $id)->first());
    }

    public function count(?TenantContext $context): int
    {
        return $this->guard->run($context, fn () => $this->scoped($context)->count());
    }

    public function create(?TenantContext $context, array $attributes): void
    {
        $this->rejectOwnershipFields($attributes);
        $this->guard->run($context, fn () => $this->scoped($context)->insert([...$attributes, 'tenant_id' => $context->tenantId]), true);
    }

    public function update(?TenantContext $context, string $id, array $attributes): bool
    {
        $this->rejectOwnershipFields($attributes);
        return $this->guard->run($context, fn () => $this->scoped($context)->where('id', $id)->update($attributes) === 1, true);
    }

    public function delete(?TenantContext $context, string $id): bool
    {
        return $this->guard->run($context, fn () => $this->scoped($context)->where('id', $id)->delete() === 1, true);
    }

    public function requireOwned(?TenantContext $context, string $id): void
    {
        if (! $this->find($context, $id)) {
            throw TenantAccessException::objectNotFound();
        }
    }

    private function rejectOwnershipFields(array $attributes): void
    {
        if (array_key_exists('tenant_id', $attributes)) {
            throw new InvalidArgumentException('Tenant ownership is controlled by the server.');
        }
    }
}
