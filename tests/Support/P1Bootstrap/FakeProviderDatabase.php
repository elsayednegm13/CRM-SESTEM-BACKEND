<?php

declare(strict_types=1);

namespace Tests\Support\P1Bootstrap;

use Closure;
use Illuminate\Support\Collection;
use RuntimeException;

/** In-memory adapter only. No PDO, database driver, SQL interpreter or Laravel boot. */
final class FakeProviderDatabase
{
    public array $rows = [
        'provider_installation_setup' => [['id' => 1, 'sealed' => false, 'completed_at' => null]],
        'provider_users' => [],
        'users' => [],
        'tenant_staff_users' => [],
        'tenants' => [],
        'provider_control_operations' => [],
        'provider_approval_requests' => [],
        'provider_capabilities' => [
            ['key' => 'provider.team.manage', 'status' => 'ACTIVE'],
            ['key' => 'company.provision', 'status' => 'ACTIVE'],
            ['key' => 'retired.example', 'status' => 'RETIRED'],
        ],
        'provider_user_capabilities' => [],
        'security_audit_events' => [],
    ];
    public array $events = [];
    public int $connections = 0;
    public int $depth = 0;
    public bool $failAudit = false;
    public bool $failInsert = false;
    public bool $failSeal = false;
    public bool $missingMarkerTable = false;
    public string $driver = 'pgsql';
    public ?Closure $beforeTransaction = null;

    public function connection(?string $name = null): self
    {
        if ($name !== 'pgsql_provider') {
            throw new RuntimeException('Unexpected database connection.');
        }
        $this->connections++;
        return $this;
    }

    public function getDriverName(): string { return $this->driver; }
    public function transactionLevel(): int { return $this->depth; }

    public function transaction(Closure $operation): mixed
    {
        if ($this->beforeTransaction !== null) {
            ($this->beforeTransaction)();
        }
        $before = $this->rows;
        $this->depth++;
        $this->events[] = 'transaction.begin';
        try {
            $result = $operation();
            $this->events[] = 'transaction.commit';
            return $result;
        } catch (\Throwable $exception) {
            $this->rows = $before;
            $this->events[] = 'transaction.rollback';
            throw $exception;
        } finally {
            $this->depth--;
        }
    }

    /** ProviderDatabaseContext settings are acknowledged, never executed as SQL. */
    public function selectOne(string $statement, array $bindings): object
    {
        if ($this->depth < 1 || (! str_contains($statement, 'current_setting') && ! str_contains($statement, 'set_config'))) {
            throw new RuntimeException('Unexpected context adapter operation.');
        }
        $this->events[] = 'context.setting';
        return (object) ['value' => ''];
    }

    /** Model only: this does NOT execute or prove the PostgreSQL trigger function. */
    public function afterPopulationInsert(string $table): void
    {
        if (! in_array($table, ['provider_users', 'users', 'tenant_staff_users', 'tenants',
            'security_audit_events', 'provider_control_operations', 'provider_approval_requests'], true)) {
            return;
        }
        foreach ($this->rows['provider_installation_setup'] as &$marker) {
            if ($marker['id'] === 1 && ! $marker['sealed']) {
                $marker['sealed'] = true;
                $marker['completed_at'] = new \DateTimeImmutable;
                $this->events[] = 'population-trigger.seal';
                return;
            }
        }
        $this->events[] = 'population-trigger.no-op';
    }

    public function table(string $name): FakeProviderQuery
    {
        if (! array_key_exists($name, $this->rows) || ($name === 'provider_installation_setup' && $this->missingMarkerTable)) {
            throw new RuntimeException('In-memory table unavailable.');
        }
        $this->events[] = $name.'.query';
        return new FakeProviderQuery($this, $name);
    }
}

final class FakeProviderQuery
{
    private array $filters = [];
    private bool $locked = false;

    public function __construct(private FakeProviderDatabase $db, private string $table) {}

    public function where(string $key, mixed $value): self
    {
        $this->filters[$key] = $value;
        return $this;
    }

    public function lockForUpdate(): self
    {
        if ($this->db->depth < 1) {
            throw new RuntimeException('Lock requested outside a transaction.');
        }
        // Records requested lock order; it does NOT implement PostgreSQL concurrency.
        $this->locked = true;
        $this->db->events[] = $this->table.'.lock';
        return $this;
    }

    private function matches(array $row): bool
    {
        foreach ($this->filters as $key => $value) {
            if (($row[$key] ?? null) !== $value) {
                return false;
            }
        }
        return true;
    }

    public function first(array $columns): ?object
    {
        if ($this->table === 'provider_installation_setup' && ! $this->locked) {
            throw new RuntimeException('Marker read was not locked.');
        }
        foreach ($this->db->rows[$this->table] as $row) {
            if ($this->matches($row)) {
                return (object) array_intersect_key($row, array_flip($columns));
            }
        }
        return null;
    }

    public function exists(): bool
    {
        foreach ($this->db->rows[$this->table] as $row) {
            if ($this->matches($row)) {
                return true;
            }
        }
        return false;
    }

    public function pluck(string $column): Collection
    {
        return new Collection(array_values(array_map(fn ($row) => $row[$column],
            array_filter($this->db->rows[$this->table], fn ($row) => $this->matches($row)))));
    }

    public function insert(array $row): bool
    {
        if ($this->db->depth < 1 || $this->table === 'provider_installation_setup') {
            throw new RuntimeException('Unsupported in-memory insert.');
        }
        if ($this->table === 'provider_users' && $this->db->failInsert) {
            throw new RuntimeException('Synthetic account insertion failure.');
        }
        if ($this->table === 'security_audit_events' && $this->db->failAudit) {
            throw new RuntimeException('Synthetic audit failure.');
        }
        $this->db->events[] = $this->table.'.insert';
        $this->db->rows[$this->table][] = $row;
        $this->db->afterPopulationInsert($this->table);
        return true;
    }

    public function update(array $values): int
    {
        if ($this->db->failSeal) {
            return 0;
        }
        $changed = 0;
        foreach ($this->db->rows[$this->table] as &$row) {
            if ($this->matches($row)) {
                $row = array_replace($row, $values);
                $changed++;
            }
        }
        $this->db->events[] = $this->table.'.update';
        return $changed;
    }
}
