<?php

namespace App\Modules\Identity\Application;

use App\Modules\Identity\Domain\TenantHostContext;
use Illuminate\Database\Connection;
use RuntimeException;

/** Request-local SQL proof; the runtime login cannot read its signing key. */
final class CoreSqlContextSigner
{
    public function bind(Connection $connection, TenantHostContext $host, string $userId,
        string $membershipId, int $authVersion, int $authorizationVersion,
        ?string $sessionHash = null, ?string $sessionGeneration = null): void
    {
        $key = config('core_sql.signing_key');
        if (! is_string($key) || ! preg_match('/^[a-f0-9]{64}$/D', $key)) {
            throw new RuntimeException('Trusted SQL context key is unavailable.');
        }
        if ($sessionHash !== null && $sessionGeneration !== null
            && preg_match('/^[a-f0-9]{64}$/D', $sessionHash) === 1) {
            $connection->selectOne('SELECT pg_catalog.set_config(?, ?, true)', ['app.core01_login_bridge', '']);
            $generation = (int) config('core_sql.signing_key_generation', 1);
            if ($generation < 1) {
                throw new RuntimeException('Trusted SQL key generation is unavailable.');
            }
            $backend = $connection->selectOne('SELECT pg_catalog.pg_backend_pid() AS pid');
            if (! is_object($backend) || ! is_numeric($backend->pid ?? null) || (int) $backend->pid < 1) {
                throw new RuntimeException('Trusted SQL backend binding is unavailable.');
            }
            $parts = [$host->tenantId, $userId, $membershipId, (string) $authVersion,
                (string) $authorizationVersion, $sessionHash, $sessionGeneration, (string) $generation,
                (string) $backend->pid, (string) (time() + 90), bin2hex(random_bytes(16)), 'v3'];
        } else {
            throw new RuntimeException('Trusted SQL session authority is unavailable.');
        }
        $message = implode('|', $parts);
        $signature = hash_hmac('sha256', $message, hex2bin($key));
        $connection->selectOne('SELECT pg_catalog.set_config(?, ?, true)',
            ['app.core01_signed_context', $message.'|'.$signature]);
    }
}
