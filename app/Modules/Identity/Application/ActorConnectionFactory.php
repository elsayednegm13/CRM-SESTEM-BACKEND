<?php

namespace App\Modules\Identity\Application;

use App\Modules\Identity\Domain\Exceptions\ActorSqlUnavailableException;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use LogicException;

/**
 * SECURITY-F06-LARAVEL-IMPLEMENT-01: switches the 'pgsql_tenant_runtime' Laravel
 * connection name to a per-actor PostgreSQL LOGIN for the lifetime of one request,
 * then restores the original shared configuration. This is the only class allowed
 * to call Config::set()+DB::purge() on this connection for this feature.
 *
 * Hard rules enforced here (NOT optional):
 *  - switchTo() refuses (fail-closed, LogicException) if transactionLevel() > 0 --
 *    purging a connection mid-transaction would silently drop/orphan it instead of
 *    rolling back. (NC-03)
 *  - switchTo() always re-verifies `session_user` against the role it just
 *    requested; a mismatch throws instead of proceeding (NC-01).
 *  - A missing/invalid password never falls back to the shared runtime credential;
 *    it throws before any PDO connection is attempted (NC-02).
 *  - reset() is unconditional and connection-name-scoped: it restores the exact
 *    username/password this factory captured at construction, and purges again,
 *    so a later request on the same PHP-FPM worker cannot inherit an actor
 *    connection left over from a previous request (SESSION_REUSE / GATE-06).
 */
final class ActorConnectionFactory
{
    private const CONNECTION = 'pgsql_tenant_runtime';

    private readonly ?string $originalUsername;

    private readonly ?string $originalPassword;

    private bool $switched = false;

    public function __construct()
    {
        $this->originalUsername = config('database.connections.'.self::CONNECTION.'.username');
        $this->originalPassword = config('database.connections.'.self::CONNECTION.'.password');
    }

    public function switchTo(string $sqlRoleName, ?string $password): void
    {
        if ($password === null || $password === '') {
            $mapped = config('f06_actor_sql.synthetic_actor_passwords', []);
            throw is_array($mapped) && array_key_exists($sqlRoleName, $mapped)
                ? ActorSqlUnavailableException::missingCredential()
                : ActorSqlUnavailableException::unmappedActor();
        }

        $connection = DB::connection(self::CONNECTION);
        if ($connection->transactionLevel() > 0) {
            throw new LogicException('Refusing to switch the actor SQL identity while a transaction is open on pgsql_tenant_runtime.');
        }

        Config::set('database.connections.'.self::CONNECTION.'.username', $sqlRoleName);
        Config::set('database.connections.'.self::CONNECTION.'.password', $password);
        DB::purge(self::CONNECTION);
        $this->switched = true;

        try {
            $observed = DB::connection(self::CONNECTION)->selectOne('SELECT session_user AS value')->value ?? null;
        } catch (\Throwable $e) {
            // Any connection/auth failure here (not just a session_user mismatch)
            // must not leave Config permanently pointed at a broken credential --
            // restore the original shared config before propagating the error.
            $this->forceRestoreOriginalConfig();
            throw $e;
        }

        if ($observed !== $sqlRoleName) {
            // Fail closed and immediately drop the connection we just opened.
            $this->forceRestoreOriginalConfig();
            throw ActorSqlUnavailableException::identityMismatch();
        }
    }

    /** Always call from a finally block, whether or not the request succeeded. */
    public function reset(): void
    {
        if (! $this->switched) {
            return;
        }

        $connection = DB::connection(self::CONNECTION);
        if ($connection->transactionLevel() > 0) {
            // A caller that forgot to roll back before reset() is a programming
            // error upstream; fail loudly rather than purge a connection with an
            // open transaction still attached to it.
            throw new LogicException('Refusing to reset the actor SQL identity while a transaction is still open.');
        }

        $this->forceRestoreOriginalConfig();
    }

    /** Unconditional restore, used both by reset() and by switchTo()'s own failure paths. */
    private function forceRestoreOriginalConfig(): void
    {
        Config::set('database.connections.'.self::CONNECTION.'.username', $this->originalUsername);
        Config::set('database.connections.'.self::CONNECTION.'.password', $this->originalPassword);
        DB::purge(self::CONNECTION);
        $this->switched = false;
    }
}
