<?php

namespace Tests\Feature\Identity;

/**
 * CORE-01 G2 — mandatory pre-write identity guard for the service-layer
 * authority tests (AL09 fault injection, AL11 concurrency / parallel).
 *
 * The connection target is ENV-configurable (G2_SANDBOX_*), but no ENV value
 * can widen the guard: a forbidden port or a protected reference database is
 * REFUSED (hard failure) even when ENV explicitly points there, and the live
 * system_identifier must match the single authorized sandbox before any write.
 *
 * Skip (BLOCKED) vs. fail (REFUSED):
 *   - ENV not configured            -> markTestSkipped  (BLOCKED, never a PASS)
 *   - config/ENV mismatch           -> markTestSkipped  (BLOCKED)
 *   - forbidden port / protected DB -> fail()           (REFUSED)
 *   - system_identifier mismatch    -> fail()           (REFUSED)
 *   - missing BYPASSRLS on verifier -> fail()           (REFUSED)
 *
 * This guard changes no production code, migration, trigger, RLS policy, or
 * role privilege; it only verifies the environment and returns a superuser PDO
 * bound to the verified sandbox for the RLS-bypass verification writes that the
 * (unchanged) test logic already performs.
 */
trait G2SandboxGuard
{
    private const G2_ALLOWED_SYSTEM_IDENTIFIER = '7702591224362536999';

    /** Permanently forbidden published ports — refused regardless of ENV. */
    private const G2_FORBIDDEN_PORTS = [55440, 55441, 55501, 55502, 55503, 55504, 55505];

    /** Permanently protected reference databases — never a write target. */
    private const G2_PROTECTED_DATABASES = ['d1_fresh', 'd1_upgrade', 'postgres'];

    protected string $g2Host = '127.0.0.1';
    protected int $g2Port = 0;
    protected string $g2Db = '';

    /**
     * Resolve the sandbox target from ENV, or null when it is not configured.
     *
     * @return array{host:string,port:int,db:string,superuser:string}|null
     */
    private function g2SandboxTarget(): ?array
    {
        $db = env('G2_SANDBOX_DB');
        $port = env('G2_SANDBOX_PORT');

        if ($db === null || $db === '' || $port === null || $port === '') {
            return null;
        }

        return [
            'host' => (string) env('G2_SANDBOX_HOST', '127.0.0.1'),
            'port' => (int) $port,
            'db' => (string) $db,
            'superuser' => (string) env('G2_SANDBOX_SUPERUSER', 'postgres'),
        ];
    }

    /**
     * MANDATORY. Call first in setUp(), before any write. Verifies identity and
     * authorized scope and returns a verified superuser PDO, or skips/refuses.
     */
    private function g2GuardOrSkip(): \PDO
    {
        $t = $this->g2SandboxTarget();
        if ($t === null) {
            $this->markTestSkipped(
                'G2 sandbox not configured (set G2_SANDBOX_DB / G2_SANDBOX_PORT). '
                .'Declared BLOCKED — not converted to PASS.'
            );
        }

        // The service under test connects via pgsql_tenant_auth; that live
        // connection must point at the same sandbox we are about to verify,
        // else the run would not exercise the sandbox at all.
        $cfgDb = config('database.connections.pgsql_tenant_auth.database');
        $cfgPort = (int) config('database.connections.pgsql_tenant_auth.port');
        if ($cfgDb !== $t['db'] || $cfgPort !== $t['port']) {
            $this->markTestSkipped(
                "G2 sandbox ENV ({$t['db']}:{$t['port']}) does not match the active "
                ."pgsql_tenant_auth connection ({$cfgDb}:{$cfgPort}). Declared BLOCKED."
            );
        }

        // REFUSE forbidden ports even when ENV points there (condition 3).
        if (in_array($t['port'], self::G2_FORBIDDEN_PORTS, true)) {
            $this->fail("G2 GUARD REFUSED: port {$t['port']} is on the permanent forbidden-port list.");
        }
        // REFUSE protected reference databases even when ENV points there.
        if (in_array($t['db'], self::G2_PROTECTED_DATABASES, true)) {
            $this->fail("G2 GUARD REFUSED: database '{$t['db']}' is a permanently protected reference database.");
        }
        // REQUIRE the synthetic g2_ prefix — writes only ever hit g2_* DBs.
        if (! str_starts_with($t['db'], 'g2_')) {
            $this->fail("G2 GUARD REFUSED: database '{$t['db']}' lacks the required g2_ prefix.");
        }

        // Live identity BEFORE any write: system_identifier must match the one
        // authorized sandbox. A matching identifier pins the physical cluster
        // regardless of which host port routed us here.
        $dsn = "pgsql:host={$t['host']};port={$t['port']};dbname={$t['db']}";
        $pdo = new \PDO($dsn, $t['superuser'], (string) config('database.connections.pgsql.password'));
        $pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);

        $liveId = (string) $pdo->query('SELECT system_identifier FROM pg_control_system()')->fetchColumn();
        if ($liveId !== self::G2_ALLOWED_SYSTEM_IDENTIFIER) {
            $this->fail(
                "G2 GUARD REFUSED: live system_identifier '{$liveId}' does not match the "
                ."authorized sandbox '".self::G2_ALLOWED_SYSTEM_IDENTIFIER."'."
            );
        }

        // Privilege check: the verification identity must truly bypass RLS,
        // otherwise its verification reads/writes would be silently filtered.
        $priv = (string) $pdo->query(
            'SELECT (rolsuper OR rolbypassrls)::text FROM pg_roles WHERE rolname = current_user'
        )->fetchColumn();
        if ($priv !== 'true' && $priv !== 't') {
            $this->fail('G2 GUARD REFUSED: verification identity lacks superuser/BYPASSRLS.');
        }

        $this->g2Host = $t['host'];
        $this->g2Port = $t['port'];
        $this->g2Db = $t['db'];

        return $pdo;
    }
}
