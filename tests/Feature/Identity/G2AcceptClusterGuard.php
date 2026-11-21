<?php

namespace Tests\Feature\Identity;

/**
 * CORE-01 G2 — mandatory pre-write identity guard for the HTTP-level
 * authority tests running against the independent G2 acceptance cluster
 * (port 55460, daleel-d1-g2accept-pg).
 *
 * Unlike G2SandboxGuard (which pins system_identifier to the single
 * authorized sandbox at compile time), this guard reads the expected
 * system_identifier from ENV at runtime. The ENV variable is REQUIRED
 * with no default — a missing or empty G2_ACCEPT_CLUSTER_SYSID is a
 * hard REFUSED, not a skip. This ensures the cluster is explicitly
 * identified before any write.
 *
 * The guard reads the cluster target from G2_ACCEPT_* ENV vars and
 * exposes the same $g2Host / $g2Port / $g2Db properties that
 * G2SandboxGuard exposes, so any test using this guard can call
 * g2GuardOrSkip() identically.
 *
 * Skip (BLOCKED) vs. fail (REFUSED):
 *   - G2_ACCEPT_DB or G2_ACCEPT_PORT not set → markTestSkipped (BLOCKED)
 *   - G2_ACCEPT_CLUSTER_SYSID not set        → fail()           (REFUSED)
 *   - config/ENV mismatch                    → markTestSkipped  (BLOCKED)
 *   - forbidden port / protected DB          → fail()           (REFUSED)
 *   - system_identifier mismatch             → fail()           (REFUSED)
 *   - missing BYPASSRLS on verifier          → fail()           (REFUSED)
 */
trait G2AcceptClusterGuard
{
    /** Permanently forbidden published ports — refused regardless of ENV. */
    private const G2_ACCEPT_FORBIDDEN_PORTS = [55440, 55441, 55501, 55502, 55503, 55504, 55505];

    /** Permanently protected reference databases — never a write target. */
    private const G2_ACCEPT_PROTECTED_DATABASES = ['d1_fresh', 'd1_upgrade', 'postgres'];

    protected string $g2Host = '127.0.0.1';
    protected int    $g2Port = 0;
    protected string $g2Db   = '';

    /**
     * Resolve the acceptance cluster target from ENV, or null when not configured.
     *
     * @return array{host:string,port:int,db:string,superuser:string}|null
     */
    private function g2AcceptTarget(): ?array
    {
        $db   = env('G2_ACCEPT_DB');
        $port = env('G2_ACCEPT_PORT');

        if ($db === null || $db === '' || $port === null || $port === '') {
            return null;
        }

        return [
            'host'      => (string) env('G2_ACCEPT_HOST', '127.0.0.1'),
            'port'      => (int) $port,
            'db'        => (string) $db,
            'superuser' => (string) env('G2_ACCEPT_SUPERUSER', 'postgres'),
        ];
    }

    /**
     * MANDATORY. Call first in setUp(), before any write. Verifies identity
     * and authorized scope, then returns a verified superuser PDO.
     *
     * Method name matches G2SandboxGuard so tests can swap the trait without
     * changing their setUp() body.
     */
    private function g2GuardOrSkip(): \PDO
    {
        // The expected system_identifier is required with no default.
        // An empty/missing ENV means the cluster was never bootstrapped — REFUSED.
        $expectedSysid = env('G2_ACCEPT_CLUSTER_SYSID');
        if ($expectedSysid === null || $expectedSysid === '') {
            $this->fail(
                'G2 ACCEPT GUARD REFUSED: G2_ACCEPT_CLUSTER_SYSID is not set. '
                .'Run build-g2accept-cluster.sh and source the generated identity env file.'
            );
        }

        $t = $this->g2AcceptTarget();
        if ($t === null) {
            $this->markTestSkipped(
                'G2 acceptance cluster not configured (set G2_ACCEPT_DB / G2_ACCEPT_PORT). '
                .'Declared BLOCKED — not converted to PASS.'
            );
        }

        // The service under test connects via pgsql_tenant_auth; that live
        // connection must point at the same cluster we are about to verify.
        $cfgDb   = config('database.connections.pgsql_tenant_auth.database');
        $cfgPort = (int) config('database.connections.pgsql_tenant_auth.port');
        if ($cfgDb !== $t['db'] || $cfgPort !== $t['port']) {
            $this->markTestSkipped(
                "G2 accept cluster ENV ({$t['db']}:{$t['port']}) does not match the active "
                ."pgsql_tenant_auth connection ({$cfgDb}:{$cfgPort}). Declared BLOCKED."
            );
        }

        // REFUSE forbidden ports even when ENV points there.
        if (in_array($t['port'], self::G2_ACCEPT_FORBIDDEN_PORTS, true)) {
            $this->fail("G2 ACCEPT GUARD REFUSED: port {$t['port']} is on the permanent forbidden-port list.");
        }
        // REFUSE protected reference databases even when ENV points there.
        if (in_array($t['db'], self::G2_ACCEPT_PROTECTED_DATABASES, true)) {
            $this->fail("G2 ACCEPT GUARD REFUSED: database '{$t['db']}' is a permanently protected reference database.");
        }
        // REQUIRE the synthetic g2_ prefix — writes only ever hit g2_* DBs.
        if (! str_starts_with($t['db'], 'g2_')) {
            $this->fail("G2 ACCEPT GUARD REFUSED: database '{$t['db']}' lacks the required g2_ prefix.");
        }

        $dsn = "pgsql:host={$t['host']};port={$t['port']};dbname={$t['db']}";
        $pdo = new \PDO($dsn, $t['superuser'], (string) config('database.connections.pgsql.password'));
        $pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);

        // Live identity BEFORE any write: system_identifier must match the
        // expected value from ENV. Pinning the physical cluster regardless of
        // which host port routed us here.
        $liveId = (string) $pdo->query('SELECT system_identifier FROM pg_control_system()')->fetchColumn();
        if ($liveId !== (string) $expectedSysid) {
            $this->fail(
                "G2 ACCEPT GUARD REFUSED: live system_identifier '{$liveId}' does not match "
                ."G2_ACCEPT_CLUSTER_SYSID '{$expectedSysid}'."
            );
        }

        // Privilege check: the verification identity must truly bypass RLS.
        $priv = (string) $pdo->query(
            'SELECT (rolsuper OR rolbypassrls)::text FROM pg_roles WHERE rolname = current_user'
        )->fetchColumn();
        if ($priv !== 'true' && $priv !== 't') {
            $this->fail('G2 ACCEPT GUARD REFUSED: verification identity lacks superuser/BYPASSRLS.');
        }

        $this->g2Host = $t['host'];
        $this->g2Port = $t['port'];
        $this->g2Db   = $t['db'];

        return $pdo;
    }
}
