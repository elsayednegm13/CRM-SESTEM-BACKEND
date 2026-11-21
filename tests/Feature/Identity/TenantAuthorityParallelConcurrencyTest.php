<?php

namespace Tests\Feature\Identity;

use App\Modules\Identity\Application\TenantAuthoritySessionService;
use App\Modules\Identity\Domain\TenantStaffContext;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Str;
use Tests\TestCase;

/**
 * AL11 UPGRADE (G2-B) — TRUE parallel concurrency.
 *
 * The original TenantAuthorityConcurrencyTest proves the invariants with
 * SEQUENTIAL calls on one process ("simulated via sequential calls — advisory
 * lock serializes"). This suite replaces the simulation with genuine OS-level
 * parallelism: N independent PHP processes, each with its own dl_tauth PDO
 * connection, race the production serialization point
 * public.core01_tenant_authority_register_attempt(...) at a synchronized
 * barrier. The binding hashes are derived here via the real production service
 * and handed to every worker unchanged.
 *
 * What is actually being exercised concurrently (migration 063):
 *   - pg_advisory_xact_lock(hashtextextended(attempt_hash, 63005))
 *   - SELECT ... login_attempt_hash=? FOR UPDATE
 *   - partial UNIQUE index core01_tenant_authority_login_attempt_uq
 *
 * No production code, migration, trigger, RLS, or privilege is modified. Only
 * synthetic seed subjects are used. Superuser PDO is read/cleanup only, exactly
 * as the existing AL11 suite already does.
 */
class TenantAuthorityParallelConcurrencyTest extends TestCase
{
    use G2SandboxGuard;

    private const TENANT_A = 'a0000001-0001-4001-8001-000000000001';
    private const STAFF_A = 'b0000001-0001-4001-8001-000000000001';
    private const MEMBERSHIP_A = 'c0000001-0001-4001-8001-000000000001';
    private const HOST_A = 'al11-parallel-a.test';

    private TenantAuthoritySessionService $service;
    private \PDO $superPdo;
    private string $scratch;

    /** @var list<string> attempt hashes created during a test, for cleanup */
    private array $createdAttemptHashes = [];

    protected function setUp(): void
    {
        parent::setUp();

        // MANDATORY identity/scope guard before any write; returns the verified
        // superuser PDO (read/cleanup only). Sets $this->g2Host/g2Port/g2Db used
        // to build each worker process's dl_tauth DSN below.
        $this->superPdo = $this->g2GuardOrSkip();

        $this->service = new TenantAuthoritySessionService;

        $this->scratch = sys_get_temp_dir().DIRECTORY_SEPARATOR.'al11-parallel-'.getmypid();
        if (! is_dir($this->scratch)) {
            mkdir($this->scratch, 0700, true);
        }
    }

    protected function tearDown(): void
    {
        // Remove only the synthetic authorities this test created.
        foreach (array_unique($this->createdAttemptHashes) as $hash) {
            $this->superPdo->prepare(
                'DELETE FROM core01_tenant_authority_sessions WHERE login_attempt_hash = ?'
            )->execute([$hash]);
        }
        $this->createdAttemptHashes = [];

        foreach (glob($this->scratch.DIRECTORY_SEPARATOR.'*') ?: [] as $f) {
            @unlink($f);
        }
        @rmdir($this->scratch);

        parent::tearDown();
    }

    // ── helpers ─────────────────────────────────────────────────────────

    /** Derive production-faithful binding via the real service. */
    private function bindingFor(string $retryKey, string $clientSeed): array
    {
        $session = new Store('al11p', new ArraySessionHandler(120));
        $session->start();
        $request = Request::create('/test', 'POST');
        $request->setLaravelSession($session);
        $request->attributes->set(
            'tenant_login_client_hash',
            hash_hmac('sha256', $clientSeed, 'al11-secret')
        );

        return $this->service->attemptBinding($request, $retryKey, self::HOST_A);
    }

    /**
     * Write the shared worker config and spawn one real process per variant,
     * all released together at a synchronized start epoch.
     *
     * @param  list<string>  $variants  each 'same' or 'diff'
     * @return list<array<string,mixed>>  decoded worker results
     */
    private function raceWorkers(array $variants, array $binding, string $altClientHash): array
    {
        $config = [
            'dsn' => 'pgsql:host='.$this->g2Host.';port='.$this->g2Port.';dbname='.$this->g2Db,
            'user' => config('database.connections.pgsql_tenant_auth.username'),
            'password' => config('database.connections.pgsql_tenant_auth.password'),
            'tenant' => self::TENANT_A,
            'staff' => self::STAFF_A,
            'membership' => self::MEMBERSHIP_A,
            'auth_version' => 1,
            'authorization_version' => 1,
            'attempt_hash' => $binding['attempt_hash'],
            'client_hash' => $binding['client_hash'],
            'host_hash' => $binding['host_hash'],
            'alt_client_hash' => $altClientHash,
            'expires_at' => now('UTC')->addSeconds(28800)->toIso8601String(),
            // Generous barrier so every process reaches the gate before release.
            'start_epoch' => microtime(true) + 1.0 + 0.15 * count($variants),
        ];
        $configPath = $this->scratch.DIRECTORY_SEPARATOR.'cfg-'.Str::uuid().'.json';
        file_put_contents($configPath, json_encode($config));

        $worker = __DIR__.DIRECTORY_SEPARATOR.'parallel_authority_worker.php';
        $spec = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];

        $procs = [];
        foreach ($variants as $i => $variant) {
            $pipes = [];
            $cmd = [PHP_BINARY, $worker, $configPath, $variant];
            $proc = proc_open($cmd, $spec, $pipes);
            self::assertIsResource($proc, "worker {$i} failed to spawn");
            $procs[$i] = ['proc' => $proc, 'pipes' => $pipes];
        }

        $results = [];
        foreach ($procs as $i => $p) {
            $out = stream_get_contents($p['pipes'][1]);
            $err = stream_get_contents($p['pipes'][2]);
            fclose($p['pipes'][1]);
            fclose($p['pipes'][2]);
            proc_close($p['proc']);

            $decoded = json_decode(trim((string) $out), true);
            self::assertIsArray($decoded, "worker {$i} produced no JSON (stderr: {$err}, stdout: {$out})");
            $results[] = $decoded;
        }

        $this->createdAttemptHashes[] = $binding['attempt_hash'];

        return $results;
    }

    private function countRows(string $attemptHash): int
    {
        $stmt = $this->superPdo->prepare(
            'SELECT count(*) FROM core01_tenant_authority_sessions WHERE login_attempt_hash = ?'
        );
        $stmt->execute([$attemptHash]);

        return (int) $stmt->fetchColumn();
    }

    private function storedClientHash(string $attemptHash): ?string
    {
        $stmt = $this->superPdo->prepare(
            'SELECT login_attempt_client_hash FROM core01_tenant_authority_sessions WHERE login_attempt_hash = ?'
        );
        $stmt->execute([$attemptHash]);
        $v = $stmt->fetchColumn();

        return $v === false ? null : trim((string) $v);
    }

    // ── P1: convergence — N parallel workers, one attempt, one authority ──

    public function test_parallel_same_attempt_yields_single_authority(): void
    {
        $retryKey = (string) Str::uuid();
        $binding = $this->bindingFor($retryKey, 'test-client-'.$retryKey);
        $alt = hash_hmac('sha256', 'attacker-'.$retryKey, 'al11-secret');

        $results = $this->raceWorkers(array_fill(0, 12, 'same'), $binding, $alt);

        $created = array_filter($results, fn ($r) => ($r['disposition'] ?? null) === 'CREATED');
        $rebound = array_filter($results, fn ($r) => ($r['disposition'] ?? null) === 'REBOUND');
        $errors = array_filter($results, fn ($r) => ($r['ok'] ?? false) !== true);

        self::assertCount(0, $errors, 'No same-proof worker may error: '.json_encode($errors));
        self::assertCount(1, $created, 'Exactly one worker may CREATE the authority');
        self::assertCount(11, $rebound, 'All other same-proof workers must REBOUND the same authority');

        // One physical authority, and every REBOUND points at that same id.
        self::assertSame(1, $this->countRows($binding['attempt_hash']), 'Exactly one authority row for the attempt');
        $ids = array_unique(array_map(fn ($r) => $r['authority_id'], $results));
        self::assertCount(1, $ids, 'CREATE and all REBOUNDs must resolve to one authority id');
    }

    // ── P2: isolation — mixed proofs race one attempt_hash ──────────────
    //
    // The attempt_hash binding is first-writer-wins with proof isolation: the
    // retry/idempotency key alone derives the attempt_hash, so a simultaneous
    // race between two proofs on the SAME key binds the authority to WHOEVER
    // commits first — the function does not privilege either proof. The
    // security guarantee is therefore outcome-agnostic and deterministic:
    //   (a) exactly one authority row exists,
    //   (b) it is bound to exactly one proof (the winner's),
    //   (c) every worker whose proof equals the winner's REBOUNDs it,
    //   (d) every worker whose proof differs is hard-rejected with PZ409 —
    //       it can neither create a second authority nor rebind the first.
    // This holds no matter which worker wins the advisory-lock dead heat.

    public function test_parallel_mixed_proof_conflict_is_isolated(): void
    {
        $retryKey = (string) Str::uuid();
        $binding = $this->bindingFor($retryKey, 'test-client-'.$retryKey);
        $alt = hash_hmac('sha256', 'attacker-'.$retryKey, 'al11-secret');
        $proofFor = fn (array $r) => ($r['variant'] ?? null) === 'diff' ? $alt : $binding['client_hash'];

        $variants = array_merge(array_fill(0, 8, 'same'), array_fill(0, 4, 'diff'));
        shuffle($variants);
        $results = $this->raceWorkers($variants, $binding, $alt);

        // (a) + (b): exactly one authority, bound to exactly one proof.
        $created = array_values(array_filter($results, fn ($r) => ($r['disposition'] ?? null) === 'CREATED'));
        self::assertCount(1, $created, 'Exactly one authority is created under the race');
        self::assertSame(1, $this->countRows($binding['attempt_hash']), 'One authority row only');

        $winnerProof = $proofFor($created[0]);
        self::assertSame(
            $winnerProof,
            $this->storedClientHash($binding['attempt_hash']),
            'The stored proof is exactly the winning worker\'s proof'
        );

        // (c) + (d): every non-winner is classified strictly by proof match.
        $sawForeignRejected = false;
        foreach ($results as $r) {
            if (($r['disposition'] ?? null) === 'CREATED') {
                continue;
            }
            if ($proofFor($r) === $winnerProof) {
                self::assertSame('REBOUND', $r['disposition'] ?? null,
                    'A worker sharing the winning proof must REBOUND, never conflict: '.json_encode($r));
            } else {
                self::assertSame('PZ409', $r['sqlstate'] ?? null,
                    'A worker with a foreign proof must be hard-rejected (PZ409), never bind: '.json_encode($r));
                self::assertArrayNotHasKey('disposition', $r,
                    'A foreign-proof worker must not receive any disposition');
                $sawForeignRejected = true;
            }
        }
        self::assertTrue($sawForeignRejected, 'The mixed race must actually exercise the foreign-proof rejection path');
    }

    // ── P3: independence — distinct attempts fire together, no leakage ───

    public function test_parallel_distinct_attempts_all_created(): void
    {
        $n = 10;
        $bindings = [];
        $procs = [];
        $spec = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $worker = __DIR__.DIRECTORY_SEPARATOR.'parallel_authority_worker.php';
        $startEpoch = microtime(true) + 1.0 + 0.15 * $n;

        for ($i = 0; $i < $n; $i++) {
            $retryKey = (string) Str::uuid();
            $binding = $this->bindingFor($retryKey, 'test-client-'.$retryKey);
            $bindings[$i] = $binding;
            $this->createdAttemptHashes[] = $binding['attempt_hash'];

            $config = [
                'dsn' => 'pgsql:host='.$this->g2Host.';port='.$this->g2Port.';dbname='.$this->g2Db,
                'user' => config('database.connections.pgsql_tenant_auth.username'),
                'password' => config('database.connections.pgsql_tenant_auth.password'),
                'tenant' => self::TENANT_A, 'staff' => self::STAFF_A, 'membership' => self::MEMBERSHIP_A,
                'auth_version' => 1, 'authorization_version' => 1,
                'attempt_hash' => $binding['attempt_hash'],
                'client_hash' => $binding['client_hash'],
                'host_hash' => $binding['host_hash'],
                'alt_client_hash' => $binding['client_hash'],
                'expires_at' => now('UTC')->addSeconds(28800)->toIso8601String(),
                'start_epoch' => $startEpoch,
            ];
            $configPath = $this->scratch.DIRECTORY_SEPARATOR.'cfg-dist-'.$i.'.json';
            file_put_contents($configPath, json_encode($config));

            $pipes = [];
            $proc = proc_open([PHP_BINARY, $worker, $configPath, 'same'], $spec, $pipes);
            self::assertIsResource($proc, "distinct worker {$i} failed to spawn");
            $procs[$i] = ['proc' => $proc, 'pipes' => $pipes];
        }

        $results = [];
        foreach ($procs as $p) {
            $out = stream_get_contents($p['pipes'][1]);
            fclose($p['pipes'][1]);
            fclose($p['pipes'][2]);
            proc_close($p['proc']);
            $results[] = json_decode(trim((string) $out), true);
        }

        $created = array_filter($results, fn ($r) => is_array($r) && ($r['disposition'] ?? null) === 'CREATED');
        self::assertCount($n, $created, 'Every distinct attempt must create its own authority under parallelism');

        // Each distinct attempt produced exactly one row, each a distinct id.
        foreach ($bindings as $binding) {
            self::assertSame(1, $this->countRows($binding['attempt_hash']), 'Each distinct attempt → exactly one row');
        }
        $ids = array_unique(array_map(fn ($r) => $r['authority_id'], $results));
        self::assertCount($n, $ids, 'No id collision across distinct parallel attempts');
    }
}
