<?php

/**
 * AL11 upgrade — true-parallel concurrency worker (G2-B).
 *
 * Standalone PDO process (NO Laravel bootstrap). Each instance is one real OS
 * worker that races the production SQL serialization point
 * public.core01_tenant_authority_register_attempt(...) at a synchronized start.
 *
 * All binding hashes (attempt/client/host) are derived by the PARENT PHPUnit
 * test via the real TenantAuthoritySessionService, then handed to every worker
 * unchanged — so this process exercises the production function with
 * production-faithful inputs, under genuine concurrency (pg_advisory_xact_lock
 * + FOR UPDATE + partial UNIQUE index). It never recomputes a hash and never
 * touches production code.
 *
 * Filename deliberately does NOT end in *Test.php so PHPUnit never collects it.
 *
 * Usage: php parallel_authority_worker.php <config.json> <same|diff>
 * Emits exactly one JSON line on stdout.
 */

if ($argc < 3) {
    fwrite(STDOUT, json_encode(['ok' => false, 'error' => 'usage']) . "\n");
    exit(2);
}

$cfg = json_decode((string) file_get_contents($argv[1]), true);
$variant = $argv[2] === 'diff' ? 'diff' : 'same';

if (! is_array($cfg)) {
    fwrite(STDOUT, json_encode(['ok' => false, 'error' => 'bad-config']) . "\n");
    exit(2);
}

$clientHash = $variant === 'diff' ? $cfg['alt_client_hash'] : $cfg['client_hash'];

// Per-worker server-side identity. session_hash validity is not part of the
// REBOUND match contract (only proof + subject + key_generation are), so a
// fresh random 64-hex token is faithful and needs no shared binding secret.
$sessionHash = bin2hex(random_bytes(32));
$generation = sprintf(
    '%08x-%04x-4%03x-%04x-%012x',
    random_int(0, 0xffffffff), random_int(0, 0xffff), random_int(0, 0xfff),
    random_int(0x8000, 0xbfff), random_int(0, 0xffffffffffff)
);

try {
    $pdo = new PDO($cfg['dsn'], $cfg['user'], $cfg['password'], [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_TIMEOUT => 10,
    ]);
    // Prepare the exact production call signature up front, outside the race.
    $stmt = $pdo->prepare(
        'SELECT * FROM public.core01_tenant_authority_register_attempt('
        . '?::uuid, ?::uuid, ?::uuid, ?::bigint, ?::bigint, ?, ?::uuid, ?::timestamptz, ?, ?, ?)'
    );
    $params = [
        $cfg['tenant'], $cfg['staff'], $cfg['membership'],
        $cfg['auth_version'], $cfg['authorization_version'],
        $sessionHash, $generation, $cfg['expires_at'],
        $cfg['attempt_hash'], $clientHash, $cfg['host_hash'],
    ];
} catch (Throwable $e) {
    fwrite(STDOUT, json_encode(['ok' => false, 'phase' => 'connect', 'variant' => $variant, 'error' => $e->getMessage()]) . "\n");
    exit(1);
}

// Barrier: busy-wait until the shared start epoch to maximize real overlap.
$start = (float) $cfg['start_epoch'];
while (microtime(true) < $start) {
    $remaining = $start - microtime(true);
    if ($remaining > 0.002) {
        usleep((int) (($remaining - 0.001) * 1_000_000));
    }
}

$fired = microtime(true);
try {
    $stmt->execute($params);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    fwrite(STDOUT, json_encode([
        'ok' => true,
        'variant' => $variant,
        'disposition' => $row['disposition'] ?? null,
        'authority_id' => $row['authority_id'] ?? null,
        'fired_at' => $fired,
    ]) . "\n");
    exit(0);
} catch (PDOException $e) {
    // SQLSTATE is the first element of errorInfo; carry it, drop any detail text.
    $sqlstate = $e->errorInfo[0] ?? $e->getCode();
    fwrite(STDOUT, json_encode([
        'ok' => false,
        'variant' => $variant,
        'sqlstate' => $sqlstate,
        'fired_at' => $fired,
    ]) . "\n");
    exit(0);
}
