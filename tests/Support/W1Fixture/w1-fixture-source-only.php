<?php

declare(strict_types=1);

use Tests\Support\W1Fixture\W1FixturePrerequisiteManifest;

require_once __DIR__.'/W1FixturePrerequisiteManifest.php';

if (($argv[1] ?? null) !== '--manifest' || isset($argv[2])) {
    fwrite(STDERR, "Usage: php w1-fixture-source-only.php --manifest\n");
    exit(64);
}

// Deliberately no framework bootstrap, environment read, connection, or seed.
echo json_encode(
    W1FixturePrerequisiteManifest::definition(),
    JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR,
)."\n";
