<?php

// Source-only check of the synthetic credential map. No Laravel boot or DB call.
function env(string $key, mixed $default = null): mixed
{
    $value = getenv($key);
    return $value === false ? $default : $value;
}

putenv('F06_ACTOR_PW_A1=synthetic-a1-check-only');
$settings = require dirname(__DIR__, 3).'/config/f06_actor_sql.php';
function config(string $key): mixed
{
    global $settings;
    return match ($key) {
        'f06_actor_sql.enabled' => true,
        'f06_actor_sql.synthetic_actor_passwords.daleel_f06team01_actor_a5' => $settings['synthetic_actor_passwords']['daleel_f06team01_actor_a5'],
        'f06_actor_sql.synthetic_actor_passwords.daleel_f06i02_actor_a1' => $settings['synthetic_actor_passwords']['daleel_f06i02_actor_a1'],
        default => null,
    };
}
require dirname(__DIR__, 3).'/app/Modules/Identity/Application/ActorSqlIdentityResolver.php';
$resolver = new App\Modules\Identity\Application\ActorSqlIdentityResolver;
$map = $settings['synthetic_actor_passwords'];
if (count($map) !== count(array_unique(array_keys($map)))) {
    throw new RuntimeException('duplicate actor mapping');
}
if (($map['daleel_f06team01_actor_a5'] ?? null) !== null
    || array_key_exists('unknown_actor', $map)
    || ! array_key_exists('daleel_f06i02_actor_a1', $map)
    || $resolver->passwordFor('daleel_f06team01_actor_a5') !== null
    || $resolver->passwordFor('daleel_f06i02_actor_a1') !== 'synthetic-a1-check-only'
    || $resolver->passwordFor('unknown_actor') !== null) {
    throw new RuntimeException('missing/unknown/A1 mapping failed');
}
putenv('F06_ACTOR_PW_A5=synthetic-check-only');
$withA5 = require dirname(__DIR__, 3).'/config/f06_actor_sql.php';
$settings = $withA5;
if (($withA5['synthetic_actor_passwords']['daleel_f06team01_actor_a5'] ?? null) !== 'synthetic-check-only') {
    throw new RuntimeException('A5 environment mapping failed');
}
if ($resolver->passwordFor('daleel_f06team01_actor_a5') !== 'synthetic-check-only') {
    throw new RuntimeException('A5 resolver mapping failed');
}
putenv('F06_ACTOR_PW_A5');
putenv('F06_ACTOR_PW_A1');
echo "CONFIG_PREFLIGHT=PASS missing_A5=null unknown=null A1_key=present A5_env=isolated\n";
