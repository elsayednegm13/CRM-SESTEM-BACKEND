<?php

// SECURITY-F06-LARAVEL-IMPLEMENT-01: isolated, default-OFF feature flag for the
// per-actor PostgreSQL LOGIN integration slice. Reused across environments only
// by explicit env configuration; absence of every F06_* env var leaves the
// feature fully inert (legacy TenantStaffRequestContext/TenantStaffContextGuard
// behavior, byte-for-byte, when F06_ACTOR_SQL_INTEGRATION_ENABLED is false/unset).

return [
    'enabled' => (bool) env('F06_ACTOR_SQL_INTEGRATION_ENABLED', false),

    // Guard rail: even if the flag above is accidentally set true, refuse to run
    // unless the app also explicitly declares itself a sandbox for this slice.
    // Prevents the flag from doing anything on a real/staging/production APP_ENV.
    'allow_env' => array_filter(array_map('trim', explode(',', (string) env('F06_ACTOR_SQL_ALLOWED_APP_ENV', 'testing')))),

    // Name of the sandbox's SECURITY DEFINER bootstrap-lookup function, schema-qualified.
    // Each isolated sandbox round creates its own uniquely-named function.
    'bootstrap_lookup_function' => env('F06_BOOTSTRAP_LOOKUP_FUNCTION', 'public.f06i01_bootstrap_lookup'),

    // Test-only synthetic credential provider. ActorSqlIdentityResolver reads
    // role->password pairs from here; these are never real tenant secrets and
    // are not used by any route unless the flag above is enabled.
    // SECURITY-F06-LARAVEL-IMPLEMENT-02: role names are sandbox-run-specific
    // (new unique roles each time a new isolated sandbox is built), so both the
    // IMPLEMENT-01 and IMPLEMENT-02 sandbox role names are listed; only the ones
    // whose env var is actually set resolve to a non-null password.
    'synthetic_actor_passwords' => [
        'daleel_f06i01_actor_a1' => env('F06_ACTOR_PW_A1'),
        'daleel_f06i01_actor_a2' => env('F06_ACTOR_PW_A2'),
        'daleel_f06i01_actor_b1' => env('F06_ACTOR_PW_B1'),
        'daleel_f06i02_actor_a1' => env('F06_ACTOR_PW_A1'),
        'daleel_f06i02_actor_a2' => env('F06_ACTOR_PW_A2'),
        'daleel_f06i02_actor_b1' => env('F06_ACTOR_PW_B1'),
        'daleel_f06i03_actor_a4' => env('F06_ACTOR_PW_A4'),
        'daleel_f06team01_actor_a5' => env('F06_ACTOR_PW_A5'),
    ],
];
