<?php

return [
    // Deployment supplies both roles and the trusted login's secret out of band.
    // Their names are explicit so an accidental production migrate fails closed.
    'trusted_tenant_login' => env('CORE_SQL_TRUSTED_TENANT_LOGIN'),
    'legacy_tenant_login' => env('CORE_SQL_LEGACY_TENANT_LOGIN'),
    'signing_key' => env('CORE01_SQL_SIGNING_KEY'),
    'signing_key_generation' => (int) env('CORE01_SQL_SIGNING_KEY_GENERATION', 1),
    'provider_proof_key' => env('CORE01_PROVIDER_PROOF_KEY'),
    // Distinct 32-byte secret for opaque server-session bindings. It is never
    // accepted from clients or stored in PostgreSQL authority tables.
    'session_binding_key' => env('CORE01_SESSION_BINDING_KEY'),
    'provider_authority_enabled' => env('CORE01_PROVIDER_AUTHORITY_ENABLED', false),
    // Gates the signed actor-bound first-admin activation path. Default closed:
    // the HTTP route fails closed (503) until an environment opts in, and the
    // old core01_activate_first_admin gate (migration 048 + 503) stays shut.
    'activation_authority_enabled' => env('CORE01_ACTIVATION_AUTHORITY_ENABLED', false),
];
