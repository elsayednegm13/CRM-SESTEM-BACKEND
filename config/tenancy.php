<?php

return [
    // Extend only with a reviewed product locale and matching frontend support.
    'supported_locales' => ['ar', 'en'],
    // Explicitly unset until an owner-selected domain is available. No fallback domain is used.
    'base_domain' => env('BASE_DOMAIN'),
    // Local .localhost hosts require both a local/testing APP_ENV and an exact configured base.
    'allow_localhost_base_domain' => filter_var(env('TENANCY_ALLOW_LOCALHOST_BASE_DOMAIN', false), FILTER_VALIDATE_BOOL),
    'local_test_base_domain' => env('TENANCY_LOCAL_TEST_BASE_DOMAIN'),
    // Explicit local/test disposable fixture path; never customer provisioning.
    'disposable_bootstrap_enabled' => env('TENANCY_DISPOSABLE_BOOTSTRAP', false),
];
