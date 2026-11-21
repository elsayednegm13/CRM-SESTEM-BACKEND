<?php

$apiHosts = array_values(array_filter(array_map(
    static fn (string $host): string => strtolower(trim($host)),
    explode(',', (string) env('PROVIDER_API_HOSTS', '')),
)));

return [
    'api_hosts' => $apiHosts,
    'allowed_origins' => array_values(array_filter(array_map('trim', explode(',', (string) env(
        'PROVIDER_ALLOWED_ORIGINS', env('APP_ENV', 'production') === 'local' ? 'http://localhost:3002' : '',
    ))))),
    'bootstrap' => [
        'enabled' => env('PROVIDER_BOOTSTRAP_ENABLED', false),
        'secret' => env('PROVIDER_BOOTSTRAP_SECRET', ''),
        'expires_at' => env('PROVIDER_BOOTSTRAP_EXPIRES_AT', ''),
        'allow_loopback_http' => env('PROVIDER_BOOTSTRAP_ALLOW_LOOPBACK_HTTP', false),
    ],
    'pending_seconds' => 300,
    'absolute_session_seconds' => 14400,
    'step_up_seconds' => 600,
    'totp_period_seconds' => 30,
    'totp_skew_steps' => 1,
    'max_mfa_attempts' => 5,
    'approval_lifetime_seconds' => 900,
    'approval_required' => [
        'company.provision' => 1,
        'company.recover' => 1,
        'company.lifecycle.manage' => 1,
    ],
];
