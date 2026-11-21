<?php

return [
    'dummy_password_hash' => '$argon2id$v=19$m=65536,t=4,p=1$MGFOUXl3QUFZRTZTc2swTQ$tLXj+OqIO2BXZ1bit7zDQEg6dxZXYQFiy2vdsy0jieI',
    'reset_url' => env('AUTH_PASSWORD_RESET_URL', 'http://localhost:3000/reset-password'),
    'absolute_session_lifetime' => (int) env('AUTH_ABSOLUTE_SESSION_LIFETIME', 28800),
    'tenant_auth_client_enabled' => filter_var(env('TENANT_STAFF_AUTH_ENABLED', false), FILTER_VALIDATE_BOOL),
    'login' => [
        'max_failures' => (int) env('AUTH_LOGIN_MAX_FAILURES', 5),
        'decay_seconds' => (int) env('AUTH_LOGIN_DECAY_SECONDS', 900),
        'ip_max_failures' => (int) env('AUTH_LOGIN_IP_MAX_FAILURES', 100),
    ],
    'forgot' => [
        'max_attempts' => (int) env('AUTH_FORGOT_MAX_ATTEMPTS', 3),
        'decay_seconds' => (int) env('AUTH_FORGOT_DECAY_SECONDS', 3600),
        'ip_max_attempts' => (int) env('AUTH_FORGOT_IP_MAX_ATTEMPTS', 30),
    ],
    'reset' => [
        'max_attempts' => (int) env('AUTH_RESET_MAX_ATTEMPTS', 5),
        'decay_seconds' => (int) env('AUTH_RESET_DECAY_SECONDS', 900),
    ],
    'verification' => [
        'max_resends' => (int) env('AUTH_VERIFICATION_MAX_RESENDS', 3),
        'decay_seconds' => (int) env('AUTH_VERIFICATION_DECAY_SECONDS', 3600),
        'expire_minutes' => (int) env('AUTH_VERIFICATION_EXPIRE_MINUTES', 60),
    ],
];
