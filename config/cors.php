<?php

$origins = array_values(array_filter(array_map(
    'trim',
    explode(',', (string) env('CORS_ALLOWED_ORIGINS', 'http://localhost:3000,http://localhost:3001,http://localhost:3002')),
)));
$origins = array_values(array_filter($origins, static function (string $origin): bool {
    $parts = parse_url($origin);

    return $origin !== '*'
        && is_array($parts)
        && in_array($parts['scheme'] ?? null, ['http', 'https'], true)
        && isset($parts['host'])
        && ! isset($parts['user'], $parts['pass'], $parts['query'], $parts['fragment'])
        && in_array($parts['path'] ?? '', ['', '/'], true);
}));

return [
    'paths' => ['api/*', 'sanctum/csrf-cookie'],
    'allowed_methods' => ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    'allowed_origins' => $origins,
    'allowed_origins_patterns' => [],
    'allowed_headers' => ['Accept', 'Authorization', 'Content-Type', 'Idempotency-Key', 'Origin', 'X-Request-ID', 'X-XSRF-TOKEN'],
    'exposed_headers' => ['X-Request-ID'],
    'max_age' => 600,
    'supports_credentials' => true,
];
