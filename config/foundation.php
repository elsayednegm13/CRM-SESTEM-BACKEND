<?php

return [
    'dependency_checks_enabled' => (bool) env('FOUNDATION_DEPENDENCY_CHECKS', false),
    'redis_dependency_configured' => (bool) env('FOUNDATION_REDIS_CONFIGURED', false),
];
