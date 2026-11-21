<?php

return [
    // HTTP runtimes must select an identity explicitly. Migration commands run
    // separately and never expose an HTTP listener.
    'mode' => env('CORE_RUNTIME_MODE'),
    'owner_login' => env('CORE_SQL_OWNER_LOGIN'),
    'base_host' => env('CORE_RUNTIME_BASE_HOST'),
    'legacy_host' => env('CORE_RUNTIME_LEGACY_HOST'),
];
