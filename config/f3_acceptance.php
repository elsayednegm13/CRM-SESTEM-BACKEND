<?php

return [
    'enabled' => (bool) env('DCRM_F3_ACCEPTANCE_ENABLED', false),
    'fixture_enabled' => (bool) env('DCRM_F3_FIXTURE_ENABLED', false),
    'run_id' => env('DCRM_F3_ACCEPTANCE_RUN_ID'),
    'expected_runtime_principal' => env('DCRM_F3_EXPECTED_RUNTIME_PRINCIPAL'),
    'expected_database' => env('DCRM_F3_EXPECTED_DATABASE'),
    'expected_system_identifier' => env('DCRM_F3_EXPECTED_SYSTEM_IDENTIFIER'),
    'expected_database_oid' => env('DCRM_F3_EXPECTED_DATABASE_OID'),
    'fixture_permit_id' => env('DCRM_F3_FIXTURE_PERMIT_ID'),
    'fixture_permit_path' => env('DCRM_F3_FIXTURE_PERMIT_PATH'),
    'allowed_environments' => ['local', 'testing'],
];
