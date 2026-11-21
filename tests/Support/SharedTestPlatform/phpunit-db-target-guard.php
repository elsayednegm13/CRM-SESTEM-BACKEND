<?php

declare(strict_types=1);

/*
 * PHPUnit defaults to a non-existent driver. Database-capable tests must be
 * launched by the shared platform with a verified, run-scoped certificate.
 */
$connection = getenv('DB_CONNECTION');
if ($connection === false || $connection === '' || $connection === 'shared_test_guard') {
    return;
}

$certificatePath = getenv('DCRM_SHARED_TEST_TARGET_CERT');
if ($certificatePath === false || $certificatePath === '') {
    throw new RuntimeException('DCRM_SHARED_TEST_TARGET_CERT_REQUIRED');
}
if (!is_file($certificatePath)) {
    throw new RuntimeException('DCRM_SHARED_TEST_TARGET_CERT_PATH_INVALID');
}
$certificate = json_decode((string) file_get_contents($certificatePath), true, 512, JSON_THROW_ON_ERROR);
foreach (['format', 'task', 'kind', 'run_id', 'database', 'container_id', 'system_identifier', 'host', 'port', 'ledger_sha256', 'network', 'postgres_image', 'php_image', 'runtime_role', 'labels'] as $key) {
    if (!array_key_exists($key, $certificate)) {
        throw new RuntimeException('DCRM_SHARED_TEST_TARGET_CERT_FIELD_MISSING:'.$key);
    }
}
if ($certificate['format'] !== 'DCRM_SHARED_TEST_TARGET_CERTIFICATE_V1'
    || $certificate['task'] !== 'DCRM-V1-SHARED-TEST-PLATFORM-20261121'
    || !in_array($certificate['kind'], ['SHARED_TEST_CLONE', 'FUNCTIONAL_SLICE'], true)
    || !preg_match('/^shared-test-\d{8}-[a-z0-9-]+$/', (string) $certificate['run_id'])
    || !preg_match('/^dcrm_shared_test_[a-z0-9_]+$/', (string) $certificate['database'])
    || !preg_match('/^[a-f0-9]{64}$/', (string) $certificate['container_id'])
    || !preg_match('/^\d+$/', (string) $certificate['system_identifier'])
    || !preg_match('/^[a-f0-9]{64}$/', (string) $certificate['ledger_sha256'])
    || !preg_match('/^dcrm-shared-test-\d{8}-[a-z0-9-]+-net$/', (string) $certificate['network'])
    || !preg_match('/^postgres@sha256:[a-f0-9]{64}$/', (string) $certificate['postgres_image'])
    || !preg_match('/^daleel-core01-php-local@sha256:[a-f0-9]{64}$/', (string) $certificate['php_image'])
    || $certificate['runtime_role'] !== 'dcrm_shared_runtime'
    || $certificate['host'] !== 'pg' || (int) $certificate['port'] !== 5432
    || ($certificate['labels']['dcrm.task'] ?? null) !== $certificate['task']
    || ($certificate['labels']['dcrm.run_id'] ?? null) !== $certificate['run_id']
    || ($certificate['labels']['dcrm.kind'] ?? null) !== $certificate['kind']) {
    throw new RuntimeException('DCRM_SHARED_TEST_TARGET_CERT_INVALID');
}
if ($certificate['kind'] === 'FUNCTIONAL_SLICE'
    && (getenv('DCRM_SHARED_TEST_SERVICE_RUNNER') !== '1'
        || getenv('DCRM_SHARED_TEST_SUITE') !== 'customer_service_functional_v1'
        || getenv('DCRM_SHARED_TEST_RUN_ID') !== $certificate['run_id'])) {
    throw new RuntimeException('DCRM_SHARED_TEST_FUNCTIONAL_SLICE_SCOPE_REFUSED');
}
if (getenv('DB_HOST') !== 'pg' || (int) getenv('DB_PORT') !== 5432 || getenv('DB_DATABASE') !== $certificate['database']) {
    throw new RuntimeException('DCRM_SHARED_TEST_DATABASE_TARGET_MISMATCH');
}
