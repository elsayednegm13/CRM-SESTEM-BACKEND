<?php

use Illuminate\Support\Str;
use Pdo\Mysql;

return [

    /*
    |--------------------------------------------------------------------------
    | Default Database Connection Name
    |--------------------------------------------------------------------------
    |
    | Here you may specify which of the database connections below you wish
    | to use as your default connection for database operations. This is
    | the connection which will be utilized unless another connection
    | is explicitly specified when you execute a query / statement.
    |
    */

    'default' => env('DB_CONNECTION', 'pgsql'),

    /*
    |--------------------------------------------------------------------------
    | Database Connections
    |--------------------------------------------------------------------------
    |
    | Below are all of the database connections defined for your application.
    | An example configuration is provided for each database system which
    | is supported by Laravel. You're free to add / remove connections.
    |
    */

    'connections' => [

        'sqlite' => [
            'driver' => 'sqlite',
            'url' => env('DB_URL'),
            'database' => env('DB_DATABASE', database_path('database.sqlite')),
            'prefix' => '',
            'foreign_key_constraints' => env('DB_FOREIGN_KEYS', true),
            'busy_timeout' => null,
            'journal_mode' => null,
            'synchronous' => null,
            'transaction_mode' => 'DEFERRED',
        ],

        'mysql' => [
            'driver' => 'mysql',
            'url' => env('DB_URL'),
            'host' => env('DB_HOST', '127.0.0.1'),
            'port' => env('DB_PORT', '3306'),
            'database' => env('DB_DATABASE', 'laravel'),
            'username' => env('DB_USERNAME', 'root'),
            'password' => env('DB_PASSWORD', ''),
            'unix_socket' => env('DB_SOCKET', ''),
            'charset' => env('DB_CHARSET', 'utf8mb4'),
            'collation' => env('DB_COLLATION', 'utf8mb4_unicode_ci'),
            'prefix' => '',
            'prefix_indexes' => true,
            'strict' => true,
            'engine' => null,
            'options' => extension_loaded('pdo_mysql') ? array_filter([
                Mysql::ATTR_SSL_CA => env('MYSQL_ATTR_SSL_CA'),
            ]) : [],
        ],

        'mariadb' => [
            'driver' => 'mariadb',
            'url' => env('DB_URL'),
            'host' => env('DB_HOST', '127.0.0.1'),
            'port' => env('DB_PORT', '3306'),
            'database' => env('DB_DATABASE', 'laravel'),
            'username' => env('DB_USERNAME', 'root'),
            'password' => env('DB_PASSWORD', ''),
            'unix_socket' => env('DB_SOCKET', ''),
            'charset' => env('DB_CHARSET', 'utf8mb4'),
            'collation' => env('DB_COLLATION', 'utf8mb4_unicode_ci'),
            'prefix' => '',
            'prefix_indexes' => true,
            'strict' => true,
            'engine' => null,
            'options' => extension_loaded('pdo_mysql') ? array_filter([
                Mysql::ATTR_SSL_CA => env('MYSQL_ATTR_SSL_CA'),
            ]) : [],
        ],

        'pgsql' => [
            'driver' => 'pgsql',
            'url' => env('DB_URL'),
            'host' => env('DB_HOST', '127.0.0.1'),
            'port' => env('DB_PORT', '5432'),
            'database' => env('DB_DATABASE', 'laravel'),
            'username' => env('DB_USERNAME', 'root'),
            'password' => env('DB_PASSWORD', ''),
            'charset' => env('DB_CHARSET', 'utf8'),
            'prefix' => '',
            'prefix_indexes' => true,
            'search_path' => 'public',
            'sslmode' => env('DB_SSLMODE', 'prefer'),
        ],

        // Same PostgreSQL cluster, independent least-privilege control-plane credential.
        'pgsql_provider' => [
            'driver' => 'pgsql',
            'host' => env('PROVIDER_DB_HOST', env('DB_HOST', '127.0.0.1')),
            'port' => env('PROVIDER_DB_PORT', env('DB_PORT', '5432')),
            'database' => env('PROVIDER_DB_DATABASE', env('DB_DATABASE', 'laravel')),
            'username' => env('PROVIDER_DB_USERNAME'),
            'password' => env('PROVIDER_DB_PASSWORD'),
            'charset' => 'utf8',
            'prefix' => '',
            'prefix_indexes' => true,
            'search_path' => 'public',
            'sslmode' => env('PROVIDER_DB_SSLMODE', env('DB_SSLMODE', 'prefer')),
        ],

        // Operational control plane and one-column-scoped founder onboarding.
        // These credentials are intentionally distinct from provider auth.
        'pgsql_provider_control' => [
            'driver' => 'pgsql',
            'host' => env('PROVIDER_CONTROL_DB_HOST', env('DB_HOST', '127.0.0.1')),
            'port' => env('PROVIDER_CONTROL_DB_PORT', env('DB_PORT', '5432')),
            'database' => env('PROVIDER_CONTROL_DB_DATABASE', env('DB_DATABASE', 'laravel')),
            'username' => env('PROVIDER_CONTROL_DB_USERNAME'),
            'password' => env('PROVIDER_CONTROL_DB_PASSWORD'),
            'charset' => 'utf8', 'prefix' => '', 'prefix_indexes' => true,
            'search_path' => 'public',
            'sslmode' => env('PROVIDER_CONTROL_DB_SSLMODE', env('DB_SSLMODE', 'prefer')),
        ],
        // Authority issuer: distinct credential, never available to the control consumer.
        'pgsql_provider_issuer' => [
            'driver' => 'pgsql',
            'host' => env('PROVIDER_ISSUER_DB_HOST', env('DB_HOST', '127.0.0.1')),
            'port' => env('PROVIDER_ISSUER_DB_PORT', env('DB_PORT', '5432')),
            'database' => env('PROVIDER_ISSUER_DB_DATABASE', env('DB_DATABASE', 'laravel')),
            'username' => env('PROVIDER_ISSUER_DB_USERNAME'),
            'password' => env('PROVIDER_ISSUER_DB_PASSWORD'),
            'charset' => 'utf8', 'prefix' => '', 'prefix_indexes' => true,
            'search_path' => 'public',
            'sslmode' => env('PROVIDER_ISSUER_DB_SSLMODE', env('DB_SSLMODE', 'prefer')),
        ],
        'pgsql_onboarding' => [
            'driver' => 'pgsql',
            'host' => env('ONBOARDING_DB_HOST', env('DB_HOST', '127.0.0.1')),
            'port' => env('ONBOARDING_DB_PORT', env('DB_PORT', '5432')),
            'database' => env('ONBOARDING_DB_DATABASE', env('DB_DATABASE', 'laravel')),
            'username' => env('ONBOARDING_DB_USERNAME'),
            'password' => env('ONBOARDING_DB_PASSWORD'),
            'charset' => 'utf8', 'prefix' => '', 'prefix_indexes' => true,
            'search_path' => 'public',
            'sslmode' => env('ONBOARDING_DB_SSLMODE', env('DB_SSLMODE', 'prefer')),
        ],

        // Host lookup, pre-authentication and authenticated staff SQL use distinct
        // database principals. Production credentials are provisioned separately.
        'pgsql_hostname_resolver' => [
            'driver' => 'pgsql',
            'host' => env('TENANT_HOST_DB_HOST'),
            'port' => env('TENANT_HOST_DB_PORT', '5432'),
            'database' => env('TENANT_HOST_DB_DATABASE'),
            'username' => env('TENANT_HOST_DB_USERNAME'),
            'password' => env('TENANT_HOST_DB_PASSWORD'),
            'charset' => 'utf8', 'prefix' => '', 'prefix_indexes' => true,
            'search_path' => 'public',
            'sslmode' => env('TENANT_HOST_DB_SSLMODE', env('DB_SSLMODE', 'prefer')),
        ],
        'pgsql_tenant_auth' => [
            'driver' => 'pgsql',
            'host' => env('TENANT_AUTH_DB_HOST'),
            'port' => env('TENANT_AUTH_DB_PORT', '5432'),
            'database' => env('TENANT_AUTH_DB_DATABASE'),
            'username' => env('TENANT_AUTH_DB_USERNAME'),
            'password' => env('TENANT_AUTH_DB_PASSWORD'),
            'charset' => 'utf8', 'prefix' => '', 'prefix_indexes' => true,
            'search_path' => 'public',
            'sslmode' => env('TENANT_AUTH_DB_SSLMODE', env('DB_SSLMODE', 'prefer')),
        ],
        'pgsql_tenant_runtime' => [
            'driver' => 'pgsql',
            'host' => env('TENANT_RUNTIME_DB_HOST'),
            'port' => env('TENANT_RUNTIME_DB_PORT', '5432'),
            'database' => env('TENANT_RUNTIME_DB_DATABASE'),
            'username' => env('TENANT_RUNTIME_DB_USERNAME'),
            'password' => env('TENANT_RUNTIME_DB_PASSWORD'),
            'charset' => 'utf8', 'prefix' => '', 'prefix_indexes' => true,
            'search_path' => 'public',
            'sslmode' => env('TENANT_RUNTIME_DB_SSLMODE', env('DB_SSLMODE', 'prefer')),
        ],

        // SECURITY-F06-LARAVEL-IMPLEMENT-01: read-only bootstrap-identity lookup connection,
        // deliberately separate from pgsql_tenant_runtime. Used only by
        // TrustedActorBootstrapVerifier, and only when F06_ACTOR_SQL_INTEGRATION_ENABLED=true.
        // Unset host/credentials by default -> fails closed outside an explicitly configured
        // sandbox/test environment. Never points at a protected or product database.
        'pgsql_f06_bootstrap' => [
            'driver' => 'pgsql',
            'host' => env('F06_BOOTSTRAP_DB_HOST'),
            'port' => env('F06_BOOTSTRAP_DB_PORT', '5432'),
            'database' => env('F06_BOOTSTRAP_DB_DATABASE'),
            'username' => env('F06_BOOTSTRAP_DB_USERNAME'),
            'password' => env('F06_BOOTSTRAP_DB_PASSWORD'),
            'charset' => 'utf8', 'prefix' => '', 'prefix_indexes' => true,
            'search_path' => 'public',
            'sslmode' => env('F06_BOOTSTRAP_DB_SSLMODE', 'disable'),
        ],

        'sqlsrv' => [
            'driver' => 'sqlsrv',
            'url' => env('DB_URL'),
            'host' => env('DB_HOST', 'localhost'),
            'port' => env('DB_PORT', '1433'),
            'database' => env('DB_DATABASE', 'laravel'),
            'username' => env('DB_USERNAME', 'root'),
            'password' => env('DB_PASSWORD', ''),
            'charset' => env('DB_CHARSET', 'utf8'),
            'prefix' => '',
            'prefix_indexes' => true,
            // 'encrypt' => env('DB_ENCRYPT', 'yes'),
            // 'trust_server_certificate' => env('DB_TRUST_SERVER_CERTIFICATE', 'false'),
        ],

    ],

    /*
    |--------------------------------------------------------------------------
    | Migration Repository Table
    |--------------------------------------------------------------------------
    |
    | This table keeps track of all the migrations that have already run for
    | your application. Using this information, we can determine which of
    | the migrations on disk haven't actually been run on the database.
    |
    */

    'migrations' => [
        'table' => 'migrations',
        'update_date_on_publish' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | Redis Databases
    |--------------------------------------------------------------------------
    |
    | Redis is an open source, fast, and advanced key-value store that also
    | provides a richer body of commands than a typical key-value system
    | such as Memcached. You may define your connection settings here.
    |
    */

    'redis' => [

        'client' => env('REDIS_CLIENT', 'phpredis'),

        'options' => [
            'cluster' => env('REDIS_CLUSTER', 'redis'),
            'prefix' => env('REDIS_PREFIX', Str::slug((string) env('APP_NAME', 'laravel')).'-database-'),
            'persistent' => env('REDIS_PERSISTENT', false),
        ],

        'default' => [
            'url' => env('REDIS_URL'),
            'host' => env('REDIS_HOST', '127.0.0.1'),
            'username' => env('REDIS_USERNAME'),
            'password' => env('REDIS_PASSWORD'),
            'port' => env('REDIS_PORT', '6379'),
            'database' => env('REDIS_DB', '0'),
            'max_retries' => env('REDIS_MAX_RETRIES', 3),
            'backoff_algorithm' => env('REDIS_BACKOFF_ALGORITHM', 'decorrelated_jitter'),
            'backoff_base' => env('REDIS_BACKOFF_BASE', 100),
            'backoff_cap' => env('REDIS_BACKOFF_CAP', 1000),
        ],

        'cache' => [
            'url' => env('REDIS_URL'),
            'host' => env('REDIS_HOST', '127.0.0.1'),
            'username' => env('REDIS_USERNAME'),
            'password' => env('REDIS_PASSWORD'),
            'port' => env('REDIS_PORT', '6379'),
            'database' => env('REDIS_CACHE_DB', '1'),
            'max_retries' => env('REDIS_MAX_RETRIES', 3),
            'backoff_algorithm' => env('REDIS_BACKOFF_ALGORITHM', 'decorrelated_jitter'),
            'backoff_base' => env('REDIS_BACKOFF_BASE', 100),
            'backoff_cap' => env('REDIS_BACKOFF_CAP', 1000),
        ],

    ],

];
