<?php

declare(strict_types=1);

namespace App\Modules\Identity\Application;

use Illuminate\Database\Connection;
use LogicException;

final class LaravelTenantRuntimeIdentityAttestor implements TenantRuntimeIdentityAttestor
{
    public function attest(Connection $connection): array
    {
        $expectedRole = config('f3_acceptance.expected_runtime_principal');
        $expectedDatabase = config('f3_acceptance.expected_database');
        $expectedSystemIdentifier = config('f3_acceptance.expected_system_identifier');
        $expectedDatabaseOid = config('f3_acceptance.expected_database_oid');
        $identity = $connection->selectOne(<<<'SQL'
            SELECT current_user::text AS current_user,
                   session_user::text AS session_user,
                   current_database()::text AS database,
                   (SELECT system_identifier::text FROM pg_catalog.pg_control_system()) AS system_identifier,
                   (SELECT oid::bigint FROM pg_catalog.pg_database WHERE datname = current_database()) AS database_oid,
                   pg_backend_pid()::int AS backend_pid,
                   r.rolsuper, r.rolbypassrls, r.rolcreaterole, r.rolcreatedb,
                   EXISTS (
                       SELECT 1 FROM pg_catalog.pg_class c
                       WHERE c.relowner = r.oid
                         AND c.oid IN ('public.tenants'::regclass, 'public.tenant_staff_users'::regclass,
                                       'public.tenant_staff_memberships'::regclass, 'public.leads'::regclass)
                   ) AS owns_probed_table,
                   EXISTS (
                       WITH RECURSIVE memberships(roleid) AS (
                           SELECT m.roleid FROM pg_catalog.pg_auth_members m WHERE m.member = r.oid
                           UNION
                           SELECT m.roleid FROM pg_catalog.pg_auth_members m JOIN memberships p ON m.member = p.roleid
                       )
                       SELECT 1
                       FROM memberships m
                       JOIN pg_catalog.pg_roles granted ON granted.oid = m.roleid
                       WHERE (granted.rolsuper OR granted.rolbypassrls OR granted.rolcreaterole OR granted.rolcreatedb
                              OR EXISTS (
                                  SELECT 1 FROM pg_catalog.pg_class c
                                  WHERE c.relowner = granted.oid
                                        AND c.oid IN ('public.tenants'::regclass, 'public.tenant_staff_users'::regclass,
                                                      'public.tenant_staff_memberships'::regclass, 'public.leads'::regclass)
                              ))
                   ) AS has_privileged_membership
            FROM pg_catalog.pg_roles r
            WHERE r.rolname = session_user
        SQL);
        if (! is_object($identity) || ! is_string($expectedRole) || $expectedRole === ''
            || ! is_string($expectedDatabase) || $expectedDatabase === ''
            || ! is_string($expectedSystemIdentifier) || preg_match('/^\d{10,24}$/D', $expectedSystemIdentifier) !== 1
            || ! is_string($expectedDatabaseOid) || preg_match('/^\d+$/D', $expectedDatabaseOid) !== 1
            || ! is_string($identity->current_user ?? null) || ! is_string($identity->session_user ?? null)
            || ! hash_equals($expectedRole, $identity->current_user)
            || ! hash_equals($expectedRole, $identity->session_user)
            || in_array($identity->current_user, ['postgres','daleel_b10b_owner'], true)
            || ! is_string($identity->database ?? null) || ! hash_equals($expectedDatabase, $identity->database)
            || ! is_string($identity->system_identifier ?? null) || ! hash_equals($expectedSystemIdentifier, $identity->system_identifier)
            || ! is_numeric($identity->database_oid ?? null) || (string) $identity->database_oid !== $expectedDatabaseOid
            || ! is_numeric($identity->backend_pid ?? null) || (int) $identity->backend_pid < 1
            || ($identity->rolsuper ?? null) !== false || ($identity->rolbypassrls ?? null) !== false
            || ($identity->rolcreaterole ?? null) !== false || ($identity->rolcreatedb ?? null) !== false
            || ($identity->owns_probed_table ?? null) !== false
            || ($identity->has_privileged_membership ?? null) !== false) {
            throw new LogicException('Restricted tenant runtime identity attestation failed.');
        }

        return [
            'principal' => $identity->current_user,
            'database' => $identity->database,
            'system_identifier' => $identity->system_identifier,
            'database_oid' => (int) $identity->database_oid,
            'backend_pid' => (int) $identity->backend_pid,
        ];
    }
}
