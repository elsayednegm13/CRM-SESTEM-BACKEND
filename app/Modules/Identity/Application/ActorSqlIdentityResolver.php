<?php

namespace App\Modules\Identity\Application;

use RuntimeException;

/**
 * SECURITY-F06-LARAVEL-IMPLEMENT-01: test-only synthetic credential provider.
 *
 * This resolver does NOT read, derive, or rotate any real tenant/provider secret.
 * It looks up a SCRAM password for a given SQL role name from
 * config('f06_actor_sql.synthetic_actor_passwords'), which is populated only by
 * F06_ACTOR_PW_* env vars that exist only in the isolated sandbox/test
 * environment for this slice. Absence of a mapped password is fail-closed
 * (null), never a fallback to TENANT_RUNTIME_DB_USERNAME or any shared credential.
 */
final class ActorSqlIdentityResolver
{
    public function passwordFor(string $sqlRoleName): ?string
    {
        if (! (bool) config('f06_actor_sql.enabled')) {
            throw new RuntimeException('ActorSqlIdentityResolver must not be used while the F06 flag is disabled.');
        }

        $password = config('f06_actor_sql.synthetic_actor_passwords.'.$sqlRoleName);

        return is_string($password) && $password !== '' ? $password : null;
    }
}
