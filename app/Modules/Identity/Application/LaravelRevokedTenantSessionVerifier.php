<?php

declare(strict_types=1);

namespace App\Modules\Identity\Application;

use App\Modules\Identity\Domain\TenantHostContext;
use App\Modules\Tenancy\Domain\TenantAccessException;
use Illuminate\Database\Connection;
use Illuminate\Http\Request;
use LogicException;

/** Acceptance-only proof that a just-revoked authority cannot be rebound. */
final class LaravelRevokedTenantSessionVerifier implements RevokedTenantSessionVerifier
{
    public function __construct(private readonly TenantStaffContextGuard $guard) {}

    public function assertDenied(TenantHostContext $host, Request $request, Connection $connection): void
    {
        if ($connection->transactionLevel() !== 0) {
            throw new LogicException('Revoked-session verification requires a clean runtime connection.');
        }
        $stored = $request->session()->get('identity.tenant_staff');
        if (! is_array($stored)) {
            throw new LogicException('Revoked-session verification has no prior server session tuple.');
        }

        $denied = false;
        $connection->beginTransaction();
        try {
            $this->guard->activateFromSession($host, $stored, $request);
        } catch (TenantAccessException) {
            $denied = true;
        } finally {
            if ($connection->transactionLevel() > 0) {
                $connection->rollBack();
            }
        }
        if (! $denied || $connection->transactionLevel() !== 0) {
            throw new LogicException('Revoked tenant authority remained usable.');
        }
    }
}
