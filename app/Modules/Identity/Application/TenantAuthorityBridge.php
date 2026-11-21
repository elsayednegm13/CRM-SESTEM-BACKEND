<?php

declare(strict_types=1);

namespace App\Modules\Identity\Application;

use App\Modules\Identity\Domain\TenantHostContext;
use App\Modules\Identity\Domain\TenantStaffContext;
use App\Modules\Identity\Infrastructure\Persistence\TenantStaffUser;
use Illuminate\Http\Request;
use LogicException;

/**
 * Narrow composition seam for acceptance tests and internal callers.
 *
 * It deliberately has no SQL, signer, issuer or GUC API.  The existing login
 * service owns credential verification, session rotation and registration on
 * pgsql_tenant_auth; the context guard owns same-connection runtime binding.
 */
final class TenantAuthorityBridge
{
    public function __construct(private readonly TenantAuthorityAuthenticator $login)
    {
    }

    /** @return array{principal: TenantStaffUser, context: TenantStaffContext, authority_generation: string} */
    public function authenticateAndBind(
        TenantHostContext $host,
        string $email,
        string $password,
        string $retryKey,
        Request $request,
    ): array {
        $before = $request->session()->getId();
        $principal = $this->login->authenticate($host, $email, $password, $retryKey, $request);
        $context = $request->attributes->get('tenant_staff_context');
        $stored = $request->session()->get('identity.tenant_staff');
        $generation = is_array($stored) ? ($stored['authority_generation'] ?? null) : null;

        if (! $context instanceof TenantStaffContext || ! is_string($generation)
            || $generation === '' || $request->session()->getId() === $before) {
            throw new LogicException('Tenant authority bridge requires rotated session and bound authority context.');
        }

        return ['principal' => $principal, 'context' => $context, 'authority_generation' => $generation];
    }
}
