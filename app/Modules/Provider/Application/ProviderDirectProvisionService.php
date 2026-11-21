<?php

namespace App\Modules\Provider\Application;

use App\Modules\Identity\Domain\EmailAddressNormalizer;
use App\Modules\Provider\Domain\CanonicalTenantHost;
use App\Modules\Provider\Domain\ProviderAccessException;
use App\Modules\Provider\Domain\ProviderContext;
use Illuminate\Database\QueryException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;
use InvalidArgumentException;
use RuntimeException;

/** V1 direct company bootstrap; one PostgreSQL function owns the entire write set. */
final class ProviderDirectProvisionService
{
    public function __construct(
        private readonly ProviderAuthorizationService $authorization,
        private readonly EmailAddressNormalizer $emails,
        private readonly ProviderAuthorityService $authority,
    ) {}

    public function create(ProviderContext $actor, array $input, string $idempotencyKey, Request $request): array
    {
        $this->authorization->assertStepUp($actor);
        $this->authorization->assertCapability($actor, 'company.provision');

        if (! preg_match('/^[A-Za-z0-9._:-]{16,128}$/D', $idempotencyKey)) {
            throw ValidationException::withMessages(['idempotency_key' => ['A valid idempotency key is required.']]);
        }
        $display = trim((string) $input['display_name']);
        $adminName = trim((string) $input['first_admin_display_name']);
        $timezone = (string) $input['timezone'];
        $password = (string) $input['initial_password'];
        try {
            $email = $this->emails->normalize((string) $input['first_admin_email']);
            $host = CanonicalTenantHost::forSlug(
                (string) $input['slug'],
                config('tenancy.base_domain'),
                (string) config('app.env'),
                (bool) config('tenancy.allow_localhost_base_domain'),
                config('tenancy.local_test_base_domain'),
            );
        } catch (InvalidArgumentException) {
            throw ValidationException::withMessages(['company' => ['The company host or administrator email is invalid.']]);
        }
        if ($display === '' || mb_strlen($display) > 160 || $adminName === '' || mb_strlen($adminName) > 160
            || preg_match('/[\x00-\x1F\x7F]/u', $display.$adminName)
            || ! mb_check_encoding($password, 'UTF-8') || mb_strlen($password, 'UTF-8') < 12
            || strlen($password) > 1024 || ! in_array($timezone, timezone_identifiers_list(), true)) {
            throw ValidationException::withMessages(['company' => ['The company or first administrator data is invalid.']]);
        }

        $canonical = [
            'display_name' => $display, 'slug' => $host->slug(), 'timezone' => $timezone,
            'first_admin_email' => $email, 'first_admin_display_name' => $adminName,
            'initial_password' => $password, 'base_domain' => $host->baseDomain(),
        ];
        $key = (string) config('app.key');
        if ($key === '') {
            throw new RuntimeException('Trusted application key is unavailable.');
        }
        $keyHash = hash_hmac('sha256', $idempotencyKey, $key);
        $digest = hash_hmac('sha256', json_encode($canonical, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES), $key);
        $passwordHash = Hash::driver('argon2id')->make($password);
        $payloadFields = [
            $canonical['display_name'], $canonical['slug'], $canonical['timezone'],
            $canonical['first_admin_email'], $canonical['first_admin_display_name'],
            $canonical['base_domain'],
        ];
        $payloadEncoding = implode('', array_map(static fn (string $value): string => strlen($value).':'.$value, $payloadFields));
        $payloadHash = hash('sha256', $payloadEncoding);
        $authority = $this->authority->obtainProvisionReceipt($request, $actor, $keyHash, $digest, $payloadHash, $passwordHash);
        unset($canonical['initial_password'], $password);

        $db = DB::connection('pgsql_provider_control');
        if ($db->getDriverName() !== 'pgsql' || $db->getConfig('username') === config('core_runtime.owner_login')) {
            throw new RuntimeException('Provider V1 requires a scoped PostgreSQL runtime.');
        }
        try {
            // The response is returned only after the connection transaction commits.
            return $db->transaction(function () use ($db, $actor, $keyHash, $digest, $canonical, $authority, $payloadHash): array {
                $row = $db->selectOne(<<<'SQL'
                    SELECT public.core01_provision_company_with_authority(
                        ?, ?, ?::uuid, ?::bigint, ?::bigint,
                        ?, ?, ?, ?, ?, ?, ?, ?, ?
                    ) AS result
                SQL, [
                    $authority['token'], $authority['session_hash'], $actor->providerUserId, $actor->authVersion, $actor->authorizationVersion,
                    $keyHash, $digest, $canonical['display_name'], $canonical['slug'],
                    $canonical['timezone'], $canonical['first_admin_email'],
                    $canonical['first_admin_display_name'], $canonical['base_domain'], $payloadHash,
                ]);
                $result = json_decode((string) ($row->result ?? ''), true, 512, JSON_THROW_ON_ERROR);
                if (! is_array($result) || ! isset($result['operation_id'], $result['tenant_id'], $result['hostname'])) {
                    throw new RuntimeException('Provider V1 returned an invalid result.');
                }
                return $result;
            });
        } catch (QueryException $exception) {
            $state = (string) ($exception->errorInfo[0] ?? $exception->getCode());
            if ($state === 'PZ409' || $state === '23505') {
                throw new ProviderAccessException('PROVIDER_PROVISION_CONFLICT', 409);
            }
            if ($state === 'PZ403') {
                throw ProviderAccessException::denied();
            }
            if ($state === 'PZ422') {
                throw ValidationException::withMessages(['company' => ['The company request is invalid.']]);
            }
            logger()->error('Provider V1 persistence failed.', [
                'request_id' => $actor->requestId,
                'sqlstate' => preg_match('/^[A-Z0-9]{5}$/D', $state) ? $state : 'UNKNOWN',
            ]);
            throw new ProviderAccessException('PROVIDER_PROVISION_UNAVAILABLE', 503);
        }
    }
}
